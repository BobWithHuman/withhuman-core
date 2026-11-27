//! `withhuman-local`: the personal engine (`WITHHUMAN_PROFILE=personal` throughout). Decision,
//! Generator and Collector run in this one process, on a PostgreSQL this binary installs and
//! runs in `WITHHUMAN_HOME`; there is no gateway and no Redis. The personal app starts it (with
//! launchd on a Mac) and hands it its secrets:
//!
//! - `WITHHUMAN_HOME`: the engine's folder, PostgreSQL's installation (`postgresql/`) and data
//!   (`pg/`) in it;
//! - `WITHHUMAN_PG_PASSWORD`: the database's own login, set on the first run;
//! - `WITHHUMAN_VIEWER_PASSWORD`: the app's read-only login (`withhuman_viewer`);
//! - `JEV_API_KEY`, and `JEV_MODEL` / `JEV_URL` when not the defaults.
//!
//! The ports are `withhuman_common::profile::personal`'s; a second engine beside one moves them
//! with the services' own `*_ADDR` and `*_URL` variables and `WITHHUMAN_PG_PORT`. It stops on SIGTERM or Ctrl-C, and
//! exits non-zero when a part of it fails, for launchd to start it again.

use std::{env, io, net::SocketAddr, path::PathBuf, time::Duration};

use tokio::{sync::watch, task::JoinHandle};
use withhuman_collector::CollectorConfig;
use withhuman_common::{
    graph_store::PostgresSettings,
    profile::{Profile, personal},
    shutdown::shutdown_signal,
};
use withhuman_decision::DecisionConfig;
use withhuman_generator::{GeneratorConfig, PgGraphRepository};

/// PostgreSQL 16, as the enterprise engine's Compose file runs.
const PG_VERSION: &str = "=16.16.0";
const DATABASE: &str = "withhuman";
/// How long a part may take to listen before the next one starts anyway.
const READY_WAIT: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("withhuman-local: {error}");
        std::process::exit(1);
    }
}

async fn run() -> io::Result<()> {
    let profile = Profile::Personal;
    // Every setting first, so a wrong one stops the engine before anything starts.
    let home = PathBuf::from(required("WITHHUMAN_HOME")?);
    let pg_password = required("WITHHUMAN_PG_PASSWORD")?;
    let viewer_password = env::var("WITHHUMAN_VIEWER_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty());
    let mut decision = DecisionConfig::from_env_as(profile)?;
    let mut generator = GeneratorConfig::from_env_as(profile)?;
    let mut collector = CollectorConfig::from_env_as(profile)?;
    // The services take only each other's calls: another user of this machine reaches their
    // ports, and the Generator's routes change the record. A token new at each start.
    let token = Some(internal_token()?);
    decision.internal_token.clone_from(&token);
    generator.internal_token.clone_from(&token);
    collector.internal_token = token;
    let pg_port = match env::var("WITHHUMAN_PG_PORT") {
        Ok(port) => port.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid WITHHUMAN_PG_PORT {port:?}: {error}"),
            )
        })?,
        Err(_) => personal::POSTGRES_PORT,
    };

    let pg = start_store(&home, &pg_password, pg_port).await?;
    eprintln!("withhuman-local: PostgreSQL on {pg_port}");
    let settings = PostgresSettings {
        database_url: format!("postgres://postgres:{pg_password}@127.0.0.1:{pg_port}/{DATABASE}"),
        pool_size: personal::POOL_SIZE,
    };

    let (stop, stopped) = watch::channel(false);
    let outcome = run_services(
        decision,
        generator,
        collector,
        settings,
        viewer_password,
        stopped,
    )
    .await;
    let _ = stop.send(true);
    // Stopped here, its drop finds nothing more to stop.
    if let Err(error) = pg.stop().await {
        eprintln!("withhuman-local: PostgreSQL did not stop cleanly: {error}");
    }
    outcome
}

/// The three services, each started once the one before it listens, until the signal or until
/// one of them fails.
async fn run_services(
    decision: DecisionConfig,
    generator: GeneratorConfig,
    collector: CollectorConfig,
    settings: PostgresSettings,
    viewer_password: Option<String>,
    stopped: watch::Receiver<bool>,
) -> io::Result<()> {
    let (stop_all, all_stopped) = watch::channel(false);
    let until = || wait_for(all_stopped.clone());

    let decision_at = decision.bind_address;
    let decision = tokio::spawn(withhuman_decision::serve(
        decision,
        settings.clone(),
        until(),
    ));
    listening("Decision", decision_at, &decision).await?;

    // The Generator lays out the schema and the viewer's login before it serves.
    let repository = PgGraphRepository::connect_with_viewer(
        &settings.database_url,
        settings.pool_size,
        viewer_password.as_deref(),
    )
    .await
    .map_err(io::Error::other)?;
    let generator_at = generator.bind_address;
    let generator = tokio::spawn(withhuman_generator::serve(generator, repository, until()));
    listening("Generator", generator_at, &generator).await?;

    let collector_at = collector.bind_address;
    let collector = tokio::spawn(withhuman_collector::serve(collector, until()));
    listening("Collector", collector_at, &collector).await?;
    eprintln!("withhuman-local: hooks at http://{collector_at}");

    let mut parts = [
        ("Decision", decision),
        ("Generator", generator),
        ("Collector", collector),
    ];
    let failed = tokio::select! {
        () = signal_or(stopped) => None,
        (name, result) = first_to_end(&mut parts) => Some((name, result)),
    };
    let _ = stop_all.send(true);
    for (_, part) in &mut parts {
        let _ = part.await;
    }
    match failed {
        None => Ok(()),
        Some((name, Ok(Ok(())))) => Err(io::Error::other(format!("{name} stopped by itself"))),
        Some((name, Ok(Err(error)))) => Err(io::Error::other(format!("{name}: {error}"))),
        Some((name, Err(error))) => Err(io::Error::other(format!("{name}: {error}"))),
    }
}

type Part = (&'static str, JoinHandle<io::Result<()>>);

/// The first part to end, and how it ended.
async fn first_to_end(
    parts: &mut [Part],
) -> (&'static str, Result<io::Result<()>, tokio::task::JoinError>) {
    loop {
        for (name, part) in parts.iter_mut() {
            if part.is_finished() {
                return (name, part.await);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// SIGTERM or Ctrl-C, or the caller's own stop.
async fn signal_or(mut stopped: watch::Receiver<bool>) {
    tokio::select! {
        () = shutdown_signal() => {}
        _ = stopped.wait_for(|stopped| *stopped) => {}
    }
}

async fn wait_for(mut stopped: watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stopped| *stopped).await;
}

/// Waits until `part` takes connections at `address`, for a minute at most; an error when it
/// ended first.
async fn listening(
    name: &str,
    address: SocketAddr,
    part: &JoinHandle<io::Result<()>>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + READY_WAIT;
    while tokio::time::Instant::now() < deadline {
        if part.is_finished() {
            return Err(io::Error::other(format!("{name} did not start")));
        }
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!("withhuman-local: {name} is slow to start; going on");
    Ok(())
}

/// 32 random bytes in hex.
fn internal_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn required(name: &str) -> io::Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} must be set")))
}

/// Installs PostgreSQL on the first run, makes its data folder, and starts it with the database
/// the engine keeps its graph in. A server left running by an engine that did not stop cleanly
/// is taken as it is.
async fn start_store(
    home: &std::path::Path,
    password: &str,
    port: u16,
) -> io::Result<postgresql_embedded::PostgreSQL> {
    let password_file = home.join("pg-password");
    // initdb reads the password from a file: written unreadable to others, removed after.
    write_private(&password_file, password)?;
    let settings = postgresql_embedded::Settings {
        version: postgresql_embedded::VersionReq::parse(PG_VERSION).map_err(io::Error::other)?,
        installation_dir: home.join("postgresql"),
        password_file: password_file.clone(),
        data_dir: home.join("pg"),
        host: "127.0.0.1".into(),
        port,
        username: postgresql_embedded::BOOTSTRAP_SUPERUSER.into(),
        password: password.into(),
        temporary: false,
        timeout: Some(Duration::from_secs(60)),
        // 127.0.0.1 alone, the address every part connects to: a server that cannot take it (a
        // program already holds the port) fails to start instead of starting on ::1 alone while
        // the connections go to whatever holds 127.0.0.1.
        configuration: std::collections::HashMap::from([(
            "listen_addresses".to_owned(),
            "127.0.0.1".to_owned(),
        )]),
        ..postgresql_embedded::Settings::default()
    };
    let mut pg = postgresql_embedded::PostgreSQL::new(settings);
    let setup = pg.setup().await;
    let _ = std::fs::remove_file(&password_file);
    setup.map_err(|e| io::Error::other(format!("could not install PostgreSQL: {e}")))?;
    // A server left running by an engine that did not stop cleanly is taken as it is, but only
    // when it is this folder's own: anything else on the port (another user's server, a program
    // waiting for the password) is never connected to.
    if let Err(error) = pg.start().await
        && !runs_here(pg.settings(), port).await
    {
        return Err(io::Error::other(format!(
            "could not start PostgreSQL, and what holds port {port} is not its server: {error}"
        )));
    }
    let exists = pg
        .database_exists(DATABASE)
        .await
        .map_err(|e| io::Error::other(format!("could not check the database: {e}")))?;
    if !exists {
        pg.create_database(DATABASE)
            .await
            .map_err(|e| io::Error::other(format!("could not create the database: {e}")))?;
    }
    Ok(pg)
}

/// Whether the server on `port` is the one of `settings`' data folder: its `postmaster.pid` names
/// that folder and that port and says it is ready, and `pg_ctl status` finds its process alive.
async fn runs_here(settings: &postgresql_embedded::Settings, port: u16) -> bool {
    let data = &settings.data_dir;
    let Ok(pid_file) = std::fs::read_to_string(data.join("postmaster.pid")) else {
        return false;
    };
    if !pid_file_is_ours(&pid_file, data, port) {
        return false;
    }
    let pg_ctl = settings.binary_dir().join(if cfg!(windows) {
        "pg_ctl.exe"
    } else {
        "pg_ctl"
    });
    tokio::process::Command::new(pg_ctl)
        .arg("status")
        .arg("-D")
        .arg(data)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

/// Whether a `postmaster.pid` is the one of a server of `data` on `port`, ready: its second line
/// is the data folder, its fourth the port, and a line says `ready`.
fn pid_file_is_ours(pid_file: &str, data: &std::path::Path, port: u16) -> bool {
    let lines: Vec<&str> = pid_file.lines().map(str::trim).collect();
    let same_folder = lines.get(1).is_some_and(|folder| {
        let canonical = |p: &std::path::Path| std::fs::canonicalize(p).ok();
        let named = std::path::Path::new(folder);
        named == data || (canonical(named).is_some() && canonical(named) == canonical(data))
    });
    let same_port = lines.get(3).and_then(|p| p.parse::<u16>().ok()) == Some(port);
    same_folder && same_port && lines.contains(&"ready")
}

fn write_private(path: &std::path::Path, text: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    std::fs::write(path, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_this_folders_ready_server_on_this_port_is_taken() {
        let data = std::env::temp_dir();
        let folder = data.display().to_string();
        let file = |folder: &str, port: &str, status: &str| {
            format!(
                "81358\n{folder}\n1795759641\n{port}\n/tmp\nlocalhost\n149183947    983040\n{status}\n"
            )
        };
        assert!(pid_file_is_ours(
            &file(&folder, "47432", "ready"),
            &data,
            47432
        ));
        assert!(!pid_file_is_ours(
            &file(&folder, "5432", "ready"),
            &data,
            47432
        ));
        assert!(!pid_file_is_ours(
            &file("/elsewhere/pg", "47432", "ready"),
            &data,
            47432
        ));
        assert!(!pid_file_is_ours(
            &file(&folder, "47432", "starting"),
            &data,
            47432
        ));
        assert!(!pid_file_is_ours("", &data, 47432));
    }

    #[test]
    fn the_personal_engine_listens_on_this_machine_and_stops_nothing() {
        let collector = CollectorConfig::from_env_as(Profile::Personal).unwrap();
        assert_eq!(collector.bind_address.to_string(), "127.0.0.1:47380");
        assert_eq!(collector.generator_url, "http://127.0.0.1:47381");
        assert_ne!(
            collector.enforcement_mode,
            withhuman_collector::CollectorConfig::default().enforcement_mode
        );
        assert!(collector.enforce_mcp_at_hook);
        assert!(collector.redis_url.is_none());
        assert!(collector.admin_token.is_none());
        assert!(!collector.require_key);
        let generator = GeneratorConfig::from_env_as(Profile::Personal).unwrap();
        assert_eq!(generator.bind_address.to_string(), "127.0.0.1:47381");
        assert_eq!(generator.decision_url, "http://127.0.0.1:47382");
        assert!(generator.wazuh.is_none());
    }
}
