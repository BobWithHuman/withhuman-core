use std::{env, io};

use withhuman_common::graph_store::PostgresSettings;
use withhuman_generator::{GeneratorConfig, PgGraphRepository, serve};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = GeneratorConfig::from_env()?;
    let settings = PostgresSettings::from_env()?;
    // The security team's viewer reads the graph through its own login (WITHHUMAN_VIEWER_PASSWORD).
    let viewer_password = env::var("WITHHUMAN_VIEWER_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty());
    let repository = PgGraphRepository::connect_with_viewer(
        &settings.database_url,
        settings.pool_size,
        viewer_password.as_deref(),
    )
    .await
    .map_err(io::Error::other)?;
    if env::args().nth(1).as_deref() == Some("reindex-paragraphs") {
        let report = repository
            .reindex_paragraphs()
            .await
            .map_err(io::Error::other)?;
        println!(
            "re-chunked {} of {} committed events",
            report.reindexed, report.scanned
        );
        return Ok(());
    }
    if env::args().nth(1).as_deref() == Some("backtrack-secrets") {
        let report = repository
            .backtrack_secrets()
            .await
            .map_err(io::Error::other)?;
        println!(
            "found {} of {} agent-first values again; {} traced to an earlier node, {} stored rows masked",
            report.recovered, report.scanned, report.traced, report.masked
        );
        return Ok(());
    }
    serve(
        config,
        repository,
        withhuman_common::shutdown::shutdown_signal(),
    )
    .await
}
