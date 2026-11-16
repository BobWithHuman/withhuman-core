//! The company's device list from its EDR (a Wazuh manager), matched to the devices that
//! registered with the engine.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::time::MissedTickBehavior;

use crate::{
    config::{WazuhConfig, WazuhTls},
    pg_repository::PgGraphRepository,
    repository::RepositoryError,
    wazuh::WazuhClient,
};

/// A device as the EDR lists it; a row of `edr_devices`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdrDevice {
    /// The EDR's own ID of the device (`001`).
    pub agent_id: String,
    /// The name it enrolled under, its hostname unless someone chose another.
    pub name: Option<String>,
    pub os: Option<String>,
    /// `active`, `disconnected`, `never_connected` or `pending`.
    pub status: Option<String>,
    /// The motherboard's serial number, as the EDR's inventory reports it.
    pub serial: Option<String>,
    /// When the EDR last heard from it, epoch milliseconds.
    pub last_seen: Option<i64>,
    /// `claude-code` or `codex` when the EDR's inventory shows that program on the device.
    pub agent: Option<String>,
}

/// What a registered device is matched by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub client_id: String,
    pub hostname: Option<String>,
    pub serial: Option<String>,
}

/// A registered device and the EDR device it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdrMatch {
    pub client_id: String,
    pub agent_id: String,
    pub status: Option<String>,
}

/// What firmware reports when the manufacturer set no serial number: the values the client's
/// setup (`deploy/client/configure.py`) refuses too.
const NO_SERIAL: [&str; 8] = [
    "",
    "0",
    "none",
    "default string",
    "not specified",
    "not applicable",
    "system serial number",
    "to be filled by o.e.m.",
];

/// A serial number to compare by: trimmed, in upper case; none for a firmware placeholder.
fn serial_key(serial: Option<&str>) -> Option<String> {
    let serial = serial?.trim();
    let placeholder =
        NO_SERIAL.contains(&serial.to_lowercase().as_str()) || serial.bytes().all(|b| b == b'0');
    (!placeholder).then(|| serial.to_uppercase())
}

/// A hostname to compare by: in lower case, without its domain (`Mac-1.local` is `mac-1`).
/// An IP address names no host.
fn host_key(hostname: Option<&str>) -> Option<String> {
    let hostname = hostname?.trim().trim_end_matches('.');
    if hostname.parse::<IpAddr>().is_ok() {
        return None;
    }
    let label = hostname.split('.').next()?.to_lowercase();
    (!label.is_empty()).then_some(label)
}

/// Which of two EDR devices answering to the same serial or hostname stands for it: the one
/// connected now, then the one heard from last, then the lower ID.
fn preferred<'a>(current: &'a EdrDevice, other: &'a EdrDevice) -> &'a EdrDevice {
    let rank = |device: &EdrDevice| {
        (
            device.status.as_deref() == Some("active"),
            device.last_seen.unwrap_or(i64::MIN),
        )
    };
    match rank(other).cmp(&rank(current)) {
        std::cmp::Ordering::Greater => other,
        std::cmp::Ordering::Less => current,
        std::cmp::Ordering::Equal if other.agent_id < current.agent_id => other,
        std::cmp::Ordering::Equal => current,
    }
}

/// The EDR device of each registered device that has one.
///
/// Two devices that both report a serial number are the same machine only when the numbers are
/// equal: hostnames repeat too easily (`MacBook-Pro`) to overrule that. When either side has no
/// serial, or only a firmware placeholder, the hostnames decide, compared without case or
/// domain. One EDR device stands for every client row of its machine, one per OS account.
pub fn match_clients(clients: &[ClientIdentity], devices: &[EdrDevice]) -> Vec<EdrMatch> {
    let mut by_serial: HashMap<String, &EdrDevice> = HashMap::new();
    // By hostname: every device, and those without a serial of their own.
    let mut by_host: HashMap<String, &EdrDevice> = HashMap::new();
    let mut by_host_without_serial: HashMap<String, &EdrDevice> = HashMap::new();
    fn keep<'a>(map: &mut HashMap<String, &'a EdrDevice>, key: String, device: &'a EdrDevice) {
        map.entry(key)
            .and_modify(|current| *current = preferred(current, device))
            .or_insert(device);
    }
    for device in devices {
        let serial = serial_key(device.serial.as_deref());
        if let Some(host) = host_key(device.name.as_deref()) {
            if serial.is_none() {
                keep(&mut by_host_without_serial, host.clone(), device);
            }
            keep(&mut by_host, host, device);
        }
        if let Some(serial) = serial {
            keep(&mut by_serial, serial, device);
        }
    }
    clients
        .iter()
        .filter_map(|client| {
            let host = host_key(client.hostname.as_deref());
            let device = match serial_key(client.serial.as_deref()) {
                Some(serial) => by_serial
                    .get(&serial)
                    .or_else(|| by_host_without_serial.get(host.as_ref()?)),
                None => by_host.get(host.as_ref()?),
            }?;
            Some(EdrMatch {
                client_id: client.client_id.clone(),
                agent_id: device.agent_id.clone(),
                status: device.status.clone(),
            })
        })
        .collect()
}

/// How a sync ended without failing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdrSync {
    /// `edr_devices` now mirrors the manager, and `clients` carries the matches.
    Synced { devices: usize, matched: usize },
    /// Another Generator is syncing right now.
    Busy,
    /// Another Generator synced less than half an interval ago.
    Fresh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdrSyncError {
    /// The EDR could not be read; nothing was written.
    Source(String),
    Store(RepositoryError),
}

impl fmt::Display for EdrSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => formatter.write_str(error),
            Self::Store(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for EdrSyncError {}

/// Reads the manager's devices and stores them with their matches, unless another Generator is
/// doing so or just did. `now` is epoch milliseconds.
pub async fn sync_edr_devices(
    repository: &PgGraphRepository,
    config: &WazuhConfig,
    now: u64,
) -> Result<EdrSync, EdrSyncError> {
    repository
        .mirror_edr_devices(now, config.sync_interval / 2, || async {
            // Built for each sync: a CA file replaced on disk is read again.
            let mut wazuh = WazuhClient::new(config)?;
            let devices = wazuh.devices().await?;
            if wazuh.refused() > 0 {
                eprintln!(
                    "Wazuh device sync: {} inventory requests were refused and read as unknown",
                    wazuh.refused()
                );
            }
            Ok::<_, crate::wazuh::WazuhError>(devices)
        })
        .await
}

/// Syncs now and then every `sync_interval`, for as long as the service runs. A sync that
/// fails, or panics, is logged and tried again at the next interval.
pub async fn run_edr_sync(repository: PgGraphRepository, config: WazuhConfig) {
    eprintln!(
        "Wazuh device sync: {} every {}s",
        config.url,
        config.sync_interval.as_secs()
    );
    if config.tls == WazuhTls::SkipVerification {
        eprintln!(
            "Wazuh device sync: WARNING: WITHHUMAN_WAZUH_TLS_SKIP_VERIFY=1, the manager's \
             certificate is not verified"
        );
    }
    let mut ticks = tokio::time::interval(config.sync_interval);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let (repository, config) = (repository.clone(), config.clone());
        let sync = tokio::spawn(async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_millis() as u64);
            sync_edr_devices(&repository, &config, now).await
        });
        match sync.await {
            Ok(Ok(EdrSync::Synced { devices, matched })) => eprintln!(
                "Wazuh device sync: {devices} devices, {matched} registered clients matched"
            ),
            Ok(Ok(EdrSync::Busy | EdrSync::Fresh)) => {}
            Ok(Err(error)) => eprintln!("Wazuh device sync failed, trying again later: {error}"),
            Err(error) => eprintln!("Wazuh device sync stopped, trying again later: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str, hostname: Option<&str>, serial: Option<&str>) -> ClientIdentity {
        ClientIdentity {
            client_id: id.into(),
            hostname: hostname.map(str::to_owned),
            serial: serial.map(str::to_owned),
        }
    }

    fn device(id: &str, name: &str, serial: Option<&str>) -> EdrDevice {
        EdrDevice {
            agent_id: id.into(),
            name: Some(name.into()),
            status: Some("active".into()),
            serial: serial.map(str::to_owned),
            ..EdrDevice::default()
        }
    }

    fn matched(clients: &[ClientIdentity], devices: &[EdrDevice]) -> Vec<(String, String)> {
        match_clients(clients, devices)
            .into_iter()
            .map(|found| (found.client_id, found.agent_id))
            .collect()
    }

    fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(client, agent)| ((*client).to_owned(), (*agent).to_owned()))
            .collect()
    }

    #[test]
    fn a_serial_number_matches_whatever_the_hostnames() {
        let devices = [
            device("001", "ana-laptop", Some("C02XK1")),
            device("002", "build-7", Some("PF3ABC")),
        ];
        let clients = [
            // Case and surrounding spaces do not matter.
            client("t/a", Some("Anas-MacBook-Pro.local"), Some(" c02xk1 ")),
            client("t/b", Some("build-7"), Some("PF3ABC")),
        ];
        assert_eq!(
            matched(&clients, &devices),
            pairs(&[("t/a", "001"), ("t/b", "002")])
        );
    }

    #[test]
    fn two_different_serial_numbers_are_two_machines_even_with_one_hostname() {
        let devices = [device("001", "MacBook-Pro", Some("C02AAA"))];
        let clients = [client("t/a", Some("MacBook-Pro.local"), Some("C02BBB"))];
        assert_eq!(matched(&clients, &devices), pairs(&[]));
    }

    #[test]
    fn hostnames_decide_when_a_side_has_no_serial_number() {
        let devices = [
            device("001", "DESKTOP-ABC", None),
            device("002", "build-7.corp.example.com", Some("PF3ABC")),
            device("003", "db-1", Some("S3")),
        ];
        let clients = [
            // The client has a serial, the EDR device none.
            client("t/a", Some("desktop-abc.corp.example.com"), Some("X1")),
            // The EDR device has a serial, the client none.
            client("t/b", Some("BUILD-7.local"), None),
            // Neither name is known to the other side.
            client("t/c", Some("db-2"), None),
            client("t/d", None, None),
        ];
        assert_eq!(
            matched(&clients, &devices),
            pairs(&[("t/a", "001"), ("t/b", "002")])
        );
    }

    #[test]
    fn hostnames_are_compared_without_case_or_domain() {
        for (left, right) in [
            ("Mac-1.local", "mac-1"),
            ("MAC-1", "mac-1.corp.example.com"),
            (" mac-1.lan. ", "Mac-1"),
        ] {
            assert_eq!(host_key(Some(left)), host_key(Some(right)), "{left}");
        }
        assert_eq!(host_key(Some("mac-1")), Some("mac-1".into()));
        assert_ne!(host_key(Some("mac-1")), host_key(Some("mac-10")));
        // An address is not a name, and its first number even less.
        for none in ["", " ", ".local", "10.0.0.5", "fe80::1"] {
            assert_eq!(host_key(Some(none)), None, "{none:?}");
        }
        assert_eq!(host_key(None), None);
    }

    #[test]
    fn firmware_placeholders_are_no_serial_number() {
        for placeholder in [
            "",
            " ",
            "0",
            "00000000",
            "To Be Filled By O.E.M.",
            "Default string",
            "DEFAULT STRING",
            "None",
            "Not Specified",
            "Not Applicable",
            "System Serial Number",
        ] {
            assert_eq!(serial_key(Some(placeholder)), None, "{placeholder:?}");
        }
        assert_eq!(serial_key(None), None);
        assert_eq!(serial_key(Some("c02xk1")), Some("C02XK1".into()));

        // Two machines whose firmware says the same nothing are not one machine...
        let devices = [device("001", "desk-1", Some("To Be Filled By O.E.M."))];
        let other = [client(
            "t/a",
            Some("desk-2"),
            Some("To Be Filled By O.E.M."),
        )];
        assert_eq!(matched(&other, &devices), pairs(&[]));
        // ...and a placeholder leaves the hostname to decide.
        let same = [client("t/b", Some("DESK-1.local"), Some("Default string"))];
        assert_eq!(matched(&same, &devices), pairs(&[("t/b", "001")]));
    }

    #[test]
    fn one_edr_device_stands_for_every_account_of_its_machine() {
        let devices = [
            device("001", "shared-mac", Some("C02XK1")),
            device("002", "kiosk", None),
        ];
        let clients = [
            client("t/ana", Some("shared-mac.local"), Some("C02XK1")),
            client("t/ben", Some("shared-mac.local"), Some("C02XK1")),
            client("t/cho", Some("shared-mac"), None),
            client("t/k1", Some("kiosk"), None),
            client("t/k2", Some("KIOSK.local"), None),
        ];
        assert_eq!(
            matched(&clients, &devices),
            pairs(&[
                ("t/ana", "001"),
                ("t/ben", "001"),
                ("t/cho", "001"),
                ("t/k1", "002"),
                ("t/k2", "002"),
            ])
        );
    }

    #[test]
    fn of_two_edr_devices_for_one_machine_the_connected_one_stands() {
        let stale = EdrDevice {
            status: Some("disconnected".into()),
            last_seen: Some(9_000),
            ..device("001", "mac-1", Some("C02XK1"))
        };
        let live = EdrDevice {
            last_seen: Some(5_000),
            ..device("007", "mac-1", Some("C02XK1"))
        };
        let clients = [
            client("t/a", None, Some("C02XK1")),
            client("t/b", Some("mac-1"), None),
        ];
        for devices in [[stale.clone(), live.clone()], [live.clone(), stale.clone()]] {
            let found = match_clients(&clients, &devices);
            assert_eq!(found.len(), 2);
            assert!(
                found
                    .iter()
                    .all(|found| found.agent_id == "007"
                        && found.status.as_deref() == Some("active"))
            );
        }
        // Both gone quiet: the one heard from last.
        let quiet = EdrDevice {
            status: Some("disconnected".into()),
            ..live
        };
        assert_eq!(
            matched(&clients[..1], &[quiet, stale]),
            pairs(&[("t/a", "001")])
        );
    }
}
