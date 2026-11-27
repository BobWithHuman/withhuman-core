//! Which of the two products the engine runs as, read once from `WITHHUMAN_PROFILE`. Every
//! default that differs between them is decided here, so the two never drift apart in the
//! services' own settings.
//!
//! - `enterprise` (the default): the company's engine behind its gateway, on shared PostgreSQL and
//!   Redis, able to stop a Call, with its EDR sync and administration API.
//! - `personal`: one developer's engine on their own machine (`withhuman-local`): it records and
//!   judges but stops nothing, keeps its state in memory, takes the hooks straight at the
//!   Collector without a key, and has no EDR sync, administration or triage.

use std::{env, io};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    #[default]
    Enterprise,
    Personal,
}

/// The personal engine's ports, away from the ones a developer's own servers take (8080, 5432,
/// 3000…). The personal app reads the record and sends its hooks at these.
pub mod personal {
    pub const POSTGRES_PORT: u16 = 47432;
    pub const COLLECTOR_PORT: u16 = 47380;
    pub const GENERATOR_PORT: u16 = 47381;
    pub const DECISION_PORT: u16 = 47382;
    pub const EXT_AUTHZ_PORT: u16 = 47390;
    /// Connections each service keeps to the one machine's PostgreSQL.
    pub const POOL_SIZE: usize = 4;
}

impl Profile {
    /// `WITHHUMAN_PROFILE`: `enterprise` or unset, else `personal`.
    pub fn from_env() -> io::Result<Self> {
        Self::parse(env::var("WITHHUMAN_PROFILE").ok().as_deref())
            .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))
    }

    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("" | "enterprise") => Ok(Self::Enterprise),
            Some("personal") => Ok(Self::Personal),
            Some(other) => Err(format!(
                "invalid WITHHUMAN_PROFILE {other:?}: enterprise or personal"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Enterprise => "enterprise",
            Self::Personal => "personal",
        }
    }

    pub fn is_personal(self) -> bool {
        self == Self::Personal
    }

    /// Where a service listens by default: every address in a container, this machine alone for
    /// the personal engine.
    pub fn bind_address(self, enterprise: &str, personal_port: u16) -> String {
        match self {
            Self::Enterprise => enterprise.to_owned(),
            Self::Personal => format!("127.0.0.1:{personal_port}"),
        }
    }

    /// Where a service reaches another by default: by its Compose name, or on this machine.
    pub fn service_url(self, enterprise: &str, personal_port: u16) -> String {
        match self {
            Self::Enterprise => enterprise.to_owned(),
            Self::Personal => format!("http://127.0.0.1:{personal_port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_is_the_default_and_nothing_else_is_guessed() {
        assert_eq!(Profile::parse(None), Ok(Profile::Enterprise));
        assert_eq!(Profile::parse(Some("")), Ok(Profile::Enterprise));
        assert_eq!(Profile::parse(Some("enterprise")), Ok(Profile::Enterprise));
        assert_eq!(Profile::parse(Some(" personal ")), Ok(Profile::Personal));
        assert!(Profile::parse(Some("Personal")).is_err());
        assert!(Profile::parse(Some("dev")).is_err());
    }

    #[test]
    fn the_personal_engine_stays_on_this_machine() {
        let personal = Profile::Personal;
        assert_eq!(
            personal.bind_address("0.0.0.0:8080", personal::COLLECTOR_PORT),
            "127.0.0.1:47380"
        );
        assert_eq!(
            personal.service_url("http://generator:8081", personal::GENERATOR_PORT),
            "http://127.0.0.1:47381"
        );
        assert_eq!(
            Profile::Enterprise.bind_address("0.0.0.0:8080", personal::COLLECTOR_PORT),
            "0.0.0.0:8080"
        );
    }
}
