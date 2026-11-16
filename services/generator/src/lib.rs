mod config;
mod decision;
mod edr;
mod event;
mod http;
mod pg_edr;
mod pg_inventory;
mod pg_repository;
mod pg_triage;
mod repository;
mod wazuh;

pub use config::{GeneratorConfig, WazuhConfig, WazuhTls};
pub use decision::{DecisionClient, DecisionError, HttpDecisionClient};
pub use edr::{
    ClientIdentity, EdrDevice, EdrMatch, EdrSync, EdrSyncError, match_clients, run_edr_sync,
    sync_edr_devices,
};
pub use event::GeneratorEvent;
pub use http::{GeneratorService, app};
pub use pg_repository::PgGraphRepository;
pub use repository::{GraphRepository, KeyScope, ReindexReport, RepositoryError};
pub use wazuh::{WazuhClient, WazuhError};
