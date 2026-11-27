mod config;
mod decision;
mod edr;
mod event;
mod http;
mod pg_backtrack;
mod pg_edr;
mod pg_inventory;
mod pg_repository;
mod pg_triage;
mod repository;
mod wazuh;

mod serve;

pub use config::{GeneratorConfig, WazuhConfig, WazuhTls};
pub use decision::{DecisionClient, DecisionError, HttpDecisionClient};
pub use edr::{
    ClientIdentity, EdrDevice, EdrMatch, EdrSync, EdrSyncError, match_clients, run_edr_sync,
    sync_edr_devices,
};
pub use event::GeneratorEvent;
pub use http::{GeneratorService, app};
pub use pg_repository::PgGraphRepository;
pub use repository::{BacktrackReport, GraphRepository, KeyScope, ReindexReport, RepositoryError};
pub use serve::serve;
pub use wazuh::{WazuhClient, WazuhError};
