use std::io;

use withhuman_common::{graph_store::PostgresSettings, shutdown::shutdown_signal};
use withhuman_decision::{DecisionConfig, serve};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = DecisionConfig::from_env()?;
    let settings = PostgresSettings::from_env()?;
    serve(config, settings, shutdown_signal()).await
}
