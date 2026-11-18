use std::{io, sync::Arc};

use withhuman_common::graph_store::PostgresSettings;
use withhuman_decision::{
    DecisionConfig, DecisionProvider, DecisionRepository, DecisionService, JevDecisionProvider,
    MockDecisionProvider, PgDecisionRepository, app, jev::HttpJevClient,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = DecisionConfig::from_env()?;
    // A table of known tools, read before their names are: what each one does.
    if let Some(path) = std::env::var_os("WITHHUMAN_TOOL_CATEGORIES") {
        let count = withhuman_decision::category::load(std::path::Path::new(&path))?;
        eprintln!("decision read {count} tool categories");
    }
    let settings = PostgresSettings::from_env()?;
    let repository: Arc<dyn DecisionRepository> = Arc::new(
        PgDecisionRepository::connect(&settings.database_url, settings.pool_size)
            .await
            .map_err(io::Error::other)?,
    );
    let provider: Arc<dyn DecisionProvider> = match &config.jev {
        Some(jev) => Arc::new(JevDecisionProvider::new(
            repository.clone(),
            Arc::new(HttpJevClient::new(&jev.url, jev.api_key.clone()).map_err(io::Error::other)?),
            config.trace.clone(),
            jev.timeout,
            config.thresholds,
        )),
        None => Arc::new(MockDecisionProvider::new(&config)),
    };
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    eprintln!(
        "decision listening on {} with PostgreSQL",
        config.bind_address
    );

    axum::serve(
        listener,
        app(DecisionService::from_shared(repository, provider)),
    )
    .with_graceful_shutdown(withhuman_common::shutdown::shutdown_signal())
    .await
}
