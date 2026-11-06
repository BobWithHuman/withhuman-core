use std::{io, sync::Arc};

use withhuman_common::graph_store::{GraphStore, PostgresSettings};
use withhuman_decision::{
    DecisionConfig, DecisionProvider, DecisionRepository, DecisionService, JevDecisionProvider,
    MockDecisionProvider, Neo4jDecisionRepository, PgDecisionRepository, app, jev::HttpJevClient,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = DecisionConfig::from_env()?;
    let store = GraphStore::from_env()?;
    let repository: Arc<dyn DecisionRepository> = match store {
        GraphStore::Neo4j => Arc::new(
            Neo4jDecisionRepository::connect(&config)
                .await
                .map_err(io::Error::other)?,
        ),
        GraphStore::Postgres => {
            let settings = PostgresSettings::from_env()?;
            Arc::new(
                PgDecisionRepository::connect(&settings.database_url, settings.pool_size)
                    .await
                    .map_err(io::Error::other)?,
            )
        }
    };
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
        "decision listening on {} with the {} graph store",
        config.bind_address,
        store.name()
    );

    axum::serve(
        listener,
        app(DecisionService::from_shared(repository, provider)),
    )
    .with_graceful_shutdown(withhuman_common::shutdown::shutdown_signal())
    .await
}
