use std::{io, sync::Arc};

use withhuman_decision::{
    DecisionConfig, DecisionProvider, DecisionRepository, DecisionService, JevDecisionProvider,
    MockDecisionProvider, Neo4jDecisionRepository, app, jev::HttpJevClient,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = DecisionConfig::from_env()?;
    let repository: Arc<dyn DecisionRepository> = Arc::new(
        Neo4jDecisionRepository::connect(&config)
            .await
            .map_err(io::Error::other)?,
    );
    let provider: Arc<dyn DecisionProvider> = match &config.jev {
        Some(jev) => Arc::new(JevDecisionProvider::new(
            repository.clone(),
            Arc::new(HttpJevClient::new(&jev.url, jev.api_key.clone()).map_err(io::Error::other)?),
            config.trace.clone(),
            jev.timeout,
            config.intent_block_threshold,
        )),
        None => Arc::new(MockDecisionProvider::new(&config)),
    };
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;

    axum::serve(
        listener,
        app(DecisionService::from_shared(repository, provider)),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
