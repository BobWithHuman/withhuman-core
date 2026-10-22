use std::io;

use withhuman_decision::{
    DecisionConfig, DecisionService, MockDecisionProvider, Neo4jDecisionRepository, app,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = DecisionConfig::from_env()?;
    let repository = Neo4jDecisionRepository::connect(&config)
        .await
        .map_err(io::Error::other)?;
    let provider = MockDecisionProvider::new(&config);
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;

    axum::serve(listener, app(DecisionService::new(repository, provider)))
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
