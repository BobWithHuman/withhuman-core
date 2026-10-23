use std::io;

use std::sync::Arc;
use withhuman_decision::{
    DecisionConfig, DecisionProvider, DecisionService, JevDecisionProvider, MockDecisionProvider,
    Neo4jDecisionRepository, app,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = DecisionConfig::from_env()?;
    let repository = Neo4jDecisionRepository::connect(&config)
        .await
        .map_err(io::Error::other)?;
    let provider: Arc<dyn DecisionProvider> = if config.provider.eq_ignore_ascii_case("mock") {
        Arc::new(MockDecisionProvider::new(&config))
    } else {
        Arc::new(JevDecisionProvider::new(&config))
    };
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;

    axum::serve(
        listener,
        app(DecisionService::from_shared(Arc::new(repository), provider)),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
