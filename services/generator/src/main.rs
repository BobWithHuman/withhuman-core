use std::io;

use withhuman_generator::{GeneratorConfig, GeneratorService, Neo4jRepository, app};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = GeneratorConfig::from_env()?;
    let repository = Neo4jRepository::connect(&config)
        .await
        .map_err(io::Error::other)?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;

    axum::serve(listener, app(GeneratorService::new(repository)))
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
