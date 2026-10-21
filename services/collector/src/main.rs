use std::io;

use withhuman_collector::{CollectorConfig, app};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = CollectorConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;

    axum::serve(listener, app(config))
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
