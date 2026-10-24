use std::{env, io};

use withhuman_generator::{
    GeneratorConfig, GeneratorService, HttpDecisionClient, Neo4jRepository, app,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = GeneratorConfig::from_env()?;
    let repository = Neo4jRepository::connect(&config)
        .await
        .map_err(io::Error::other)?;
    if env::args().nth(1).as_deref() == Some("reindex-paragraphs") {
        let report = repository
            .reindex_paragraphs()
            .await
            .map_err(io::Error::other)?;
        println!(
            "re-chunked {} of {} committed events",
            report.reindexed, report.scanned
        );
        return Ok(());
    }
    let decision = HttpDecisionClient::new(&config).map_err(io::Error::other)?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;

    axum::serve(
        listener,
        app(GeneratorService::with_decision(repository, decision)),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
