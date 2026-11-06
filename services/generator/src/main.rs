use std::{env, io};

use withhuman_common::graph_store::PostgresSettings;
use withhuman_generator::{
    GeneratorConfig, GeneratorService, HttpDecisionClient, PgGraphRepository, app,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = GeneratorConfig::from_env()?;
    let settings = PostgresSettings::from_env()?;
    let repository = PgGraphRepository::connect(&settings.database_url, settings.pool_size)
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
    let service = GeneratorService::with_decision(repository, decision);
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    eprintln!(
        "generator listening on {} with PostgreSQL",
        config.bind_address
    );

    axum::serve(listener, app(service))
        .with_graceful_shutdown(withhuman_common::shutdown::shutdown_signal())
        .await
}
