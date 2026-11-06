use std::{env, io};

use withhuman_common::graph_store::{GraphStore, PostgresSettings};
use withhuman_generator::{
    GeneratorConfig, GeneratorService, HttpDecisionClient, Neo4jRepository, PgGraphRepository, app,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = GeneratorConfig::from_env()?;
    let store = GraphStore::from_env()?;
    let reindex = env::args().nth(1).as_deref() == Some("reindex-paragraphs");
    let service = match store {
        GraphStore::Neo4j => {
            let repository = Neo4jRepository::connect(&config)
                .await
                .map_err(io::Error::other)?;
            // Re-chunking needs only the graph, so it runs before the Decision client is made
            // and works where Decision is not configured.
            if reindex {
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
            GeneratorService::with_decision(repository, decision)
        }
        GraphStore::Postgres => {
            // Not built for PostgreSQL yet. Refusing keeps an operator from taking a server
            // that started listening for a finished re-index.
            if reindex {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "reindex-paragraphs supports only WITHHUMAN_GRAPH_STORE=neo4j",
                ));
            }
            let settings = PostgresSettings::from_env()?;
            let repository = PgGraphRepository::connect(&settings.database_url, settings.pool_size)
                .await
                .map_err(io::Error::other)?;
            let decision = HttpDecisionClient::new(&config).map_err(io::Error::other)?;
            GeneratorService::with_decision(repository, decision)
        }
    };
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    eprintln!(
        "generator listening on {} with the {} graph store",
        config.bind_address,
        store.name()
    );

    axum::serve(listener, app(service))
        .with_graceful_shutdown(withhuman_common::shutdown::shutdown_signal())
        .await
}
