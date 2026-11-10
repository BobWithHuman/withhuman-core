use std::{env, io};

use withhuman_common::graph_store::PostgresSettings;
use withhuman_generator::{
    GeneratorConfig, GeneratorService, HttpDecisionClient, PgGraphRepository, app,
};

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = GeneratorConfig::from_env()?;
    let settings = PostgresSettings::from_env()?;
    // The security team's viewer reads the graph through its own login (WITHHUMAN_VIEWER_PASSWORD).
    let viewer_password = env::var("WITHHUMAN_VIEWER_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty());
    let repository = PgGraphRepository::connect_with_viewer(
        &settings.database_url,
        settings.pool_size,
        viewer_password.as_deref(),
    )
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
    // With the model route on, the tokens of model requests come from the gateway's request log.
    if env::var("WITHHUMAN_MODEL_PROXY")
        .is_ok_and(|value| matches!(value.as_str(), "on" | "true" | "1"))
    {
        let importer = repository.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                every.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(0));
                if let Err(error) = importer
                    .import_model_tokens(now.saturating_sub(2 * 86_400_000))
                    .await
                {
                    eprintln!("model tokens not imported: {error}");
                }
            }
        });
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
