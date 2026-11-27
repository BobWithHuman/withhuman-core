//! Decision run until `shutdown`, on PostgreSQL. The service's own binary and `withhuman-local`
//! run it alike.

use std::{future::Future, io, sync::Arc};

use withhuman_common::graph_store::PostgresSettings;

use crate::{
    DecisionConfig, DecisionProvider, DecisionRepository, DecisionService, JevDecisionProvider,
    MockDecisionProvider, PgDecisionRepository, app, jev::HttpJevClient,
};

pub async fn serve(
    config: DecisionConfig,
    settings: PostgresSettings,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    // A table of known tools, read before their names are: what each one does.
    if let Some(path) = std::env::var_os("WITHHUMAN_TOOL_CATEGORIES") {
        let count = crate::category::load(std::path::Path::new(&path))?;
        eprintln!("decision read {count} tool categories");
    }
    let repository: Arc<dyn DecisionRepository> = Arc::new(
        PgDecisionRepository::connect(&settings.database_url, settings.pool_size)
            .await
            .map_err(io::Error::other)?,
    );
    let provider: Arc<dyn DecisionProvider> = match &config.jev {
        Some(jev) => Arc::new(JevDecisionProvider::new(
            repository.clone(),
            Arc::new(HttpJevClient::new(&jev.url, jev.api_key.clone()).map_err(io::Error::other)?),
            config.trace.clone(),
            jev.timeout,
            config.thresholds,
        )),
        None if config.provider.eq_ignore_ascii_case("rules") => {
            Arc::new(JevDecisionProvider::rules_only(
                repository.clone(),
                config.trace.clone(),
                config.thresholds,
            ))
        }
        None => Arc::new(MockDecisionProvider::new(&config)),
    };
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    eprintln!(
        "decision listening on {} with PostgreSQL",
        config.bind_address
    );

    axum::serve(
        listener,
        app(DecisionService::from_shared(repository, provider)),
    )
    .with_graceful_shutdown(shutdown)
    .await
}
