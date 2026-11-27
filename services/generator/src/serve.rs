//! The Generator run until `shutdown`, on PostgreSQL, with the EDR sync when it has one. The
//! service's own binary and `withhuman-local` run it alike.

use std::{future::Future, io};

use crate::{
    GeneratorConfig, GeneratorService, HttpDecisionClient, PgGraphRepository, app, run_edr_sync,
};

pub async fn serve(
    config: GeneratorConfig,
    repository: PgGraphRepository,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    // The company's device list from its EDR; nothing runs without WITHHUMAN_WAZUH_URL.
    if let Some(wazuh) = config.wazuh.clone() {
        tokio::spawn(run_edr_sync(repository.clone(), wazuh));
    }
    let decision = HttpDecisionClient::new(&config).map_err(io::Error::other)?;
    let service = GeneratorService::with_decision(repository, decision);
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    eprintln!(
        "generator listening on {} with PostgreSQL",
        config.bind_address
    );

    axum::serve(listener, app(service))
        .with_graceful_shutdown(shutdown)
        .await
}
