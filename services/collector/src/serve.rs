//! The Collector run until `shutdown`: its HTTP API and the gateway's extAuthz server, both
//! finishing the requests they hold. The service's own binary and `withhuman-local` run it alike.

use std::{future::Future, io, sync::Arc};

use tokio::sync::watch;
use withhuman_contracts::ext_authz::AuthorizationServer;

use crate::{CollectorConfig, CollectorService, ExtAuthzService, GeneratorHttpClient};

pub async fn serve(
    config: CollectorConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    let generator = Arc::new(GeneratorHttpClient::with_token(
        config.generator_url.clone(),
        config.internal_token.as_deref(),
    ));
    let service =
        CollectorService::from_config(config.clone(), generator).map_err(io::Error::other)?;
    let ext_authz = ExtAuthzService::new(service.verdicts.clone(), config.enforcement_mode);
    let http_app = crate::app_with_transport(service);
    eprintln!(
        "collector listening on {} ({})",
        config.bind_address,
        config.profile.name()
    );

    // Both servers stop on the one signal.
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop.send(true);
    });

    let http = axum::serve(listener, http_app).with_graceful_shutdown(wait_for(stopped.clone()));
    let grpc = tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(ext_authz))
        .serve_with_shutdown(config.ext_authz_address, wait_for(stopped));

    tokio::try_join!(async { http.await.map_err(io::Error::other) }, async {
        grpc.await.map_err(io::Error::other)
    })?;
    Ok(())
}

async fn wait_for(mut stopped: watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stopped| *stopped).await;
}
