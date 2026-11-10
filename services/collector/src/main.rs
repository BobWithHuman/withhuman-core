use std::{io, sync::Arc};

use tokio::sync::watch;
use withhuman_collector::{
    CollectorConfig, CollectorService, ExtAuthzService, GeneratorHttpClient, ModelAccess,
    app_with_transport,
};
use withhuman_common::shutdown::shutdown_signal;
use withhuman_contracts::ext_authz::AuthorizationServer;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = CollectorConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    let generator = Arc::new(GeneratorHttpClient::new(config.generator_url.clone()));
    let service =
        CollectorService::from_config(config.clone(), generator).map_err(io::Error::other)?;
    let mut ext_authz = ExtAuthzService::new(service.verdicts.clone(), config.enforcement_mode);
    if config.model_proxy {
        ext_authz = ext_authz.with_models(ModelAccess {
            keys: service.keys.clone(),
            flags: service.flags.clone(),
            generator: service.generator.clone(),
            require_key: config.require_key,
            failure: config.failure_policy,
        });
    }
    let http_app = app_with_transport(service);

    // Both servers stop on the one signal and finish the requests they hold.
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
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
