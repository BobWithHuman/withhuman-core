use std::{io, sync::Arc};

use withhuman_collector::{
    CollectorConfig, CollectorService, ExtAuthzService, GeneratorHttpClient, app_with_transport,
};
use withhuman_contracts::ext_authz::AuthorizationServer;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = CollectorConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.bind_address).await?;
    let generator = Arc::new(GeneratorHttpClient::new(config.generator_url.clone()));
    let service = CollectorService::new(config.clone(), generator);
    let ext_authz = ExtAuthzService::new(service.verdicts.clone(), config.enforcement_mode);
    let http_app = app_with_transport(service);

    let http = axum::serve(listener, http_app);
    let grpc = tonic::transport::Server::builder()
        .add_service(AuthorizationServer::new(ext_authz))
        .serve(config.ext_authz_address);

    tokio::select! {
        result = http => result.map_err(io::Error::other),
        result = grpc => result.map_err(io::Error::other),
        _ = shutdown_signal() => Ok(()),
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
