//! When a service should stop taking work: Ctrl-C locally, SIGTERM from Docker or Kubernetes.

/// Resolves on the first shutdown signal. Call it once, at startup, so the handlers are in place
/// before the service takes work.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).expect("a SIGTERM handler can be installed");
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.expect("a Ctrl-C handler can be installed"),
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("a Ctrl-C handler can be installed");
}
