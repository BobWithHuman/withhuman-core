use std::io;

use withhuman_collector::{CollectorConfig, serve};
use withhuman_common::shutdown::shutdown_signal;

#[tokio::main]
async fn main() -> io::Result<()> {
    serve(CollectorConfig::from_env()?, shutdown_signal()).await
}
