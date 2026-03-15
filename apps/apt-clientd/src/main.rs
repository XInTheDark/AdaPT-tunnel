//! Local privileged AdaPT client daemon.

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

mod cli;
mod daemon;
mod ipc;
mod latency;
mod supervisor;

use self::cli::Cli;

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(error) = daemon::run(Cli::parse()).await {
        eprintln!("apt-clientd failed: {error}");
        std::process::exit(1);
    }
}

fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,apt_runtime=info"));
    let _ = fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .without_time()
        .try_init();
}
