//! User-friendly CLI for the APT VPN client.

use apt_runtime::{generate_client_identity, write_key_file};
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

mod cli;
mod daemon_client;
mod import;
mod paths;
mod qa;
mod service;
mod tui;
mod up;

use self::{
    cli::{Cli, Command},
    import::import_client_bundle,
    qa::run_targeted_tests,
    service::handle_service_command,
    tui::run_tui,
    up::start_client,
};

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(error) = run().await {
        eprintln!("apt-client failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match Cli::parse().command {
        Command::Import {
            server,
            key,
            bundle,
        } => import_client_bundle(server, key, bundle).await?,
        Command::Up { launch } => start_client(launch).await?,
        Command::Test { options } => run_targeted_tests(options).await?,
        Command::Tui { options } => run_tui(options).await?,
        Command::Service { command } => handle_service_command(command).await?,
        Command::GenIdentity { out_dir } => generate_identity(&out_dir)?,
    }
    Ok(())
}

fn generate_identity(out_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let identity = generate_client_identity()?;
    write_key_file(
        &out_dir.join("client-static-private.key"),
        &identity.client_static_private_key,
    )?;
    write_key_file(
        &out_dir.join("client-static-public.key"),
        &identity.client_static_public_key,
    )?;
    println!(
        "Standalone client identity written to {}",
        out_dir.display()
    );
    Ok(())
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
