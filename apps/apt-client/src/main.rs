//! User-friendly CLI for the APT VPN client.

use apt_runtime::{generate_client_identity, run_client, write_key_file, ClientConfig};
use clap::{Parser, Subcommand};
use std::{
    io::{self, Write},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[command(
    name = "apt-client",
    about = "APT VPN client",
    long_about = "APT VPN client. The usual workflow is: receive a client bundle from the server operator, then run `apt-client up --config client.toml`."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the VPN using a client config bundle.
    #[command(alias = "connect", alias = "start", alias = "run")]
    Up {
        /// Path to client.toml. If omitted, common default locations are searched.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Advanced: generate only a standalone client identity.
    #[command(hide = true)]
    GenIdentity {
        #[arg(long)]
        out_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("apt-client failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Up { config } => start_client(config).await?,
        Command::GenIdentity { out_dir } => generate_identity(&out_dir)?,
    }
    Ok(())
}

async fn start_client(config: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = match config {
        Some(path) => path,
        None => find_client_config().unwrap_or(prompt_config_path()?),
    };
    println!("Using client bundle: {}", config_path.display());
    println!("Connecting to the VPN... Press Ctrl-C to disconnect.\n");
    let result = run_client(ClientConfig::load(&config_path)?.resolve()?).await?;
    println!("\nVPN session ended.");
    if let Some(tunnel_ip) = result.status.tunnel_address {
        println!("Last tunnel IP: {tunnel_ip}");
    }
    Ok(())
}

fn generate_identity(out_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let identity = generate_client_identity()?;
    write_key_file(&out_dir.join("client-static-private.key"), &identity.client_static_private_key)?;
    write_key_file(&out_dir.join("client-static-public.key"), &identity.client_static_public_key)?;
    println!("Standalone client identity written to {}", out_dir.display());
    Ok(())
}

fn find_client_config() -> Option<PathBuf> {
    [
        PathBuf::from("./client.toml"),
        PathBuf::from("./adapt-client/client.toml"),
        PathBuf::from("/etc/adapt/client.toml"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn prompt_config_path() -> io::Result<PathBuf> {
    let mut stdout = io::stdout();
    write!(stdout, "Path to client.toml: ")?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(PathBuf::from(input.trim()))
}
