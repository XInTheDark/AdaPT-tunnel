//! Production client for the first usable APT VPN release.

use apt_runtime::{
    encode_key_hex, generate_client_identity, run_client, write_key_file, ClientConfig,
};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "apt-client", about = "APT VPN client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Connect to the configured combined server and run the VPN tunnel.
    Connect {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate a stable client static identity into the supplied directory.
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
    let cli = Cli::parse();
    match cli.command {
        Command::Connect { config } => {
            let config = ClientConfig::load(&config)?.resolve()?;
            let result = run_client(config).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::GenIdentity { out_dir } => {
            let identity = generate_client_identity()?;
            write_key_file(&out_dir.join("client-static-private.key"), &identity.client_static_private_key)?;
            write_key_file(&out_dir.join("client-static-public.key"), &identity.client_static_public_key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "out_dir": out_dir,
                    "client_static_public_key": encode_key_hex(&identity.client_static_public_key),
                    "files": {
                        "client_static_private_key": "client-static-private.key",
                        "client_static_public_key": "client-static-public.key"
                    }
                }))?
            );
        }
    }
    Ok(())
}
