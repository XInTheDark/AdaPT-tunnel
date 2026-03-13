//! Combined production server daemon for the first usable APT release.

use apt_runtime::{
    encode_key_hex, generate_server_keyset, run_server, write_key_file, ServerConfig,
};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "apt-edge", about = "APT combined server daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the combined edge+tunnel UDP server.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate a fresh server keyset into the supplied directory.
    GenKeys {
        #[arg(long)]
        out_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("apt-edge failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => {
            let config = ServerConfig::load(&config)?.resolve()?;
            let result = run_server(config).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::GenKeys { out_dir } => {
            let keyset = generate_server_keyset()?;
            write_key_file(&out_dir.join("shared-admission.key"), &keyset.admission_key)?;
            write_key_file(&out_dir.join("server-static-private.key"), &keyset.server_static_private_key)?;
            write_key_file(&out_dir.join("server-static-public.key"), &keyset.server_static_public_key)?;
            write_key_file(&out_dir.join("cookie.key"), &keyset.cookie_key)?;
            write_key_file(&out_dir.join("ticket.key"), &keyset.ticket_key)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "out_dir": out_dir,
                    "shared_admission_key": encode_key_hex(&keyset.admission_key),
                    "server_static_public_key": encode_key_hex(&keyset.server_static_public_key),
                    "files": {
                        "shared_admission_key": "shared-admission.key",
                        "server_static_private_key": "server-static-private.key",
                        "server_static_public_key": "server-static-public.key",
                        "cookie_key": "cookie.key",
                        "ticket_key": "ticket.key"
                    }
                }))?
            );
        }
    }
    Ok(())
}
