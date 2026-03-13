//! Production CLI for the APT client runtime.

use apt_observability::{init_tracing, ObservabilityConfig};
use apt_runtime::{generate_client_identity, write_key_file, ClientConfig, RuntimeError, run_client};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "apt-client", about = "APT production client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Connect to a production APT server using the supplied config file.
    Connect {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate a stable client Noise static identity for shared-key deployments.
    GenIdentity {
        #[arg(long)]
        out_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let observability = ObservabilityConfig::default();
    init_tracing(&observability);

    let result = match cli.command {
        Command::Connect { config } => connect(config).await,
        Command::GenIdentity { out_dir } => generate_identity(out_dir),
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn connect(config_path: PathBuf) -> Result<(), RuntimeError> {
    let config = ClientConfig::load(&config_path)?.resolve()?;
    let result = run_client(config).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result.status).expect("client status should serialize to JSON")
    );
    Ok(())
}

fn generate_identity(out_dir: PathBuf) -> Result<(), RuntimeError> {
    let identity = generate_client_identity()?;
    let private_path = out_dir.join("client-static-private.key");
    let public_path = out_dir.join("client-static-public.key");
    write_key_file(&private_path, &identity.client_static_private_key)?;
    write_key_file(&public_path, &identity.client_static_public_key)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "client_static_private_key": private_path,
            "client_static_public_key": public_path,
        }))
        .expect("key generation output should serialize")
    );
    Ok(())
}
