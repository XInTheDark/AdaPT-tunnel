//! Compatibility CLI for the historical tunnel-node binary name.
//!
//! The production v1 release uses a combined edge+tunnel daemon. This binary is
//! retained as a compatibility alias to the same server runtime used by
//! `apt-edge`.

use apt_observability::{init_tracing, ObservabilityConfig};
use apt_runtime::{generate_server_keyset, write_key_file, ServerConfig, RuntimeError, run_server};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "apt-tunneld", about = "Compatibility alias for the APT combined server daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the combined production server daemon.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate server-side key material and supporting shared secrets.
    GenKeyset {
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
        Command::Serve { config } => serve(config).await,
        Command::GenKeyset { out_dir } => generate_keyset(out_dir),
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn serve(config_path: PathBuf) -> Result<(), RuntimeError> {
    let config = ServerConfig::load(&config_path)?.resolve()?;
    let result = run_server(config).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result.status).expect("server status should serialize to JSON")
    );
    Ok(())
}

fn generate_keyset(out_dir: PathBuf) -> Result<(), RuntimeError> {
    let keyset = generate_server_keyset()?;
    let admission_key = out_dir.join("shared-admission.key");
    let static_private = out_dir.join("server-static-private.key");
    let static_public = out_dir.join("server-static-public.key");
    let cookie_key = out_dir.join("cookie.key");
    let ticket_key = out_dir.join("ticket.key");

    write_key_file(&admission_key, &keyset.admission_key)?;
    write_key_file(&static_private, &keyset.server_static_private_key)?;
    write_key_file(&static_public, &keyset.server_static_public_key)?;
    write_key_file(&cookie_key, &keyset.cookie_key)?;
    write_key_file(&ticket_key, &keyset.ticket_key)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "shared_admission_key": admission_key,
            "server_static_private_key": static_private,
            "server_static_public_key": static_public,
            "cookie_key": cookie_key,
            "ticket_key": ticket_key,
        }))
        .expect("key generation output should serialize")
    );
    Ok(())
}
