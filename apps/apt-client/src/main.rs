//! User-friendly CLI for the APT VPN client.

use apt_runtime::{
    generate_client_identity, run_client, write_key_file, ClientConfig, RuntimeCarrierPreference,
    RuntimeMode,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::{self, Write},
    path::PathBuf,
};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliRuntimeMode {
    Stealth,
    Balanced,
    Speed,
}

impl From<CliRuntimeMode> for RuntimeMode {
    fn from(value: CliRuntimeMode) -> Self {
        match value {
            CliRuntimeMode::Stealth => Self::Stealth,
            CliRuntimeMode::Balanced => Self::Balanced,
            CliRuntimeMode::Speed => Self::Speed,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliCarrier {
    Auto,
    D1,
    S1,
}

impl From<CliCarrier> for RuntimeCarrierPreference {
    fn from(value: CliCarrier) -> Self {
        match value {
            CliCarrier::Auto => Self::Auto,
            CliCarrier::D1 => Self::D1,
            CliCarrier::S1 => Self::S1,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "apt-client",
    about = "APT VPN client",
    long_about = "APT VPN client. The usual workflow is: install the client bundle into `/etc/adapt`, then run `apt-client up`."
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
        /// Override the runtime mode for this launch only.
        #[arg(long, value_enum)]
        mode: Option<CliRuntimeMode>,
        /// Override the preferred carrier for this launch only.
        #[arg(long, value_enum)]
        carrier: Option<CliCarrier>,
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
    init_logging();
    if let Err(error) = run().await {
        eprintln!("apt-client failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Up {
            config,
            mode,
            carrier,
        } => start_client(config, mode, carrier).await?,
        Command::GenIdentity { out_dir } => generate_identity(&out_dir)?,
    }
    Ok(())
}

async fn start_client(
    config: Option<PathBuf>,
    mode: Option<CliRuntimeMode>,
    carrier: Option<CliCarrier>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = match config {
        Some(path) => path,
        None => find_client_config().unwrap_or(prompt_config_path()?),
    };
    println!("Using client bundle: {}", config_path.display());
    println!("Connecting to the VPN... Press Ctrl-C to disconnect.\n");
    let loaded = ClientConfig::load(&config_path)?;
    let _ = loaded.store(&config_path);
    let mut resolved = loaded.resolve()?;
    if let Some(mode) = mode {
        let mode: RuntimeMode = mode.into();
        resolved.runtime_mode = mode;
        mode.apply_to(&mut resolved.session_policy);
    }
    if let Some(carrier) = carrier {
        resolved.preferred_carrier = carrier.into();
    }
    let result = run_client(resolved).await?;
    println!("\nVPN session ended.");
    if let Some(tunnel_ip) = result.status.tunnel_address {
        println!("Last tunnel IP: {tunnel_ip}");
    }
    Ok(())
}

fn generate_identity(out_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
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

fn find_client_config() -> Option<PathBuf> {
    [
        PathBuf::from("/etc/adapt/client.toml"),
        PathBuf::from("./client.toml"),
        PathBuf::from("./adapt-client/client.toml"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn prompt_config_path() -> io::Result<PathBuf> {
    let mut stdout = io::stdout();
    write!(stdout, "Path to client.toml [/etc/adapt/client.toml]: ")?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    Ok(if trimmed.is_empty() {
        PathBuf::from("/etc/adapt/client.toml")
    } else {
        PathBuf::from(trimmed)
    })
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
