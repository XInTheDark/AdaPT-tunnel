//! User-friendly CLI for the APT VPN client.

use apt_bundle::{client_bundle_state_path, load_client_bundle, DEFAULT_CLIENT_BUNDLE_FILE_NAME};
use apt_runtime::{
    generate_client_identity, run_client, write_key_file, ClientConfig, RuntimeCarrierPreference,
    RuntimeMode,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};
use tracing_subscriber::{fmt, EnvFilter};

mod override_config;

use self::override_config::apply_optional_client_override;

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
    D2,
    S1,
}

impl From<CliCarrier> for RuntimeCarrierPreference {
    fn from(value: CliCarrier) -> Self {
        match value {
            CliCarrier::Auto => Self::Auto,
            CliCarrier::D1 => Self::D1,
            CliCarrier::D2 => Self::D2,
            CliCarrier::S1 => Self::S1,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "apt-client",
    about = "APT VPN client",
    long_about = "APT VPN client. The usual workflow is: install the single-file client bundle into `/etc/adapt/client.aptbundle`, then run `apt-client up`."
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
        /// Path to the client bundle file. If omitted, common default locations are searched.
        #[arg(long)]
        bundle: Option<PathBuf>,
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
            bundle,
            mode,
            carrier,
        } => start_client(bundle, mode, carrier).await?,
        Command::GenIdentity { out_dir } => generate_identity(&out_dir)?,
    }
    Ok(())
}

async fn start_client(
    bundle: Option<PathBuf>,
    mode: Option<CliRuntimeMode>,
    carrier: Option<CliCarrier>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = match bundle {
        Some(path) => path,
        None => find_client_bundle().unwrap_or(prompt_bundle_path()?),
    };
    println!("Using client bundle: {}", bundle_path.display());
    println!("Connecting to the VPN... Press Ctrl-C to disconnect.\n");
    let loaded = load_bundle_config(&bundle_path)?;
    let mut resolved = loaded.resolve()?;
    if let Some(mode) = mode {
        let mode: RuntimeMode = mode.into();
        resolved.runtime_mode = mode;
        mode.apply_to(&mut resolved.session_policy);
    }
    if let Some(carrier) = carrier {
        resolved.preferred_carrier = carrier.into();
        resolved.strict_preferred_carrier = !matches!(carrier, CliCarrier::Auto);
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

fn load_bundle_config(bundle_path: &Path) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut bundle = load_client_bundle(bundle_path)?;
    bundle.config.state_path = client_bundle_state_path(bundle_path);
    let override_path = apply_optional_client_override(&mut bundle.config, bundle_path)?;
    println!("Local override file: {}", override_path.display());
    Ok(bundle.config)
}

fn find_client_bundle() -> Option<PathBuf> {
    [
        PathBuf::from("/etc/adapt").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME),
        PathBuf::from(format!("./{DEFAULT_CLIENT_BUNDLE_FILE_NAME}")),
        PathBuf::from("./adapt-client").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn prompt_bundle_path() -> io::Result<PathBuf> {
    let mut stdout = io::stdout();
    write!(
        stdout,
        "Path to client bundle [/etc/adapt/{DEFAULT_CLIENT_BUNDLE_FILE_NAME}]: "
    )?;
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    Ok(if trimmed.is_empty() {
        PathBuf::from("/etc/adapt").join(DEFAULT_CLIENT_BUNDLE_FILE_NAME)
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
