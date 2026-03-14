//! Compatibility entrypoint that runs the same combined server daemon as `apt-edge`.

use apt_runtime::{run_server, RuntimeMode, ServerConfig};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
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

#[derive(Debug, Parser)]
#[command(
    name = "apt-tunneld",
    about = "Compatibility alias for the combined APT server daemon"
)]
struct Cli {
    /// Path to the server config. If omitted, /etc/adapt/server.toml is used.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override the runtime mode for this launch only.
    #[arg(long, value_enum)]
    mode: Option<CliRuntimeMode>,
}

#[tokio::main]
async fn main() {
    init_logging();
    let cli = Cli::parse();
    let config_path = cli
        .config
        .unwrap_or_else(|| PathBuf::from("/etc/adapt/server.toml"));
    match ServerConfig::load(&config_path).map_err(Box::<dyn std::error::Error>::from) {
        Ok(loaded) => {
            let _ = loaded.store(&config_path);
            let mut config = match loaded.resolve() {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("apt-tunneld failed: {error}");
                    std::process::exit(1);
                }
            };
            if let Some(mode) = cli.mode {
                let mode: RuntimeMode = mode.into();
                config.runtime_mode = mode;
                mode.apply_to(&mut config.session_policy);
            }
            match run_server(config).await {
                Ok(result) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result)
                            .expect("json serialization should succeed")
                    );
                }
                Err(error) => {
                    eprintln!("apt-tunneld failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        Err(error) => {
            eprintln!("apt-tunneld failed: {error}");
            std::process::exit(1);
        }
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
