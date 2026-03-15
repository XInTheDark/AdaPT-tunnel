//! Compatibility entrypoint that runs the same combined server daemon as `apt-edge`.

use apt_runtime::{run_server, Mode, ServerConfig};
use clap::{value_parser, Parser};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Parser)]
#[command(
    name = "apt-tunneld",
    about = "Compatibility alias for the combined APT server daemon"
)]
struct Cli {
    /// Path to the server config. If omitted, /etc/adapt/server.toml is used.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override the numeric mode for this launch only (0 = speed, 100 = stealth).
    #[arg(long, value_parser = value_parser!(u8).range(0..=100))]
    mode: Option<u8>,
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
                let mode = Mode::try_from(mode).expect("clap validated mode range");
                config.mode = mode;
                config.session_policy.initial_mode = mode.policy_mode();
                config.session_policy.allow_speed_first = mode.allow_speed_first();
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
