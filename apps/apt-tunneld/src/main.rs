//! Compatibility entrypoint that runs the same combined server daemon as `apt-edge`.

use apt_runtime::{run_server, ServerConfig};
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "apt-tunneld", about = "Compatibility alias for the combined APT server daemon")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match ServerConfig::load(&cli.config)
        .and_then(|config| config.resolve())
        .map_err(Box::<dyn std::error::Error>::from)
    {
        Ok(config) => match run_server(config).await {
            Ok(result) => {
                println!("{}", serde_json::to_string_pretty(&result).expect("json serialization should succeed"));
            }
            Err(error) => {
                eprintln!("apt-tunneld failed: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("apt-tunneld failed: {error}");
            std::process::exit(1);
        }
    }
}
