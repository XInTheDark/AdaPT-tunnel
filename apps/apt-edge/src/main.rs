//! User-friendly CLI for the combined APT server daemon.

use apt_runtime::{
    generate_client_identity, generate_server_keyset, load_key32, run_server, write_key_file,
    AuthorizedPeerConfig, ClientConfig, RuntimeCarrierPreference, RuntimeMode, ServerConfig,
    SessionPolicy,
};
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::{IpNet, Ipv4Net};
use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};
use tracing_subscriber::{fmt, EnvFilter};

mod bundle;
mod cli;
mod init;
mod start;
mod support;

use self::{
    bundle::{add_client, write_server_keyset},
    cli::{Cli, CliRuntimeMode, Command},
    init::init_server,
    start::start_server,
    support::*,
};

type CliResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(error) = run().await {
        eprintln!("apt-edge failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> CliResult {
    match Cli::parse().command {
        Command::Init {
            out_dir,
            bind,
            public_endpoint,
            stream_bind,
            stream_public_endpoint,
            stream_decoy_surface,
            endpoint_id,
            egress_interface,
            tunnel_subnet,
            interface_name,
            push_routes,
            dns_servers,
            yes,
        } => init_server(
            out_dir,
            bind,
            public_endpoint,
            stream_bind,
            stream_public_endpoint,
            stream_decoy_surface,
            endpoint_id,
            egress_interface,
            tunnel_subnet,
            interface_name,
            push_routes,
            dns_servers,
            yes,
        )?,
        Command::AddClient {
            config,
            name,
            out_dir,
            client_ip,
            yes,
        } => add_client(config, name, out_dir, client_ip, yes)?,
        Command::Start { config, mode } => start_server(config, mode).await?,
        Command::GenKeys { out_dir } => write_server_keyset(&out_dir)?,
    }
    Ok(())
}
