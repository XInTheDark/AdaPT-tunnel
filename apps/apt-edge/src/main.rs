//! User-friendly CLI for the combined APT server daemon.

use apt_runtime::{
    d2_certificate_subject_alt_names, d2_default_bind, derive_d2_public_endpoint, encode_key_hex,
    generate_client_identity, generate_d2_tls_identity, generate_server_keyset,
    load_certificate_der, load_key32, run_server, write_key_file, write_secret_file,
    AuthorizedPeerConfig, ClientConfig, RuntimeCarrierPreference, RuntimeMode, ServerConfig,
    SessionPolicy,
};
use apt_types::AuthProfile;
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
    bundle::{add_client, revoke_client, write_server_keyset},
    cli::{Cli, CliAuthProfile, CliRuntimeMode, Command, UtilsCommand},
    init::{enable_d2_for_server, init_server},
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
            enable_d2,
            d2_bind,
            d2_public_endpoint,
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
            enable_d2,
            d2_bind,
            d2_public_endpoint,
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
            auth,
            out_file,
            client_ip,
            yes,
        } => add_client(config, name, auth, out_file, client_ip, yes)?,
        Command::RevokeClient { config, name, yes } => revoke_client(config, name, yes)?,
        Command::Start { config, mode } => start_server(config, mode).await?,
        Command::Utils { command } => match command {
            UtilsCommand::EnableD2 {
                config,
                d2_bind,
                d2_public_endpoint,
                yes,
            } => enable_d2_for_server(config, d2_bind, d2_public_endpoint, yes)?,
        },
        Command::GenKeys { out_dir } => write_server_keyset(&out_dir)?,
    }
    Ok(())
}
