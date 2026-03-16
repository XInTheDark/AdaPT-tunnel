//! User-friendly CLI for the combined APT server daemon.

use apt_runtime::{
    encode_key_hex, generate_client_identity, generate_d2_tls_identity, generate_server_keyset,
    load_certificate_der, load_key32, run_server, write_key_file, write_secret_file,
    AuthorizedPeerConfig, ClientConfig, Mode, ServerConfig, SessionPolicy, V2DeploymentStrength,
};
use apt_types::AuthProfile;
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};
use tracing_subscriber::{fmt, EnvFilter};

mod bundle;
mod cli;
mod import;
mod init;
mod start;
mod startup;
mod support;

use self::{
    bundle::{add_client, list_clients, revoke_client, write_server_keyset},
    cli::{Cli, CliAuthProfile, Command, UtilsCommand},
    import::serve_client_bundle_import,
    init::{init_server, install_systemd_service_for_server},
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
            authority,
            endpoint_id,
            egress_interface,
            tunnel_subnet,
            tunnel_subnet6,
            interface_name,
            push_routes,
            dns_servers,
            install_systemd_service,
            yes,
        } => init_server(
            out_dir,
            bind,
            public_endpoint,
            authority,
            endpoint_id,
            egress_interface,
            tunnel_subnet,
            tunnel_subnet6,
            interface_name,
            push_routes,
            dns_servers,
            install_systemd_service,
            yes,
        )?,
        Command::AddClient {
            config,
            name,
            auth,
            out_file,
            no_import,
            import_host,
            import_bind,
            import_timeout_secs,
            client_ip,
            client_ipv6,
            yes,
        } => add_client(
            config,
            name,
            auth,
            out_file,
            no_import,
            import_host,
            import_bind,
            import_timeout_secs,
            client_ip,
            client_ipv6,
            yes,
        )?,
        Command::ListClients { config } => list_clients(config)?,
        Command::RevokeClient { config, name, yes } => revoke_client(config, name, yes)?,
        Command::Start { config, mode } => start_server(config, mode).await?,
        Command::ServeImport {
            bundle,
            bind,
            key,
            timeout_secs,
        } => serve_client_bundle_import(bundle, bind, key, timeout_secs).await?,
        Command::Utils { command } => match command {
            UtilsCommand::InstallSystemdService { config, yes } => {
                install_systemd_service_for_server(config, yes)?
            }
        },
        Command::GenKeys { out_dir } => write_server_keyset(&out_dir)?,
    }
    Ok(())
}
