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
    name = "apt-edge",
    about = "APT VPN server",
    long_about = "APT VPN server. Use `init` to create a server config, `add-client` to generate ready-to-use client bundles, and `start` to run the server."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Guided setup for a new server config + keyset.
    Init {
        /// Directory where server.toml and key files should be written.
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// UDP listen address for the server.
        #[arg(long)]
        bind: Option<SocketAddr>,
        /// Client-reachable host:port that clients should use, for example 203.0.113.10:51820 or vpn.example.com:51820.
        #[arg(long)]
        public_endpoint: Option<String>,
        /// TCP listen address for the stream fallback carrier.
        #[arg(long)]
        stream_bind: Option<SocketAddr>,
        /// Client-reachable host:port for the stream fallback carrier.
        #[arg(long)]
        stream_public_endpoint: Option<String>,
        /// Return a decoy-like HTTP surface on invalid stream input.
        #[arg(long, default_value_t = true)]
        stream_decoy_surface: bool,
        /// Logical deployment identifier.
        #[arg(long)]
        endpoint_id: Option<String>,
        /// Linux egress interface for NAT, for example eth0.
        #[arg(long)]
        egress_interface: Option<String>,
        /// Tunnel subnet in CIDR form, for example 10.77.0.0/24.
        #[arg(long)]
        tunnel_subnet: Option<String>,
        /// Preferred server TUN interface name.
        #[arg(long)]
        interface_name: Option<String>,
        /// Route(s) that should be pushed to clients. Repeat for multiple entries.
        #[arg(long = "push-route")]
        push_routes: Vec<String>,
        /// DNS server(s) suggested to clients. Repeat for multiple entries.
        #[arg(long = "dns")]
        dns_servers: Vec<IpAddr>,
        /// Use defaults for any missing values instead of prompting.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Create a ready-to-use client bundle and authorize it on the server.
    AddClient {
        /// Path to the server config created by `apt-edge init`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Friendly client name, for example laptop.
        #[arg(long)]
        name: Option<String>,
        /// Directory where the client bundle should be written.
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Specific client tunnel IP to assign. If omitted, the next free IP is chosen.
        #[arg(long)]
        client_ip: Option<Ipv4Addr>,
        /// Use defaults for any missing values instead of prompting.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Start the combined server daemon.
    #[command(alias = "serve", alias = "run")]
    Start {
        /// Path to the server config. If omitted, common default locations are searched.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override the runtime mode for this launch only.
        #[arg(long, value_enum)]
        mode: Option<CliRuntimeMode>,
    },
    /// Advanced: generate only the raw key files.
    #[command(hide = true)]
    GenKeys {
        #[arg(long)]
        out_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(error) = run().await {
        eprintln!("apt-edge failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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

fn init_server(
    out_dir: Option<PathBuf>,
    bind: Option<SocketAddr>,
    public_endpoint: Option<String>,
    stream_bind: Option<SocketAddr>,
    stream_public_endpoint: Option<String>,
    stream_decoy_surface: bool,
    endpoint_id: Option<String>,
    egress_interface: Option<String>,
    tunnel_subnet: Option<String>,
    interface_name: Option<String>,
    push_routes: Vec<String>,
    dns_servers: Vec<IpAddr>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("/etc/adapt"));
    let bind = match bind {
        Some(bind) => bind,
        None if yes => "0.0.0.0:51820".parse()?,
        None => prompt_parse("UDP listen address", Some("0.0.0.0:51820"))?,
    };
    let public_endpoint =
        match public_endpoint {
            Some(value) => {
                validate_client_reachable_endpoint(&value)?;
                value
            }
            None if yes && !bind.ip().is_unspecified() => {
                let value = bind.to_string();
                validate_client_reachable_endpoint(&value)?;
                value
            }
            None if yes => return Err(
                "--public-endpoint is required when using --yes with an unspecified bind address"
                    .into(),
            ),
            None => loop {
                let value = prompt_string("Client-reachable public IP/DNS and port", None)?;
                match validate_client_reachable_endpoint(&value) {
                    Ok(()) => break value,
                    Err(error) => eprintln!("Invalid value: {error}"),
                }
            },
        };
    let stream_bind = match stream_bind {
        Some(bind) => Some(bind),
        None if yes => Some("0.0.0.0:443".parse()?),
        None => {
            let value = prompt_string(
                "Optional S1 stream listen address (blank to disable)",
                Some("0.0.0.0:443"),
            )?;
            if value.trim().is_empty() {
                None
            } else {
                Some(value.parse()?)
            }
        }
    };
    let stream_public_endpoint = match stream_public_endpoint {
        Some(value) => {
            validate_client_reachable_endpoint(&value)?;
            Some(value)
        }
        None if stream_bind.is_some() && yes => derive_stream_public_endpoint(&public_endpoint),
        None if stream_bind.is_some() => {
            let value = prompt_string(
                "Optional S1 client-reachable endpoint (blank to disable)",
                derive_stream_public_endpoint(&public_endpoint).as_deref(),
            )?;
            if value.trim().is_empty() {
                None
            } else {
                validate_client_reachable_endpoint(&value)?;
                Some(value)
            }
        }
        None => None,
    };
    let endpoint_id = match endpoint_id {
        Some(value) => value,
        None if yes => "adapt-prod".to_string(),
        None => prompt_string("Deployment name / endpoint ID", Some("adapt-prod"))?,
    };
    let egress_interface = match egress_interface {
        Some(value) => value,
        None if yes => "eth0".to_string(),
        None => prompt_string("Linux egress interface for internet access", Some("eth0"))?,
    };
    let tunnel_subnet = match tunnel_subnet {
        Some(value) => value,
        None if yes => "10.77.0.0/24".to_string(),
        None => prompt_string("Tunnel subnet (CIDR)", Some("10.77.0.0/24"))?,
    };
    let subnet: Ipv4Net = tunnel_subnet
        .parse()
        .map_err(|error| format!("invalid tunnel subnet `{tunnel_subnet}`: {error}"))?;
    let interface_name = match interface_name {
        Some(value) => value,
        None if yes => "aptsrv0".to_string(),
        None => prompt_string("Server TUN interface name", Some("aptsrv0"))?,
    };
    let push_routes = if push_routes.is_empty() {
        vec!["0.0.0.0/0".to_string()]
    } else {
        push_routes
    };
    let push_routes = push_routes
        .into_iter()
        .map(|route| route.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()?;
    let push_dns = if dns_servers.is_empty() {
        vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ]
    } else {
        dns_servers
    };

    fs::create_dir_all(&out_dir)?;
    let keyset = generate_server_keyset()?;
    write_key_file(&out_dir.join("shared-admission.key"), &keyset.admission_key)?;
    write_key_file(
        &out_dir.join("server-static-private.key"),
        &keyset.server_static_private_key,
    )?;
    write_key_file(
        &out_dir.join("server-static-public.key"),
        &keyset.server_static_public_key,
    )?;
    write_key_file(&out_dir.join("cookie.key"), &keyset.cookie_key)?;
    write_key_file(&out_dir.join("ticket.key"), &keyset.ticket_key)?;
    fs::create_dir_all(out_dir.join("bundles"))?;

    let server_ip = first_usable_ipv4(subnet)?;
    let config = ServerConfig {
        bind,
        public_endpoint,
        runtime_mode: RuntimeMode::Stealth,
        stream_bind,
        stream_public_endpoint,
        stream_decoy_surface,
        endpoint_id,
        admission_key: "file:./shared-admission.key".to_string(),
        server_static_private_key: "file:./server-static-private.key".to_string(),
        server_static_public_key: "file:./server-static-public.key".to_string(),
        cookie_key: "file:./cookie.key".to_string(),
        ticket_key: "file:./ticket.key".to_string(),
        interface_name: Some(interface_name.clone()),
        tunnel_local_ipv4: server_ip,
        tunnel_netmask: ipv4_netmask(subnet.prefix_len()),
        tunnel_mtu: 1380,
        egress_interface: Some(egress_interface.clone()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
        push_routes,
        push_dns,
        session_policy: SessionPolicy::default(),
        allow_session_migration: true,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        peers: Vec::new(),
    };
    let config_path = out_dir.join("server.toml");
    config.store(&config_path)?;

    println!("\nAPT server setup complete.\n");
    println!("Created:");
    println!("  • {}", config_path.display());
    println!("  • {}/shared-admission.key", out_dir.display());
    println!("  • {}/server-static-private.key", out_dir.display());
    println!("  • {}/server-static-public.key", out_dir.display());
    println!("  • {}/cookie.key", out_dir.display());
    println!("  • {}/ticket.key", out_dir.display());
    println!("  • {}/bundles/", out_dir.display());
    println!("\nServer summary:");
    println!("  • Listen on: {bind}");
    println!(
        "  • Public endpoint for clients: {}",
        config.public_endpoint
    );
    match &config.stream_public_endpoint {
        Some(endpoint) => println!("  • Stream fallback endpoint: {endpoint}"),
        None => println!("  • Stream fallback endpoint: disabled"),
    }
    println!("  • Tunnel subnet: {}", subnet);
    println!("  • Server tunnel IP: {}", config.tunnel_local_ipv4);
    println!("  • Egress interface: {egress_interface}");
    println!("\nNext steps:");
    println!("  1. Add a client bundle:");
    println!(
        "     apt-edge add-client --config {} --name laptop",
        config_path.display()
    );
    println!("  2. Start the server:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    Ok(())
}

fn add_client(
    config: Option<PathBuf>,
    name: Option<String>,
    out_dir: Option<PathBuf>,
    client_ip: Option<Ipv4Addr>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path =
        match config {
            Some(path) => path,
            None => match find_server_config() {
                Some(path) => path,
                None if yes => return Err(
                    "could not find a server config; pass --config or run `apt-edge init` first"
                        .into(),
                ),
                None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
            },
        };
    let mut server_config = ServerConfig::load(&config_path)?;
    let name = match name {
        Some(value) => value,
        None if yes => return Err("--name is required when using --yes".into()),
        None => prompt_string("Client name", Some("laptop"))?,
    };
    if server_config.peers.iter().any(|peer| peer.name == name) {
        return Err(format!(
            "a client named `{name}` already exists in {}",
            config_path.display()
        )
        .into());
    }
    let bundle_dir = out_dir.unwrap_or_else(|| {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("bundles")
            .join(&name)
    });
    let server_peer_key_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("clients")
        .join(format!("{name}.client-static-public.key"));
    fs::create_dir_all(&bundle_dir)?;
    if let Some(parent) = server_peer_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let client_ip = client_ip.unwrap_or(next_available_client_ipv4(&server_config)?);

    let identity = generate_client_identity()?;
    write_key_file(&server_peer_key_path, &identity.client_static_public_key)?;
    server_config.peers.push(AuthorizedPeerConfig {
        name: name.clone(),
        client_static_public_key: format!("file:{}", server_peer_key_path.display()),
        tunnel_ipv4: client_ip,
    });
    server_config.store(&config_path)?;

    let shared_admission_key = load_key32(&server_config.admission_key)?;
    let server_static_public_key = load_key32(&server_config.server_static_public_key)?;
    write_key_file(
        &bundle_dir.join("shared-admission.key"),
        &shared_admission_key,
    )?;
    write_key_file(
        &bundle_dir.join("server-static-public.key"),
        &server_static_public_key,
    )?;
    write_key_file(
        &bundle_dir.join("client-static-private.key"),
        &identity.client_static_private_key,
    )?;
    write_key_file(
        &bundle_dir.join("client-static-public.key"),
        &identity.client_static_public_key,
    )?;

    let client_config = ClientConfig {
        server_addr: server_config.public_endpoint.clone(),
        runtime_mode: server_config.runtime_mode,
        preferred_carrier: RuntimeCarrierPreference::D1,
        endpoint_id: server_config.endpoint_id.clone(),
        admission_key: "file:./shared-admission.key".to_string(),
        server_static_public_key: "file:./server-static-public.key".to_string(),
        client_static_private_key: "file:./client-static-private.key".to_string(),
        client_identity: Some(name.clone()),
        bind: "0.0.0.0:0".parse()?,
        interface_name: None,
        routes: Vec::new(),
        use_server_pushed_routes: true,
        session_policy: SessionPolicy::default(),
        enable_s1_fallback: true,
        stream_server_addr: server_config.stream_public_endpoint.clone(),
        allow_session_migration: true,
        standby_health_check_secs: 0,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        handshake_timeout_secs: 5,
        handshake_retries: 5,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        state_path: PathBuf::from("./client-state.toml"),
    };
    let client_config_path = bundle_dir.join("client.toml");
    client_config.store(&client_config_path)?;
    write_bundle_readme(&bundle_dir, &name)?;

    println!("\nClient bundle created.\n");
    println!("Updated server config:");
    println!("  • {}", config_path.display());
    println!("Client bundle:");
    println!("  • {}", bundle_dir.display());
    println!("Assigned tunnel IP: {client_ip}");
    println!("\nWhat to do next:");
    println!("  1. Copy this entire folder to the client device:");
    println!("     {}", bundle_dir.display());
    println!("  2. Recommended on the client:");
    println!("     sudo mkdir -p /etc/adapt");
    println!("     sudo cp -R {}/* /etc/adapt/", bundle_dir.display());
    println!("     sudo apt-client up");
    println!("  3. If the server is not already running, start it with:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    Ok(())
}

async fn start_server(
    config: Option<PathBuf>,
    mode: Option<CliRuntimeMode>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = match config {
        Some(path) => path,
        None => match find_server_config() {
            Some(path) => path,
            None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
        },
    };
    println!("Starting APT server using {}", config_path.display());
    println!("Press Ctrl-C to stop.\n");
    let loaded = ServerConfig::load(&config_path)?;
    let _ = loaded.store(&config_path);
    let mut resolved = loaded.resolve()?;
    if let Some(mode) = mode {
        let mode: RuntimeMode = mode.into();
        resolved.runtime_mode = mode;
        mode.apply_to(&mut resolved.session_policy);
    }
    let result = run_server(resolved).await?;
    println!("\nServer stopped.");
    println!(
        "Active sessions at shutdown: {}",
        result.status.active_sessions
    );
    Ok(())
}

fn write_server_keyset(out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let keyset = generate_server_keyset()?;
    write_key_file(&out_dir.join("shared-admission.key"), &keyset.admission_key)?;
    write_key_file(
        &out_dir.join("server-static-private.key"),
        &keyset.server_static_private_key,
    )?;
    write_key_file(
        &out_dir.join("server-static-public.key"),
        &keyset.server_static_public_key,
    )?;
    write_key_file(&out_dir.join("cookie.key"), &keyset.cookie_key)?;
    write_key_file(&out_dir.join("ticket.key"), &keyset.ticket_key)?;
    println!("Raw key files written to {}", out_dir.display());
    Ok(())
}

fn write_bundle_readme(bundle_dir: &Path, name: &str) -> io::Result<()> {
    fs::write(
        bundle_dir.join("START-HERE.txt"),
        format!(
            "APT client bundle for {name}\n\nRecommended install location on the client:\n  /etc/adapt\n\nRecommended steps:\n1. Copy this entire folder to the client device.\n2. On the client, install the bundle into /etc/adapt:\n\n   sudo mkdir -p /etc/adapt\n   sudo cp -R ./* /etc/adapt/\n\n3. Start the VPN using the default config location:\n\n   sudo apt-client up\n\nAlternative: you can also run directly from this folder with:\n\n   sudo apt-client up --config client.toml\n\nNote:\n- `client.toml` contains the server address from the server's `public_endpoint` setting.\n- That value must be a client-reachable IP:port or DNS name:port.\n"
        ),
    )
}

fn find_server_config() -> Option<PathBuf> {
    [
        PathBuf::from("/etc/adapt/server.toml"),
        PathBuf::from("./server.toml"),
        PathBuf::from("./adapt-server/server.toml"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn prompt_string(label: &str, default: Option<&str>) -> io::Result<String> {
    let mut stdout = io::stdout();
    match default {
        Some(default) => write!(stdout, "{label} [{default}]: ")?,
        None => write!(stdout, "{label}: ")?,
    }
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.unwrap_or_default().to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_parse<T>(label: &str, default: Option<&str>) -> Result<T, Box<dyn std::error::Error>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    loop {
        let value = prompt_string(label, default)?;
        match value.parse() {
            Ok(parsed) => return Ok(parsed),
            Err(error) => eprintln!("Invalid value: {error}"),
        }
    }
}

fn prompt_path(label: &str, default: Option<&str>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(prompt_string(label, default)?))
}

fn validate_client_reachable_endpoint(endpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(
            "endpoint cannot be empty; use a client-reachable IP:port or DNS name:port".into(),
        );
    }
    if trimmed.contains("example.com") {
        return Err("endpoint still uses the example placeholder; replace it with the server's real public IP:port or DNS name:port".into());
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return Err("endpoint cannot use 0.0.0.0 or another unspecified address; use the server's real public IP:port or DNS name:port".into());
        }
    }
    Ok(())
}

fn derive_stream_public_endpoint(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    let (host, _) = trimmed.rsplit_once(':')?;
    Some(format!("{host}:443"))
}

fn first_usable_ipv4(subnet: Ipv4Net) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let network = u32::from(subnet.network());
    let broadcast = u32::from(subnet.broadcast());
    if broadcast <= network + 1 {
        return Err("tunnel subnet is too small to allocate a server IP".into());
    }
    Ok(Ipv4Addr::from(network + 1))
}

fn next_available_client_ipv4(
    config: &ServerConfig,
) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let subnet = subnet_from(config.tunnel_local_ipv4, config.tunnel_netmask)?;
    let mut used = HashSet::new();
    used.insert(config.tunnel_local_ipv4);
    for peer in &config.peers {
        used.insert(peer.tunnel_ipv4);
    }
    let start = u32::from(subnet.network()) + 1;
    let end = u32::from(subnet.broadcast());
    for candidate in (start + 1)..end {
        let ip = Ipv4Addr::from(candidate);
        if !used.contains(&ip) {
            return Ok(ip);
        }
    }
    Err("no free client IPs remain in the configured tunnel subnet".into())
}

#[cfg(test)]
mod tests {
    use super::validate_client_reachable_endpoint;

    #[test]
    fn placeholder_public_endpoint_is_rejected() {
        assert!(validate_client_reachable_endpoint("vpn.example.com:51820").is_err());
    }

    #[test]
    fn unspecified_public_endpoint_is_rejected() {
        assert!(validate_client_reachable_endpoint("0.0.0.0:51820").is_err());
    }

    #[test]
    fn explicit_ip_public_endpoint_is_allowed() {
        assert!(validate_client_reachable_endpoint("203.0.113.10:51820").is_ok());
    }

    #[test]
    fn dns_public_endpoint_is_allowed() {
        assert!(validate_client_reachable_endpoint("vpn.my-domain.test:51820").is_ok());
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

fn subnet_from(ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<Ipv4Net, Box<dyn std::error::Error>> {
    let mask = u32::from(netmask);
    let prefix = mask.count_ones() as u8;
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Ok(Ipv4Net::new(network, prefix)?)
}

fn ipv4_netmask(prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    Ipv4Addr::from(mask)
}
