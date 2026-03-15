use super::*;
use crate::import::DEFAULT_IMPORT_TIMEOUT_SECS;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum CliAuthProfile {
    Shared,
    PerUser,
}

impl From<CliAuthProfile> for AuthProfile {
    fn from(value: CliAuthProfile) -> Self {
        match value {
            CliAuthProfile::Shared => Self::SharedDeployment,
            CliAuthProfile::PerUser => Self::PerUser,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "apt-edge",
    about = "APT VPN server",
    long_about = "APT VPN server. Use `init` to create a server config, `add-client` to generate ready-to-use single-file client bundles plus an optional temporary import command, and `start` to run the server."
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(super) enum UtilsCommand {
    /// Install or refresh the systemd startup service for an existing server config.
    InstallSystemdService {
        /// Path to the server config created by `apt-edge init`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Use defaults for any missing values instead of prompting.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Enable or refresh the D2 QUIC carrier on an existing server config.
    EnableD2 {
        /// Path to the server config created by `apt-edge init`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// UDP listen address for the D2 QUIC carrier.
        #[arg(long)]
        d2_bind: Option<SocketAddr>,
        /// Client-reachable host:port for the D2 QUIC carrier.
        #[arg(long)]
        d2_public_endpoint: Option<String>,
        /// Use defaults for any missing values instead of prompting.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
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
        /// Enable the D2 QUIC-datagram carrier and generate a pinned server certificate.
        #[arg(long, default_value_t = false)]
        enable_d2: bool,
        /// UDP listen address for the D2 QUIC carrier.
        #[arg(long)]
        d2_bind: Option<SocketAddr>,
        /// Client-reachable host:port for the D2 QUIC carrier.
        #[arg(long)]
        d2_public_endpoint: Option<String>,
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
        /// Optional IPv6 tunnel subnet in CIDR form, for example fd77:77::/64.
        #[arg(long)]
        tunnel_subnet6: Option<String>,
        /// Preferred server TUN interface name.
        #[arg(long)]
        interface_name: Option<String>,
        /// Route(s) that should be pushed to clients. Repeat for multiple entries.
        #[arg(long = "push-route")]
        push_routes: Vec<String>,
        /// DNS server(s) suggested to clients. Repeat for multiple entries.
        #[arg(long = "dns")]
        dns_servers: Vec<IpAddr>,
        /// Install and enable a systemd service so the server starts on boot.
        #[arg(long, default_value_t = false)]
        install_systemd_service: bool,
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
        /// Admission model for this client. `per-user` is recommended for new deployments.
        #[arg(long, value_enum)]
        auth: Option<CliAuthProfile>,
        /// Path where the single-file client bundle should be written.
        #[arg(long)]
        out_file: Option<PathBuf>,
        /// Disable the short-lived temporary import service and only write the local bundle file.
        #[arg(long, default_value_t = false)]
        no_import: bool,
        /// Public hostname or IP that clients should use for the temporary import service.
        #[arg(long)]
        import_host: Option<String>,
        /// Local bind address for the temporary import service. Defaults to 0.0.0.0:0.
        #[arg(long)]
        import_bind: Option<SocketAddr>,
        /// Lifetime of the temporary import service in seconds.
        #[arg(long, default_value_t = DEFAULT_IMPORT_TIMEOUT_SECS)]
        import_timeout_secs: u64,
        /// Specific client tunnel IP to assign. If omitted, the next free IP is chosen.
        #[arg(long)]
        client_ip: Option<Ipv4Addr>,
        /// Specific client tunnel IPv6 to assign. If omitted, the next free IPv6 is chosen when the server has IPv6 enabled.
        #[arg(long)]
        client_ipv6: Option<Ipv6Addr>,
        /// Use defaults for any missing values instead of prompting.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// List the clients currently authorized in the server config.
    #[command(alias = "clients")]
    ListClients {
        /// Path to the server config created by `apt-edge init`.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Revoke a client and remove it from the server config.
    #[command(alias = "remove-client", alias = "del-client")]
    RevokeClient {
        /// Path to the server config created by `apt-edge init`.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Friendly client name to revoke.
        #[arg(long)]
        name: Option<String>,
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
        /// Override the numeric mode for this launch only (0 = speed, 100 = stealth).
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
        mode: Option<u8>,
    },
    /// Hidden helper used to serve a one-shot encrypted client bundle import.
    #[command(hide = true)]
    ServeImport {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        key: String,
        #[arg(long, default_value_t = DEFAULT_IMPORT_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
    /// Operator utilities and maintenance helpers.
    Utils {
        #[command(subcommand)]
        command: UtilsCommand,
    },
    /// Advanced: generate only the raw key files.
    #[command(hide = true)]
    GenKeys {
        #[arg(long)]
        out_dir: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_install_systemd_service_utils_command() {
        let cli = Cli::try_parse_from([
            "apt-edge",
            "utils",
            "install-systemd-service",
            "--config",
            "/etc/adapt/server.toml",
        ])
        .unwrap();

        match cli.command {
            Command::Utils {
                command: UtilsCommand::InstallSystemdService { config, yes },
            } => {
                assert_eq!(config, Some(PathBuf::from("/etc/adapt/server.toml")));
                assert!(!yes);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
