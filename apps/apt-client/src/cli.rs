use apt_client_control::ClientCarrier;
use clap::{value_parser, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 20;
const DEFAULT_PING_COUNT: u8 = 4;
const DEFAULT_DNS_HOST: &str = "example.com";
const DEFAULT_PUBLIC_IP_URL: &str = "https://api.ipify.org";
const DEFAULT_SPEEDTEST_BYTES: usize = 25_000_000;
const DEFAULT_SPEEDTEST_TIMEOUT_SECS: u64 = 45;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum CliCarrier {
    Auto,
    D1,
    D2,
    S1,
}

impl From<CliCarrier> for ClientCarrier {
    fn from(value: CliCarrier) -> Self {
        match value {
            CliCarrier::Auto => Self::Auto,
            CliCarrier::D1 => Self::D1,
            CliCarrier::D2 => Self::D2,
            CliCarrier::S1 => Self::S1,
        }
    }
}

impl ClientLaunchArgs {
    pub(crate) fn to_launch_options(
        &self,
        bundle: Option<PathBuf>,
    ) -> apt_client_control::ClientLaunchOptions {
        apt_client_control::ClientLaunchOptions {
            bundle_path: bundle.or_else(|| self.bundle.clone()),
            mode: self.mode,
            carrier: self.carrier.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct ClientLaunchArgs {
    /// Path to the client bundle file.
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Override the numeric mode for this launch only (0 = speed, 100 = stealth).
    #[arg(long, value_parser = value_parser!(u8).range(0..=100))]
    pub mode: Option<u8>,
    /// Override the preferred carrier for this launch only.
    #[arg(long, value_enum)]
    pub carrier: Option<CliCarrier>,
}

#[derive(Debug, Clone, Args)]
pub(crate) struct QaOptions {
    #[command(flatten)]
    pub launch: ClientLaunchArgs,
    /// Seconds to wait for the daemon-managed client session to establish the tunnel before failing.
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT_SECS)]
    pub connect_timeout_secs: u64,
    /// Number of ICMP echo requests to send for each tunnel ping probe.
    #[arg(long, default_value_t = DEFAULT_PING_COUNT)]
    pub ping_count: u8,
    /// Hostname to resolve during the DNS check.
    #[arg(long, default_value = DEFAULT_DNS_HOST)]
    pub dns_host: String,
    /// URL used for the public egress-IP check when full-tunnel routing is active.
    #[arg(long, default_value = DEFAULT_PUBLIC_IP_URL)]
    pub public_ip_url: String,
    /// Optional override URL for the throughput/speed test.
    #[arg(long)]
    pub speedtest_url: Option<String>,
    /// Byte target for the default download throughput test endpoint.
    #[arg(long, default_value_t = DEFAULT_SPEEDTEST_BYTES)]
    pub speedtest_bytes: usize,
    /// Timeout for the download throughput test.
    #[arg(long, default_value_t = DEFAULT_SPEEDTEST_TIMEOUT_SECS)]
    pub speedtest_timeout_secs: u64,
    /// Skip the DNS lookup test.
    #[arg(long, default_value_t = false)]
    pub skip_dns: bool,
    /// Skip the public egress-IP check.
    #[arg(long, default_value_t = false)]
    pub skip_public_ip: bool,
    /// Skip the download throughput test.
    #[arg(long, default_value_t = false)]
    pub skip_speedtest: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct TuiOptions {
    #[command(flatten)]
    pub launch: ClientLaunchArgs,
}

#[derive(Debug, Clone, Args, Default)]
pub(crate) struct ServiceArgs {
    /// Override the client root directory used by the installed daemon and local client files.
    #[arg(long)]
    pub root_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ServiceCommand {
    /// Install and start the privileged local client daemon.
    Install {
        #[command(flatten)]
        args: ServiceArgs,
    },
    /// Stop and uninstall the privileged local client daemon.
    Uninstall {
        #[command(flatten)]
        args: ServiceArgs,
    },
    /// Show whether the privileged local client daemon is installed and reachable.
    Status {
        #[command(flatten)]
        args: ServiceArgs,
    },
}

#[derive(Debug, Parser)]
#[command(
    name = "apt-client",
    about = "APT VPN client",
    long_about = "APT VPN client. Import a temporary bundle with `apt-client import`, connect through the local daemon with `apt-client up`, run targeted QA with `apt-client test`, or launch the terminal dashboard with `apt-client tui`."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Import a client bundle from a temporary host-provided import endpoint.
    Import {
        /// Temporary host:port displayed by `apt-edge add-client`.
        #[arg(long)]
        server: String,
        /// Temporary import key displayed by `apt-edge add-client`.
        #[arg(long)]
        key: String,
        /// Path where the imported bundle should be stored.
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
    /// Connect through the local privileged daemon and stay attached to its events.
    #[command(alias = "connect", alias = "start", alias = "run")]
    Up {
        #[command(flatten)]
        launch: ClientLaunchArgs,
    },
    /// Bring the tunnel up temporarily and run targeted QA checks.
    Test {
        #[command(flatten)]
        options: QaOptions,
    },
    /// Launch the terminal dashboard wrapper for the local client daemon.
    Tui {
        #[command(flatten)]
        options: TuiOptions,
    },
    /// Install, uninstall, or inspect the privileged local client daemon service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Advanced: generate only a standalone client identity.
    #[command(hide = true)]
    GenIdentity {
        #[arg(long)]
        out_dir: PathBuf,
    },
}
