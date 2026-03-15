//! Shared local-control protocol and path helpers for the AdaPT client daemon.
#![allow(missing_docs)]

use apt_types::Mode;
use serde::{Deserialize, Serialize};
use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

pub const DEFAULT_CLIENT_ROOT_DIR_NAME: &str = ".adapt-tunnel";
pub const DEFAULT_CLIENT_BUNDLE_FILE_NAME: &str = "client.aptbundle";
pub const DEFAULT_CLIENT_SOCKET_FILE_NAME: &str = "clientd.sock";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientCarrier {
    Auto,
    D1,
    D2,
    S1,
}

impl ClientCarrier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::D1 => "d1",
            Self::D2 => "d2",
            Self::S1 => "s1",
        }
    }
}

impl Default for ClientCarrier {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientLaunchOptions {
    pub bundle_path: Option<PathBuf>,
    pub mode: Option<u8>,
    pub carrier: Option<ClientCarrier>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientDaemonLifecycle {
    Idle,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Error,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ClientSessionInfo {
    pub server: String,
    pub interface_name: String,
    pub carrier: String,
    pub negotiated_mode: u8,
    pub tunnel_ipv4: Option<Ipv4Addr>,
    pub tunnel_ipv6: Option<Ipv6Addr>,
    pub server_tunnel_ipv4: Option<Ipv4Addr>,
    pub server_tunnel_ipv6: Option<Ipv6Addr>,
    #[serde(default)]
    pub tunnel_addresses: Vec<IpAddr>,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientDaemonSnapshot {
    pub lifecycle: ClientDaemonLifecycle,
    pub selected_bundle_path: Option<PathBuf>,
    pub desired_mode: Option<u8>,
    pub desired_carrier: ClientCarrier,
    pub server: Option<String>,
    pub active_carrier: Option<String>,
    pub negotiated_mode: Option<u8>,
    pub interface_name: Option<String>,
    #[serde(default)]
    pub tunnel_addresses: Vec<IpAddr>,
    pub server_tunnel_ipv4: Option<Ipv4Addr>,
    pub server_tunnel_ipv6: Option<Ipv6Addr>,
    #[serde(default)]
    pub routes: Vec<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_rtt_ms: Option<f64>,
    pub reconnect_attempt: u32,
    pub reconnect_in_secs: Option<u64>,
    pub last_error: Option<String>,
    pub daemon_pid: Option<u32>,
}

impl Default for ClientDaemonSnapshot {
    fn default() -> Self {
        Self {
            lifecycle: ClientDaemonLifecycle::Idle,
            selected_bundle_path: None,
            desired_mode: Some(Mode::STEALTH.value()),
            desired_carrier: ClientCarrier::Auto,
            server: None,
            active_carrier: None,
            negotiated_mode: None,
            interface_name: None,
            tunnel_addresses: Vec::new(),
            server_tunnel_ipv4: None,
            server_tunnel_ipv6: None,
            routes: Vec::new(),
            tx_bytes: 0,
            rx_bytes: 0,
            last_rtt_ms: None,
            reconnect_attempt: 0,
            reconnect_in_secs: None,
            last_error: None,
            daemon_pid: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientLogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientDaemonEvent {
    Snapshot(ClientDaemonSnapshot),
    Log {
        level: ClientLogLevel,
        message: String,
    },
    SessionEstablished {
        session: ClientSessionInfo,
    },
    CarrierChanged {
        from: Option<String>,
        to: String,
    },
    ModeChanged {
        mode: u8,
    },
    StatsTick {
        tx_bytes: u64,
        rx_bytes: u64,
        last_rtt_ms: Option<f64>,
    },
    ReconnectScheduled {
        attempt: u32,
        in_secs: u64,
        reason: String,
    },
    Error {
        message: String,
        fatal: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientRuntimeEvent {
    Starting {
        server: String,
        requested_mode: u8,
        preferred_carrier: ClientCarrier,
    },
    SessionEstablished {
        session: ClientSessionInfo,
    },
    CarrierChanged {
        from: Option<String>,
        to: String,
    },
    ModeChanged {
        mode: u8,
    },
    StatsTick {
        tx_bytes: u64,
        rx_bytes: u64,
    },
    SessionEnded {
        reason: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientDaemonRequest {
    Connect { options: ClientLaunchOptions },
    Disconnect,
    ReconnectNow,
    SetMode { mode: u8 },
    SetCarrier { carrier: ClientCarrier },
    SetBundle { bundle_path: PathBuf },
    GetSnapshot,
    Subscribe,
    ListBundles,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientDaemonResponse {
    Ack {
        message: String,
        snapshot: ClientDaemonSnapshot,
    },
    Snapshot(ClientDaemonSnapshot),
    BundleList {
        bundles: Vec<PathBuf>,
        selected: Option<PathBuf>,
    },
    Error {
        message: String,
    },
    Subscribed {
        snapshot: ClientDaemonSnapshot,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientDaemonWireMessage {
    Response(ClientDaemonResponse),
    Event(ClientDaemonEvent),
}

pub fn default_client_root_dir() -> io::Result<PathBuf> {
    Ok(user_home_dir()?.join(DEFAULT_CLIENT_ROOT_DIR_NAME))
}

pub fn default_client_bundle_path() -> io::Result<PathBuf> {
    Ok(default_client_bundle_path_in(default_client_root_dir()?))
}

pub fn default_client_socket_path() -> io::Result<PathBuf> {
    Ok(default_client_socket_path_in(default_client_root_dir()?))
}

pub fn user_home_dir() -> io::Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))
}

pub fn ensure_client_root_dir() -> io::Result<PathBuf> {
    let root = default_client_root_dir()?;
    std::fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&root, permissions);
    }
    Ok(root)
}

pub fn list_user_bundle_paths() -> io::Result<Vec<PathBuf>> {
    list_bundle_paths_in(default_client_root_dir()?)
}

pub fn display_path(path: &Path) -> String {
    path.display().to_string()
}

pub fn default_client_bundle_path_in(root_dir: impl AsRef<Path>) -> PathBuf {
    root_dir.as_ref().join(DEFAULT_CLIENT_BUNDLE_FILE_NAME)
}

pub fn default_client_socket_path_in(root_dir: impl AsRef<Path>) -> PathBuf {
    root_dir.as_ref().join(DEFAULT_CLIENT_SOCKET_FILE_NAME)
}

pub fn list_bundle_paths_in(root_dir: impl AsRef<Path>) -> io::Result<Vec<PathBuf>> {
    let root = root_dir.as_ref();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut bundles = std::fs::read_dir(root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("aptbundle"))
        .collect::<Vec<_>>();
    bundles.sort();
    Ok(bundles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_strings_match_cli_values() {
        assert_eq!(ClientCarrier::Auto.as_str(), "auto");
        assert_eq!(ClientCarrier::D1.as_str(), "d1");
        assert_eq!(ClientCarrier::D2.as_str(), "d2");
        assert_eq!(ClientCarrier::S1.as_str(), "s1");
    }
}
