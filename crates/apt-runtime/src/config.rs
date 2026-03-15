use crate::{error::RuntimeError, status::RuntimeStatus};
use apt_persona::RememberedProfile;
use apt_policy::LocalNormalityProfile;
use apt_types::{
    AuthProfile, CarrierBinding, EndpointId, GatewayFingerprint, LinkType, LocalNetworkContext,
    Mode, PublicRouteHint, SessionPolicy,
};
use base64::Engine as _;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

mod client;
mod io;
mod server;
mod state;

#[cfg(test)]
mod tests;

use self::io::*;

pub(crate) use self::io::resolve_socket_addr;
pub use self::{
    client::{ClientConfig, ResolvedClientConfig, ResolvedClientD2Config, ResolvedRemoteEndpoint},
    io::{encode_key_hex, load_key32},
    server::{
        AuthorizedPeerConfig, ResolvedAuthorizedPeer, ResolvedServerConfig, ResolvedServerD2Config,
        ServerConfig, ServerSessionExtension, SessionTransportParameters,
    },
    state::{
        ClientPersistentState, PersistedIdleOutcomeSummary, PersistedKeepaliveLearningState,
        PersistedNetworkProfile,
    },
};

const DEFAULT_UDP_RECV_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_UDP_SEND_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_KEEPALIVE_SECS: u64 = 25;
const DEFAULT_SESSION_IDLE_TIMEOUT_SECS: u64 = 180;
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const DEFAULT_HANDSHAKE_RETRIES: u8 = 5;
const DEFAULT_TUNNEL_MTU: u16 = 1380;
const DEFAULT_STATE_PATH: &str = ".adapt-client-state.toml";

fn default_udp_recv_buffer_bytes() -> usize {
    DEFAULT_UDP_RECV_BUFFER_BYTES
}

fn default_udp_send_buffer_bytes() -> usize {
    DEFAULT_UDP_SEND_BUFFER_BYTES
}

fn default_keepalive_secs() -> u64 {
    DEFAULT_KEEPALIVE_SECS
}

fn default_session_idle_timeout_secs() -> u64 {
    DEFAULT_SESSION_IDLE_TIMEOUT_SECS
}

fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

fn default_handshake_retries() -> u8 {
    DEFAULT_HANDSHAKE_RETRIES
}

fn default_tunnel_mtu() -> u16 {
    DEFAULT_TUNNEL_MTU
}

fn default_client_bind() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

fn default_state_path() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_PATH)
}

fn default_enable_s1_fallback() -> bool {
    true
}

fn default_enable_d2_fallback() -> bool {
    false
}

fn default_allow_session_migration() -> bool {
    true
}

fn default_standby_health_check_secs() -> u64 {
    0
}

fn default_preferred_carrier() -> RuntimeCarrierPreference {
    RuntimeCarrierPreference::D1
}

fn default_auth_profile() -> AuthProfile {
    AuthProfile::SharedDeployment
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeCarrierPreference {
    Auto,
    #[default]
    D1,
    D2,
    S1,
}

impl RuntimeCarrierPreference {
    #[must_use]
    pub const fn binding(self) -> Option<CarrierBinding> {
        match self {
            Self::Auto => None,
            Self::D1 => Some(CarrierBinding::D1DatagramUdp),
            Self::D2 => Some(CarrierBinding::D2EncryptedDatagram),
            Self::S1 => Some(CarrierBinding::S1EncryptedStream),
        }
    }
}
