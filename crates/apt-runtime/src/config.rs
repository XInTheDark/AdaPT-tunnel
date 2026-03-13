use crate::{error::RuntimeError, status::RuntimeStatus};
use apt_types::EndpointId;
use base64::Engine as _;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    pub endpoint_id: String,
    pub admission_key: String,
    pub server_static_public_key: String,
    pub client_static_private_key: String,
    #[serde(default)]
    pub client_identity: Option<String>,
    #[serde(default = "default_client_bind")]
    pub bind: SocketAddr,
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub routes: Vec<IpNet>,
    #[serde(default)]
    pub use_server_pushed_routes: bool,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_handshake_retries")]
    pub handshake_retries: u8,
    #[serde(default = "default_udp_recv_buffer_bytes")]
    pub udp_recv_buffer_bytes: usize,
    #[serde(default = "default_udp_send_buffer_bytes")]
    pub udp_send_buffer_bytes: usize,
    #[serde(default = "default_state_path")]
    pub state_path: PathBuf,
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| RuntimeError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: Self = toml::from_str(&raw)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.state_path.is_relative() {
            config.state_path = base.join(&config.state_path);
        }
        resolve_file_spec_relative_to_base(&mut config.admission_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_public_key, base);
        resolve_file_spec_relative_to_base(&mut config.client_static_private_key, base);
        Ok(config)
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), RuntimeError> {
        store_toml(path.as_ref(), self)
    }

    pub fn resolve(&self) -> Result<ResolvedClientConfig, RuntimeError> {
        Ok(ResolvedClientConfig {
            server_addr: resolve_socket_addr(&self.server_addr)?,
            endpoint_id: EndpointId::new(self.endpoint_id.clone()),
            admission_key: load_key32(&self.admission_key)?,
            server_static_public_key: load_key32(&self.server_static_public_key)?,
            client_static_private_key: load_key32(&self.client_static_private_key)?,
            client_identity: self.client_identity.clone(),
            bind: self.bind,
            interface_name: self.interface_name.clone(),
            routes: self.routes.clone(),
            use_server_pushed_routes: self.use_server_pushed_routes,
            keepalive_secs: self.keepalive_secs,
            session_idle_timeout_secs: self.session_idle_timeout_secs,
            handshake_timeout_secs: self.handshake_timeout_secs,
            handshake_retries: self.handshake_retries,
            udp_recv_buffer_bytes: self.udp_recv_buffer_bytes,
            udp_send_buffer_bytes: self.udp_send_buffer_bytes,
            state_path: self.state_path.clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedPeerConfig {
    pub name: String,
    pub client_static_public_key: String,
    pub tunnel_ipv4: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub endpoint_id: String,
    pub admission_key: String,
    pub server_static_private_key: String,
    pub server_static_public_key: String,
    pub cookie_key: String,
    pub ticket_key: String,
    #[serde(default)]
    pub interface_name: Option<String>,
    pub tunnel_local_ipv4: Ipv4Addr,
    pub tunnel_netmask: Ipv4Addr,
    #[serde(default = "default_tunnel_mtu")]
    pub tunnel_mtu: u16,
    #[serde(default)]
    pub egress_interface: Option<String>,
    #[serde(default)]
    pub enable_ipv4_forwarding: bool,
    #[serde(default)]
    pub nat_ipv4: bool,
    #[serde(default)]
    pub push_routes: Vec<IpNet>,
    #[serde(default)]
    pub push_dns: Vec<IpAddr>,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,
    #[serde(default = "default_udp_recv_buffer_bytes")]
    pub udp_recv_buffer_bytes: usize,
    #[serde(default = "default_udp_send_buffer_bytes")]
    pub udp_send_buffer_bytes: usize,
    #[serde(default)]
    pub peers: Vec<AuthorizedPeerConfig>,
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| RuntimeError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: Self = toml::from_str(&raw)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve_file_spec_relative_to_base(&mut config.admission_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_private_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_public_key, base);
        resolve_file_spec_relative_to_base(&mut config.cookie_key, base);
        resolve_file_spec_relative_to_base(&mut config.ticket_key, base);
        for peer in &mut config.peers {
            resolve_file_spec_relative_to_base(&mut peer.client_static_public_key, base);
        }
        Ok(config)
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), RuntimeError> {
        store_toml(path.as_ref(), self)
    }

    pub fn resolve(&self) -> Result<ResolvedServerConfig, RuntimeError> {
        Ok(ResolvedServerConfig {
            bind: self.bind,
            public_endpoint: self.public_endpoint.clone(),
            endpoint_id: EndpointId::new(self.endpoint_id.clone()),
            admission_key: load_key32(&self.admission_key)?,
            server_static_private_key: load_key32(&self.server_static_private_key)?,
            server_static_public_key: load_key32(&self.server_static_public_key)?,
            cookie_key: load_key32(&self.cookie_key)?,
            ticket_key: load_key32(&self.ticket_key)?,
            interface_name: self.interface_name.clone(),
            tunnel_local_ipv4: self.tunnel_local_ipv4,
            tunnel_netmask: self.tunnel_netmask,
            tunnel_mtu: self.tunnel_mtu,
            egress_interface: self.egress_interface.clone(),
            enable_ipv4_forwarding: self.enable_ipv4_forwarding,
            nat_ipv4: self.nat_ipv4,
            push_routes: self.push_routes.clone(),
            push_dns: self.push_dns.clone(),
            keepalive_secs: self.keepalive_secs,
            session_idle_timeout_secs: self.session_idle_timeout_secs,
            udp_recv_buffer_bytes: self.udp_recv_buffer_bytes,
            udp_send_buffer_bytes: self.udp_send_buffer_bytes,
            peers: self
                .peers
                .iter()
                .map(ResolvedAuthorizedPeer::from_config)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedClientConfig {
    pub server_addr: SocketAddr,
    pub endpoint_id: EndpointId,
    pub admission_key: [u8; 32],
    pub server_static_public_key: [u8; 32],
    pub client_static_private_key: [u8; 32],
    pub client_identity: Option<String>,
    pub bind: SocketAddr,
    pub interface_name: Option<String>,
    pub routes: Vec<IpNet>,
    pub use_server_pushed_routes: bool,
    pub keepalive_secs: u64,
    pub session_idle_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub handshake_retries: u8,
    pub udp_recv_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub state_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAuthorizedPeer {
    pub name: String,
    pub client_static_public_key: [u8; 32],
    pub tunnel_ipv4: Ipv4Addr,
}

impl ResolvedAuthorizedPeer {
    fn from_config(config: &AuthorizedPeerConfig) -> Result<Self, RuntimeError> {
        Ok(Self {
            name: config.name.clone(),
            client_static_public_key: load_key32(&config.client_static_public_key)?,
            tunnel_ipv4: config.tunnel_ipv4,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedServerConfig {
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub endpoint_id: EndpointId,
    pub admission_key: [u8; 32],
    pub server_static_private_key: [u8; 32],
    pub server_static_public_key: [u8; 32],
    pub cookie_key: [u8; 32],
    pub ticket_key: [u8; 32],
    pub interface_name: Option<String>,
    pub tunnel_local_ipv4: Ipv4Addr,
    pub tunnel_netmask: Ipv4Addr,
    pub tunnel_mtu: u16,
    pub egress_interface: Option<String>,
    pub enable_ipv4_forwarding: bool,
    pub nat_ipv4: bool,
    pub push_routes: Vec<IpNet>,
    pub push_dns: Vec<IpAddr>,
    pub keepalive_secs: u64,
    pub session_idle_timeout_secs: u64,
    pub udp_recv_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub peers: Vec<ResolvedAuthorizedPeer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTransportParameters {
    pub client_ipv4: Ipv4Addr,
    pub server_ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerSessionExtension {
    TunnelParameters(SessionTransportParameters),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientPersistentState {
    pub last_status: Option<RuntimeStatus>,
    pub resume_ticket: Option<Vec<u8>>,
}

impl ClientPersistentState {
    pub fn load(path: &Path) -> Result<Self, RuntimeError> {
        match fs::read_to_string(path) {
            Ok(raw) => Ok(toml::from_str(&raw)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(RuntimeError::IoWithPath {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    pub fn store(&self, path: &Path) -> Result<(), RuntimeError> {
        let serialized = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| RuntimeError::IoWithPath {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(path, serialized).map_err(|source| RuntimeError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

pub fn load_key32(spec: &str) -> Result<[u8; 32], RuntimeError> {
    let resolved = if let Some(path) = spec.strip_prefix("file:") {
        fs::read_to_string(path).map_err(|source| RuntimeError::IoWithPath {
            path: PathBuf::from(path),
            source,
        })?
    } else {
        spec.to_string()
    };

    let trimmed = resolved.trim();
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|value| value.is_ascii_hexdigit()) {
        decode_hex(trimmed)?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|_| RuntimeError::InvalidKeyMaterial("key must be 64 hex chars or base64".to_string()))?
    };
    bytes
        .try_into()
        .map_err(|_| RuntimeError::InvalidKeyMaterial("key material must decode to 32 bytes".to_string()))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, RuntimeError> {
    let mut output = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = decode_nibble(bytes[index])?;
        let lo = decode_nibble(bytes[index + 1])?;
        output.push((hi << 4) | lo);
        index += 2;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, RuntimeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RuntimeError::InvalidKeyMaterial("invalid hex digit in key material".to_string())),
    }
}

pub fn encode_key_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn store_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), RuntimeError> {
    let serialized = toml::to_string_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RuntimeError::IoWithPath {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(path, serialized).map_err(|source| RuntimeError::IoWithPath {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn resolve_file_spec_relative_to_base(spec: &mut String, base: &Path) {
    if let Some(path) = spec.strip_prefix("file:") {
        let path = Path::new(path);
        if path.is_relative() {
            *spec = format!("file:{}", base.join(path).display());
        }
    }
}

fn resolve_socket_addr(spec: &str) -> Result<SocketAddr, RuntimeError> {
    if let Ok(parsed) = spec.parse() {
        return Ok(parsed);
    }
    spec.to_socket_addrs()
        .map_err(|source| RuntimeError::InvalidConfig(format!("unable to resolve {spec}: {source}")))?
        .next()
        .ok_or_else(|| RuntimeError::InvalidConfig(format!("no socket addresses resolved for {spec}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    #[test]
    fn key_material_loads_from_hex() {
        let value = "11".repeat(32);
        let bytes = load_key32(&value).unwrap();
        assert_eq!(bytes, [0x11; 32]);
    }

    #[test]
    fn key_material_loads_from_file() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("adapt-key-{unique}.txt"));
        fs::write(&path, "22".repeat(32)).unwrap();
        let bytes = load_key32(&format!("file:{}", path.display())).unwrap();
        assert_eq!(bytes, [0x22; 32]);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_load_resolves_relative_key_paths() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("adapt-client-config-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("shared-admission.key"), "11".repeat(32)).unwrap();
        fs::write(dir.join("server-static-public.key"), "22".repeat(32)).unwrap();
        fs::write(dir.join("client-static-private.key"), "33".repeat(32)).unwrap();
        fs::write(
            dir.join("client.toml"),
            r#"
server_addr = "198.51.100.10:51820"
endpoint_id = "adapt-demo"
admission_key = "file:./shared-admission.key"
server_static_public_key = "file:./server-static-public.key"
client_static_private_key = "file:./client-static-private.key"
"#,
        )
        .unwrap();
        let config = ClientConfig::load(dir.join("client.toml")).unwrap();
        assert!(config.admission_key.contains(dir.to_string_lossy().as_ref()));
        assert!(config.server_static_public_key.contains(dir.to_string_lossy().as_ref()));
        assert!(config.client_static_private_key.contains(dir.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn server_load_resolves_relative_key_paths() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("adapt-server-config-{unique}"));
        fs::create_dir_all(dir.join("clients")).unwrap();
        for file in [
            "shared-admission.key",
            "server-static-private.key",
            "server-static-public.key",
            "cookie.key",
            "ticket.key",
            "clients/laptop.client-static-public.key",
        ] {
            fs::write(dir.join(file), "44".repeat(32)).unwrap();
        }
        fs::write(
            dir.join("server.toml"),
            r#"
bind = "0.0.0.0:51820"
public_endpoint = "198.51.100.10:51820"
endpoint_id = "adapt-demo"
admission_key = "file:./shared-admission.key"
server_static_private_key = "file:./server-static-private.key"
server_static_public_key = "file:./server-static-public.key"
cookie_key = "file:./cookie.key"
ticket_key = "file:./ticket.key"
tunnel_local_ipv4 = "10.77.0.1"
tunnel_netmask = "255.255.255.0"

[[peers]]
name = "laptop"
client_static_public_key = "file:./clients/laptop.client-static-public.key"
tunnel_ipv4 = "10.77.0.2"
"#,
        )
        .unwrap();
        let config = ServerConfig::load(dir.join("server.toml")).unwrap();
        assert!(config.admission_key.contains(dir.to_string_lossy().as_ref()));
        assert!(config.peers[0]
            .client_static_public_key
            .contains(dir.to_string_lossy().as_ref()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn extension_round_trip() {
        let original = ServerSessionExtension::TunnelParameters(SessionTransportParameters {
            client_ipv4: Ipv4Addr::new(10, 77, 0, 2),
            server_ipv4: Ipv4Addr::new(10, 77, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1380,
            routes: vec!["0.0.0.0/0".parse().unwrap()],
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        });
        let encoded = bincode::serialize(&original).unwrap();
        let decoded: ServerSessionExtension = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn client_example_config_parses() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let raw = fs::read_to_string(root.join("docs/examples/client.example.toml")).unwrap();
        let parsed: ClientConfig = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.endpoint_id, "edge-prod-1");
    }

    #[test]
    fn server_example_config_parses() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let raw = fs::read_to_string(root.join("docs/examples/server.example.toml")).unwrap();
        let parsed: ServerConfig = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.endpoint_id, "edge-prod-1");
        assert_eq!(parsed.peers.len(), 1);
    }
}
