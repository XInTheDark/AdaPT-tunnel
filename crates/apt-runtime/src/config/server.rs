use super::*;
use crate::quic::{derive_d2_public_endpoint, load_certificate_chain, load_private_key};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedPeerConfig {
    pub name: String,
    #[serde(default = "default_auth_profile")]
    pub auth_profile: AuthProfile,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub admission_key: Option<String>,
    pub client_static_public_key: String,
    pub tunnel_ipv4: Ipv4Addr,
    #[serde(default)]
    pub tunnel_ipv6: Option<Ipv6Addr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub public_endpoint: String,
    #[serde(default)]
    pub runtime_mode: RuntimeMode,
    #[serde(default)]
    pub d2_bind: Option<SocketAddr>,
    #[serde(default)]
    pub d2_public_endpoint: Option<String>,
    #[serde(default)]
    pub d2_certificate: Option<String>,
    #[serde(default)]
    pub d2_private_key: Option<String>,
    #[serde(default)]
    pub stream_bind: Option<SocketAddr>,
    #[serde(default)]
    pub stream_public_endpoint: Option<String>,
    #[serde(default)]
    pub stream_decoy_surface: bool,
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
    #[serde(default)]
    pub tunnel_local_ipv6: Option<Ipv6Addr>,
    #[serde(default)]
    pub tunnel_ipv6_prefix_len: Option<u8>,
    #[serde(default = "default_tunnel_mtu")]
    pub tunnel_mtu: u16,
    #[serde(default)]
    pub egress_interface: Option<String>,
    #[serde(default)]
    pub enable_ipv4_forwarding: bool,
    #[serde(default)]
    pub nat_ipv4: bool,
    #[serde(default)]
    pub enable_ipv6_forwarding: bool,
    #[serde(default)]
    pub nat_ipv6: bool,
    #[serde(default)]
    pub push_routes: Vec<IpNet>,
    #[serde(default)]
    pub push_dns: Vec<IpAddr>,
    #[serde(default)]
    pub session_policy: SessionPolicy,
    #[serde(default = "default_allow_session_migration")]
    pub allow_session_migration: bool,
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
        maybe_upgrade_toml_file(path, &raw, &config)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve_file_spec_relative_to_base(&mut config.admission_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_private_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_public_key, base);
        resolve_file_spec_relative_to_base(&mut config.cookie_key, base);
        resolve_file_spec_relative_to_base(&mut config.ticket_key, base);
        if let Some(d2_certificate) = &mut config.d2_certificate {
            resolve_file_spec_relative_to_base(d2_certificate, base);
        }
        if let Some(d2_private_key) = &mut config.d2_private_key {
            resolve_file_spec_relative_to_base(d2_private_key, base);
        }
        for peer in &mut config.peers {
            if let Some(admission_key) = &mut peer.admission_key {
                resolve_file_spec_relative_to_base(admission_key, base);
            }
            resolve_file_spec_relative_to_base(&mut peer.client_static_public_key, base);
        }
        Ok(config)
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), RuntimeError> {
        store_toml(path.as_ref(), self)
    }

    pub fn resolve(&self) -> Result<ResolvedServerConfig, RuntimeError> {
        if self.session_policy.allow_hybrid_pq {
            return Err(RuntimeError::InvalidConfig(
                "allow_hybrid_pq is not supported yet in the live runtime".to_string(),
            ));
        }
        validate_ipv6_config(self)?;
        let mut session_policy = self.session_policy.clone();
        self.runtime_mode.apply_to(&mut session_policy);
        let peers = self
            .peers
            .iter()
            .map(ResolvedAuthorizedPeer::from_config)
            .collect::<Result<Vec<_>, _>>()?;
        validate_peer_assignments(self, &peers)?;
        Ok(ResolvedServerConfig {
            bind: self.bind,
            public_endpoint: self.public_endpoint.clone(),
            runtime_mode: self.runtime_mode,
            d2: resolve_server_d2_config(self)?,
            stream_bind: self.stream_bind.or(Some(self.bind)),
            stream_public_endpoint: self
                .stream_public_endpoint
                .clone()
                .or_else(|| Some(self.public_endpoint.clone())),
            stream_decoy_surface: self.stream_decoy_surface,
            endpoint_id: EndpointId::new(self.endpoint_id.clone()),
            admission_key: load_key32(&self.admission_key)?,
            server_static_private_key: load_key32(&self.server_static_private_key)?,
            server_static_public_key: load_key32(&self.server_static_public_key)?,
            cookie_key: load_key32(&self.cookie_key)?,
            ticket_key: load_key32(&self.ticket_key)?,
            interface_name: self.interface_name.clone(),
            tunnel_local_ipv4: self.tunnel_local_ipv4,
            tunnel_netmask: self.tunnel_netmask,
            tunnel_local_ipv6: self.tunnel_local_ipv6,
            tunnel_ipv6_prefix_len: self.tunnel_ipv6_prefix_len,
            tunnel_mtu: self.tunnel_mtu,
            egress_interface: self.egress_interface.clone(),
            enable_ipv4_forwarding: self.enable_ipv4_forwarding,
            nat_ipv4: self.nat_ipv4,
            enable_ipv6_forwarding: self.enable_ipv6_forwarding,
            nat_ipv6: self.nat_ipv6,
            push_routes: self.push_routes.clone(),
            push_dns: self.push_dns.clone(),
            session_policy,
            allow_session_migration: self.allow_session_migration,
            keepalive_secs: self.keepalive_secs,
            session_idle_timeout_secs: self.session_idle_timeout_secs,
            udp_recv_buffer_bytes: self.udp_recv_buffer_bytes,
            udp_send_buffer_bytes: self.udp_send_buffer_bytes,
            peers,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAuthorizedPeer {
    pub name: String,
    pub auth_profile: AuthProfile,
    pub user_id: String,
    pub admission_key: Option<[u8; 32]>,
    pub client_static_public_key: [u8; 32],
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_ipv6: Option<Ipv6Addr>,
}

impl ResolvedAuthorizedPeer {
    fn from_config(config: &AuthorizedPeerConfig) -> Result<Self, RuntimeError> {
        if matches!(config.auth_profile, AuthProfile::PerUser) && config.admission_key.is_none() {
            return Err(RuntimeError::InvalidConfig(format!(
                "peer `{}` uses per-user admission but has no admission_key configured",
                config.name
            )));
        }
        Ok(Self {
            name: config.name.clone(),
            auth_profile: config.auth_profile,
            user_id: config
                .user_id
                .clone()
                .unwrap_or_else(|| config.name.clone()),
            admission_key: config
                .admission_key
                .as_deref()
                .map(load_key32)
                .transpose()?,
            client_static_public_key: load_key32(&config.client_static_public_key)?,
            tunnel_ipv4: config.tunnel_ipv4,
            tunnel_ipv6: config.tunnel_ipv6,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedServerD2Config {
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub certificate_spec: String,
    pub private_key_spec: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedServerConfig {
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub runtime_mode: RuntimeMode,
    pub d2: Option<ResolvedServerD2Config>,
    pub stream_bind: Option<SocketAddr>,
    pub stream_public_endpoint: Option<String>,
    pub stream_decoy_surface: bool,
    pub endpoint_id: EndpointId,
    pub admission_key: [u8; 32],
    pub server_static_private_key: [u8; 32],
    pub server_static_public_key: [u8; 32],
    pub cookie_key: [u8; 32],
    pub ticket_key: [u8; 32],
    pub interface_name: Option<String>,
    pub tunnel_local_ipv4: Ipv4Addr,
    pub tunnel_netmask: Ipv4Addr,
    pub tunnel_local_ipv6: Option<Ipv6Addr>,
    pub tunnel_ipv6_prefix_len: Option<u8>,
    pub tunnel_mtu: u16,
    pub egress_interface: Option<String>,
    pub enable_ipv4_forwarding: bool,
    pub nat_ipv4: bool,
    pub enable_ipv6_forwarding: bool,
    pub nat_ipv6: bool,
    pub push_routes: Vec<IpNet>,
    pub push_dns: Vec<IpAddr>,
    pub session_policy: SessionPolicy,
    pub allow_session_migration: bool,
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
    pub client_ipv6: Option<Ipv6Addr>,
    pub server_ipv6: Option<Ipv6Addr>,
    pub ipv6_prefix_len: Option<u8>,
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerSessionExtension {
    TunnelParameters(SessionTransportParameters),
}

fn resolve_server_d2_config(
    config: &ServerConfig,
) -> Result<Option<ResolvedServerD2Config>, RuntimeError> {
    let any_present = config.d2_bind.is_some()
        || config.d2_public_endpoint.is_some()
        || config.d2_certificate.is_some()
        || config.d2_private_key.is_some();
    if !any_present {
        return Ok(None);
    }

    let Some(bind) = config.d2_bind else {
        return Err(RuntimeError::InvalidConfig(
            "D2 is partially configured, but d2_bind is missing".to_string(),
        ));
    };
    let public_endpoint = match &config.d2_public_endpoint {
        Some(value) => value.clone(),
        None => derive_d2_public_endpoint(&config.public_endpoint).ok_or_else(|| {
            RuntimeError::InvalidConfig(
                "D2 is configured, but d2_public_endpoint could not be derived".to_string(),
            )
        })?,
    };
    let certificate_spec = config.d2_certificate.clone().ok_or_else(|| {
        RuntimeError::InvalidConfig("D2 is configured, but d2_certificate is missing".to_string())
    })?;
    let private_key_spec = config.d2_private_key.clone().ok_or_else(|| {
        RuntimeError::InvalidConfig("D2 is configured, but d2_private_key is missing".to_string())
    })?;

    let _ = load_certificate_chain(&certificate_spec)?;
    let _ = load_private_key(&private_key_spec)?;

    Ok(Some(ResolvedServerD2Config {
        bind,
        public_endpoint,
        certificate_spec,
        private_key_spec,
    }))
}

fn validate_ipv6_config(config: &ServerConfig) -> Result<(), RuntimeError> {
    if config.tunnel_local_ipv6.is_some() != config.tunnel_ipv6_prefix_len.is_some() {
        return Err(RuntimeError::InvalidConfig(
            "IPv6 tunnel settings require both tunnel_local_ipv6 and tunnel_ipv6_prefix_len"
                .to_string(),
        ));
    }
    if let Some(prefix_len) = config.tunnel_ipv6_prefix_len {
        if prefix_len > 128 {
            return Err(RuntimeError::InvalidConfig(
                "tunnel_ipv6_prefix_len must be between 0 and 128".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_peer_assignments(
    config: &ServerConfig,
    peers: &[ResolvedAuthorizedPeer],
) -> Result<(), RuntimeError> {
    let mut tunnel_ipv4 = std::collections::HashSet::new();
    let mut tunnel_ipv6 = std::collections::HashSet::new();
    for peer in peers {
        if !tunnel_ipv4.insert(peer.tunnel_ipv4) {
            return Err(RuntimeError::InvalidConfig(format!(
                "duplicate tunnel_ipv4 assignment detected for peer `{}`",
                peer.name
            )));
        }
        if let Some(ipv6) = peer.tunnel_ipv6 {
            if config.tunnel_local_ipv6.is_none() || config.tunnel_ipv6_prefix_len.is_none() {
                return Err(RuntimeError::InvalidConfig(format!(
                    "peer `{}` has tunnel_ipv6 configured, but the server IPv6 tunnel is not enabled",
                    peer.name
                )));
            }
            if !tunnel_ipv6.insert(ipv6) {
                return Err(RuntimeError::InvalidConfig(format!(
                    "duplicate tunnel_ipv6 assignment detected for peer `{}`",
                    peer.name
                )));
            }
        }
    }
    Ok(())
}
