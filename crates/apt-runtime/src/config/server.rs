use super::*;

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
    #[serde(default)]
    pub runtime_mode: RuntimeMode,
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
        for peer in &mut config.peers {
            resolve_file_spec_relative_to_base(&mut peer.client_static_public_key, base);
        }
        Ok(config)
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), RuntimeError> {
        store_toml(path.as_ref(), self)
    }

    pub fn resolve(&self) -> Result<ResolvedServerConfig, RuntimeError> {
        let mut session_policy = self.session_policy.clone();
        self.runtime_mode.apply_to(&mut session_policy);
        Ok(ResolvedServerConfig {
            bind: self.bind,
            public_endpoint: self.public_endpoint.clone(),
            runtime_mode: self.runtime_mode,
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
            tunnel_mtu: self.tunnel_mtu,
            egress_interface: self.egress_interface.clone(),
            enable_ipv4_forwarding: self.enable_ipv4_forwarding,
            nat_ipv4: self.nat_ipv4,
            push_routes: self.push_routes.clone(),
            push_dns: self.push_dns.clone(),
            session_policy,
            allow_session_migration: self.allow_session_migration,
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
    pub runtime_mode: RuntimeMode,
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
    pub tunnel_mtu: u16,
    pub egress_interface: Option<String>,
    pub enable_ipv4_forwarding: bool,
    pub nat_ipv4: bool,
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
    pub mtu: u16,
    pub routes: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerSessionExtension {
    TunnelParameters(SessionTransportParameters),
}
