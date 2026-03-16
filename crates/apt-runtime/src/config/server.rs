use super::*;
use crate::quic::{load_certificate_chain, load_private_key};
use apt_origin::{OriginFamilyProfile, PublicSessionTransport};

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
    pub authority: String,
    pub certificate: String,
    pub private_key: String,
    #[serde(default)]
    pub deployment_strength: V2DeploymentStrength,
    #[serde(default, alias = "runtime_mode")]
    pub mode: Mode,
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
        if config.authority.trim().is_empty() {
            config.authority = derive_authority_from_public_endpoint(&config.public_endpoint)?;
        }
        maybe_upgrade_toml_file(path, &raw, &config)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve_file_spec_relative_to_base(&mut config.certificate, base);
        resolve_file_spec_relative_to_base(&mut config.private_key, base);
        resolve_file_spec_relative_to_base(&mut config.admission_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_private_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_public_key, base);
        resolve_file_spec_relative_to_base(&mut config.cookie_key, base);
        resolve_file_spec_relative_to_base(&mut config.ticket_key, base);
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
        let peers = self
            .peers
            .iter()
            .map(ResolvedAuthorizedPeer::from_config)
            .collect::<Result<Vec<_>, _>>()?;
        validate_peer_assignments(self, &peers)?;
        let _ = load_certificate_chain(&self.certificate)?;
        let _ = load_private_key(&self.private_key)?;
        let surface_plan = V2ServerSurfaceConfig {
            authority: self.authority.clone(),
            bind: self.bind,
            public_endpoint: self.public_endpoint.clone(),
            trust: V2SurfaceTrustConfig::default(),
            cover_family: OriginFamilyProfile::api_sync().display_name,
            profile_version: OriginFamilyProfile::api_sync().profile_version,
            deployment_strength: self.deployment_strength,
            origin_backend: None,
        }
        .to_surface_plan(PublicSessionTransport::S1H2)
        .map_err(v2_origin_plan_error)?;
        Ok(ResolvedServerConfig {
            bind: self.bind,
            public_endpoint: self.public_endpoint.clone(),
            authority: self.authority.clone(),
            certificate_spec: self.certificate.clone(),
            private_key_spec: self.private_key.clone(),
            surface_plan,
            mode: self.mode,
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
            session_policy: self.session_policy.clone(),
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
pub struct ResolvedServerConfig {
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub authority: String,
    pub certificate_spec: String,
    pub private_key_spec: String,
    pub surface_plan: V2ServerSurfacePlan,
    pub mode: Mode,
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

fn derive_authority_from_public_endpoint(endpoint: &str) -> Result<String, RuntimeError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::InvalidConfig(
            "public_endpoint cannot be empty".to_string(),
        ));
    }
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        return Ok(socket_addr.ip().to_string());
    }
    trimmed
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches('[').trim_matches(']').to_string())
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| {
            RuntimeError::InvalidConfig(format!(
                "unable to derive H2 authority from public_endpoint `{trimmed}`"
            ))
        })
}

fn v2_origin_plan_error(error: V2OriginPlanError) -> RuntimeError {
    RuntimeError::InvalidConfig(format!("invalid H2 surface plan: {error:?}"))
}
