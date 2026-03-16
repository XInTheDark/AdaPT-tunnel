use super::*;
use crate::quic::load_certificate_chain;
use apt_origin::{OriginFamilyProfile, PublicSessionTransport};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    #[serde(default)]
    pub authority: String,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub server_roots: Option<String>,
    #[serde(default)]
    pub server_certificate: Option<String>,
    #[serde(default)]
    pub deployment_strength: V2DeploymentStrength,
    #[serde(default, alias = "runtime_mode")]
    pub mode: Mode,
    #[serde(default = "default_auth_profile")]
    pub auth_profile: AuthProfile,
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
    #[serde(default)]
    pub session_policy: SessionPolicy,
    #[serde(default = "default_allow_session_migration")]
    pub allow_session_migration: bool,
    #[serde(default = "default_standby_health_check_secs")]
    pub standby_health_check_secs: u64,
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
        if config.authority.trim().is_empty() {
            config.authority = derive_authority_from_endpoint(&config.server_addr)?;
        }
        maybe_upgrade_toml_file(path, &raw, &config)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.state_path.is_relative() {
            config.state_path = base.join(&config.state_path);
        }
        resolve_file_spec_relative_to_base(&mut config.admission_key, base);
        resolve_file_spec_relative_to_base(&mut config.server_static_public_key, base);
        resolve_file_spec_relative_to_base(&mut config.client_static_private_key, base);
        if let Some(server_roots) = &mut config.server_roots {
            resolve_file_spec_relative_to_base(server_roots, base);
        }
        if let Some(server_certificate) = &mut config.server_certificate {
            resolve_file_spec_relative_to_base(server_certificate, base);
        }
        Ok(config)
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), RuntimeError> {
        store_toml(path.as_ref(), self)
    }

    pub fn resolve(&self) -> Result<ResolvedClientConfig, RuntimeError> {
        if self.session_policy.allow_hybrid_pq {
            return Err(RuntimeError::InvalidConfig(
                "allow_hybrid_pq is not supported yet in the live runtime".to_string(),
            ));
        }
        if matches!(self.auth_profile, AuthProfile::PerUser)
            && self
                .client_identity
                .as_deref()
                .is_none_or(|identity| identity.trim().is_empty())
        {
            return Err(RuntimeError::InvalidConfig(
                "per-user client configs require client_identity to be set".to_string(),
            ));
        }
        if self.server_roots.is_none() && self.server_certificate.is_none() {
            return Err(RuntimeError::InvalidConfig(
                "client config requires server_certificate or server_roots for H2 TLS trust"
                    .to_string(),
            ));
        }
        if let Some(roots) = self.server_roots.as_deref() {
            let _ = load_certificate_chain(roots)?;
        }
        if let Some(certificate) = self.server_certificate.as_deref() {
            let _ = load_certificate_chain(certificate)?;
        }
        let server_addr = resolve_socket_addr(&self.server_addr)?;
        let surface_plan = V2ClientFamilyConfig {
            authority: self.authority.clone(),
            endpoint: self.server_addr.clone(),
            trust: V2SurfaceTrustConfig {
                server_name: self.server_name.clone(),
                roots: self.server_roots.clone(),
                pinned_certificate: self.server_certificate.clone(),
                pinned_spki: None,
            },
            cover_family: OriginFamilyProfile::api_sync().display_name,
            profile_version: OriginFamilyProfile::api_sync().profile_version,
            deployment_strength: self.deployment_strength,
        }
        .to_surface_plan(PublicSessionTransport::S1H2)
        .map_err(v2_origin_plan_error)?;
        Ok(ResolvedClientConfig {
            server_addr,
            authority: self.authority.clone(),
            surface_plan,
            mode: self.mode,
            auth_profile: self.auth_profile,
            endpoint_id: EndpointId::new(self.endpoint_id.clone()),
            admission_key: load_key32(&self.admission_key)?,
            server_static_public_key: load_key32(&self.server_static_public_key)?,
            client_static_private_key: load_key32(&self.client_static_private_key)?,
            client_identity: self.client_identity.clone(),
            bind: self.bind,
            interface_name: self.interface_name.clone(),
            routes: self.routes.clone(),
            use_server_pushed_routes: self.use_server_pushed_routes,
            session_policy: self.session_policy.clone(),
            allow_session_migration: self.allow_session_migration,
            standby_health_check_secs: self.standby_health_check_secs,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedClientConfig {
    pub server_addr: SocketAddr,
    pub authority: String,
    pub surface_plan: V2ClientSurfacePlan,
    pub mode: Mode,
    pub auth_profile: AuthProfile,
    pub endpoint_id: EndpointId,
    pub admission_key: [u8; 32],
    pub server_static_public_key: [u8; 32],
    pub client_static_private_key: [u8; 32],
    pub client_identity: Option<String>,
    pub bind: SocketAddr,
    pub interface_name: Option<String>,
    pub routes: Vec<IpNet>,
    pub use_server_pushed_routes: bool,
    pub session_policy: SessionPolicy,
    pub allow_session_migration: bool,
    pub standby_health_check_secs: u64,
    pub keepalive_secs: u64,
    pub session_idle_timeout_secs: u64,
    pub handshake_timeout_secs: u64,
    pub handshake_retries: u8,
    pub udp_recv_buffer_bytes: usize,
    pub udp_send_buffer_bytes: usize,
    pub state_path: PathBuf,
}

fn derive_authority_from_endpoint(endpoint: &str) -> Result<String, RuntimeError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::InvalidConfig(
            "server_addr cannot be empty".to_string(),
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
                "unable to derive H2 authority from server_addr `{trimmed}`"
            ))
        })
}

fn v2_origin_plan_error(error: V2OriginPlanError) -> RuntimeError {
    RuntimeError::InvalidConfig(format!("invalid H2 surface plan: {error:?}"))
}
