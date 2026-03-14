use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    #[serde(default)]
    pub runtime_mode: RuntimeMode,
    #[serde(default = "default_preferred_carrier")]
    pub preferred_carrier: RuntimeCarrierPreference,
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
    #[serde(default = "default_enable_s1_fallback")]
    pub enable_s1_fallback: bool,
    #[serde(default)]
    pub stream_server_addr: Option<String>,
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
        maybe_upgrade_toml_file(path, &raw, &config)?;
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
        let mut session_policy = self.session_policy.clone();
        self.runtime_mode.apply_to(&mut session_policy);
        Ok(ResolvedClientConfig {
            server_addr: resolve_socket_addr(&self.server_addr)?,
            runtime_mode: self.runtime_mode,
            preferred_carrier: self.preferred_carrier,
            strict_preferred_carrier: false,
            endpoint_id: EndpointId::new(self.endpoint_id.clone()),
            admission_key: load_key32(&self.admission_key)?,
            server_static_public_key: load_key32(&self.server_static_public_key)?,
            client_static_private_key: load_key32(&self.client_static_private_key)?,
            client_identity: self.client_identity.clone(),
            bind: self.bind,
            interface_name: self.interface_name.clone(),
            routes: self.routes.clone(),
            use_server_pushed_routes: self.use_server_pushed_routes,
            session_policy,
            enable_s1_fallback: self.enable_s1_fallback,
            stream_server_addr: self
                .stream_server_addr
                .as_deref()
                .map(resolve_socket_addr)
                .transpose()?,
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
    pub runtime_mode: RuntimeMode,
    pub preferred_carrier: RuntimeCarrierPreference,
    pub strict_preferred_carrier: bool,
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
    pub enable_s1_fallback: bool,
    pub stream_server_addr: Option<SocketAddr>,
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
