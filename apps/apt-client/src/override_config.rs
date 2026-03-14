use apt_bundle::client_bundle_override_path;
use apt_runtime::{ClientConfig, RuntimeCarrierPreference, RuntimeMode, SessionPolicy};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tracing::warn;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(super) struct ClientOverrideConfig {
    pub server_addr: Option<String>,
    pub runtime_mode: Option<RuntimeMode>,
    pub preferred_carrier: Option<RuntimeCarrierPreference>,
    pub bind: Option<SocketAddr>,
    pub interface_name: Option<String>,
    pub routes: Option<Vec<IpNet>>,
    pub use_server_pushed_routes: Option<bool>,
    pub session_policy: Option<SessionPolicy>,
    pub enable_s1_fallback: Option<bool>,
    pub stream_server_addr: Option<String>,
    pub allow_session_migration: Option<bool>,
    pub standby_health_check_secs: Option<u64>,
    pub keepalive_secs: Option<u64>,
    pub session_idle_timeout_secs: Option<u64>,
    pub handshake_timeout_secs: Option<u64>,
    pub handshake_retries: Option<u8>,
    pub udp_recv_buffer_bytes: Option<usize>,
    pub udp_send_buffer_bytes: Option<usize>,
    pub state_path: Option<PathBuf>,
}

pub(super) fn apply_optional_client_override(
    config: &mut ClientConfig,
    bundle_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let override_path = client_bundle_override_path(bundle_path);
    if let Err(error) = ensure_blank_override_file(&override_path) {
        warn!(
            error = %error,
            path = %override_path.display(),
            "failed to create blank client override file"
        );
    }
    if !override_path.exists() {
        return Ok(override_path);
    }
    let override_config = load_override_file(&override_path)?;
    override_config.apply_to(config, &override_path);
    Ok(override_path)
}

fn ensure_blank_override_file(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, b"")
}

fn load_override_file(path: &Path) -> Result<ClientOverrideConfig, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(ClientOverrideConfig::default());
    }
    Ok(toml::from_str(&raw)?)
}

impl ClientOverrideConfig {
    fn apply_to(&self, config: &mut ClientConfig, override_path: &Path) {
        let base = override_path.parent().unwrap_or_else(|| Path::new("."));
        if let Some(server_addr) = self.server_addr.as_ref().map(|value| value.trim()) {
            if !server_addr.is_empty() {
                config.server_addr = server_addr.to_string();
            }
        }
        if let Some(runtime_mode) = self.runtime_mode {
            config.runtime_mode = runtime_mode;
        }
        if let Some(preferred_carrier) = self.preferred_carrier {
            config.preferred_carrier = preferred_carrier;
        }
        if let Some(bind) = self.bind {
            config.bind = bind;
        }
        if let Some(interface_name) = self.interface_name.as_ref() {
            config.interface_name = normalized_optional_string(interface_name);
        }
        if let Some(routes) = self.routes.as_ref() {
            config.routes = routes.clone();
        }
        if let Some(use_server_pushed_routes) = self.use_server_pushed_routes {
            config.use_server_pushed_routes = use_server_pushed_routes;
        }
        if let Some(session_policy) = self.session_policy.as_ref() {
            config.session_policy = session_policy.clone();
        }
        if let Some(enable_s1_fallback) = self.enable_s1_fallback {
            config.enable_s1_fallback = enable_s1_fallback;
        }
        if let Some(stream_server_addr) = self.stream_server_addr.as_ref() {
            config.stream_server_addr = normalized_optional_string(stream_server_addr);
        }
        if let Some(allow_session_migration) = self.allow_session_migration {
            config.allow_session_migration = allow_session_migration;
        }
        if let Some(standby_health_check_secs) = self.standby_health_check_secs {
            config.standby_health_check_secs = standby_health_check_secs;
        }
        if let Some(keepalive_secs) = self.keepalive_secs {
            config.keepalive_secs = keepalive_secs;
        }
        if let Some(session_idle_timeout_secs) = self.session_idle_timeout_secs {
            config.session_idle_timeout_secs = session_idle_timeout_secs;
        }
        if let Some(handshake_timeout_secs) = self.handshake_timeout_secs {
            config.handshake_timeout_secs = handshake_timeout_secs;
        }
        if let Some(handshake_retries) = self.handshake_retries {
            config.handshake_retries = handshake_retries;
        }
        if let Some(udp_recv_buffer_bytes) = self.udp_recv_buffer_bytes {
            config.udp_recv_buffer_bytes = udp_recv_buffer_bytes;
        }
        if let Some(udp_send_buffer_bytes) = self.udp_send_buffer_bytes {
            config.udp_send_buffer_bytes = udp_send_buffer_bytes;
        }
        if let Some(state_path) = self.state_path.as_ref() {
            config.state_path = if state_path.is_relative() {
                base.join(state_path)
            } else {
                state_path.clone()
            };
        }
    }
}

fn normalized_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_runtime::SessionPolicy;
    use apt_types::AuthProfile;
    use std::{net::SocketAddr, str::FromStr};

    fn test_config() -> ClientConfig {
        ClientConfig {
            server_addr: "198.51.100.10:51820".to_string(),
            runtime_mode: RuntimeMode::Stealth,
            preferred_carrier: RuntimeCarrierPreference::D1,
            auth_profile: AuthProfile::PerUser,
            endpoint_id: "adapt-demo".to_string(),
            admission_key: "11".repeat(32),
            server_static_public_key: "22".repeat(32),
            client_static_private_key: "33".repeat(32),
            client_identity: Some("laptop".to_string()),
            bind: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            interface_name: None,
            routes: Vec::new(),
            use_server_pushed_routes: true,
            session_policy: SessionPolicy::default(),
            enable_s1_fallback: true,
            stream_server_addr: Some("198.51.100.10:443".to_string()),
            allow_session_migration: true,
            standby_health_check_secs: 0,
            keepalive_secs: 25,
            session_idle_timeout_secs: 180,
            handshake_timeout_secs: 5,
            handshake_retries: 5,
            udp_recv_buffer_bytes: 4 * 1024 * 1024,
            udp_send_buffer_bytes: 4 * 1024 * 1024,
            state_path: PathBuf::from("/var/lib/adapt/client-state.toml"),
        }
    }

    #[test]
    fn empty_override_string_clears_optional_fields() {
        let mut config = test_config();
        ClientOverrideConfig {
            interface_name: Some("   ".to_string()),
            stream_server_addr: Some(String::new()),
            ..ClientOverrideConfig::default()
        }
        .apply_to(&mut config, Path::new("/etc/adapt/client.override.toml"));
        assert_eq!(config.interface_name, None);
        assert_eq!(config.stream_server_addr, None);
    }

    #[test]
    fn relative_state_path_is_resolved_from_override_file() {
        let mut config = test_config();
        ClientOverrideConfig {
            state_path: Some(PathBuf::from("profiles/client-state.toml")),
            ..ClientOverrideConfig::default()
        }
        .apply_to(&mut config, Path::new("/etc/adapt/client.override.toml"));
        assert_eq!(
            config.state_path,
            PathBuf::from("/etc/adapt/profiles/client-state.toml")
        );
    }

    #[test]
    fn explicit_override_fields_replace_bundle_defaults() {
        let mut config = test_config();
        ClientOverrideConfig {
            runtime_mode: Some(RuntimeMode::Balanced),
            preferred_carrier: Some(RuntimeCarrierPreference::S1),
            server_addr: Some("203.0.113.5:443".to_string()),
            routes: Some(vec!["10.0.0.0/8".parse().unwrap()]),
            use_server_pushed_routes: Some(false),
            ..ClientOverrideConfig::default()
        }
        .apply_to(&mut config, Path::new("/etc/adapt/client.override.toml"));
        assert_eq!(config.runtime_mode, RuntimeMode::Balanced);
        assert_eq!(config.preferred_carrier, RuntimeCarrierPreference::S1);
        assert_eq!(config.server_addr, "203.0.113.5:443");
        assert_eq!(config.routes, vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(!config.use_server_pushed_routes);
    }
}
