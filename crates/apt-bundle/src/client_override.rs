use crate::client_bundle_override_path;
use apt_runtime::{ClientConfig, Mode, SessionPolicy, V2DeploymentStrength};
use ipnet::IpNet;
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ClientOverrideConfig {
    pub server_addr: Option<String>,
    pub authority: Option<String>,
    pub server_name: Option<String>,
    pub server_roots: Option<String>,
    pub server_certificate: Option<String>,
    #[serde(alias = "runtime_mode")]
    pub mode: Option<Mode>,
    pub deployment_strength: Option<V2DeploymentStrength>,
    pub bind: Option<SocketAddr>,
    pub interface_name: Option<String>,
    pub routes: Option<Vec<IpNet>>,
    pub use_server_pushed_routes: Option<bool>,
    pub session_policy: Option<SessionPolicy>,
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

pub fn apply_optional_client_override(
    config: &mut ClientConfig,
    bundle_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let override_path = client_bundle_override_path(bundle_path);
    if !override_path.exists() {
        return Ok(override_path);
    }
    let override_config = load_override_file(&override_path)?;
    override_config.apply_to(config, &override_path);
    Ok(override_path)
}

pub fn ensure_client_override_file(bundle_path: &Path) -> std::io::Result<PathBuf> {
    let path = client_bundle_override_path(bundle_path);
    if path.exists() {
        return Ok(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, b"")?;
    Ok(path)
}

fn load_override_file(path: &Path) -> Result<ClientOverrideConfig, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(ClientOverrideConfig::default());
    }
    Ok(toml::from_str(&raw)?)
}

impl ClientOverrideConfig {
    pub fn apply_to(&self, config: &mut ClientConfig, override_path: &Path) {
        let base = override_path.parent().unwrap_or_else(|| Path::new("."));
        if let Some(server_addr) = self.server_addr.as_ref().map(|value| value.trim()) {
            if !server_addr.is_empty() {
                config.server_addr = server_addr.to_string();
            }
        }
        if let Some(authority) = self.authority.as_ref() {
            config.authority = normalized_string_or_existing(authority, &config.authority);
        }
        if let Some(server_name) = self.server_name.as_ref() {
            config.server_name = normalized_optional_string(server_name);
        }
        if let Some(server_roots) = self.server_roots.as_ref() {
            config.server_roots = normalize_optional_file_spec(server_roots, base);
        }
        if let Some(server_certificate) = self.server_certificate.as_ref() {
            config.server_certificate = normalize_optional_file_spec(server_certificate, base);
        }
        if let Some(mode) = self.mode {
            config.mode = mode;
        }
        if let Some(deployment_strength) = self.deployment_strength {
            config.deployment_strength = deployment_strength;
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

fn normalized_string_or_existing(value: &str, current: &str) -> String {
    normalized_optional_string(value).unwrap_or_else(|| current.to_string())
}

fn normalize_optional_file_spec(value: &str, base: &Path) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = trimmed.strip_prefix("file:") {
        let candidate = Path::new(path);
        let resolved = if candidate.is_relative() {
            base.join(candidate)
        } else {
            candidate.to_path_buf()
        };
        return Some(format!("file:{}", resolved.display()));
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_types::AuthProfile;
    use std::{net::SocketAddr, str::FromStr};

    fn test_config() -> ClientConfig {
        ClientConfig {
            server_addr: "198.51.100.10:443".to_string(),
            authority: "api.example.com".to_string(),
            server_name: Some("api.example.com".to_string()),
            server_roots: None,
            server_certificate: Some("BASE64-H2-CERT".to_string()),
            deployment_strength: V2DeploymentStrength::SelfContained,
            mode: Mode::STEALTH,
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
            allow_session_migration: true,
            standby_health_check_secs: 0,
            keepalive_secs: 25,
            session_idle_timeout_secs: 180,
            handshake_timeout_secs: 5,
            handshake_retries: 5,
            udp_recv_buffer_bytes: 4 * 1024 * 1024,
            udp_send_buffer_bytes: 4 * 1024 * 1024,
            state_path: PathBuf::from("client-state.toml"),
        }
    }

    #[test]
    fn empty_override_string_clears_optional_fields() {
        let mut config = test_config();
        ClientOverrideConfig {
            interface_name: Some(String::new()),
            server_name: Some(String::new()),
            server_certificate: Some(String::new()),
            ..ClientOverrideConfig::default()
        }
        .apply_to(&mut config, Path::new("/tmp/client.override.toml"));
        assert_eq!(config.interface_name, None);
        assert_eq!(config.server_name, None);
        assert_eq!(config.server_certificate, None);
    }

    #[test]
    fn relative_state_path_resolves_against_override_file() {
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
    fn relative_file_specs_resolve_against_override_file() {
        let mut config = test_config();
        ClientOverrideConfig {
            server_certificate: Some("file:certs/server.pem".to_string()),
            server_roots: Some("file:certs/root.pem".to_string()),
            ..ClientOverrideConfig::default()
        }
        .apply_to(&mut config, Path::new("/etc/adapt/client.override.toml"));
        assert_eq!(
            config.server_certificate.as_deref(),
            Some("file:/etc/adapt/certs/server.pem")
        );
        assert_eq!(
            config.server_roots.as_deref(),
            Some("file:/etc/adapt/certs/root.pem")
        );
    }

    #[test]
    fn authority_override_keeps_existing_value_when_blank() {
        let mut config = test_config();
        ClientOverrideConfig {
            authority: Some(String::new()),
            ..ClientOverrideConfig::default()
        }
        .apply_to(&mut config, Path::new("/tmp/client.override.toml"));
        assert_eq!(config.authority, "api.example.com");
    }
}
