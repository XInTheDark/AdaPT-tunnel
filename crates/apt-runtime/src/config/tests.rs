use super::*;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn key_material_loads_from_hex() {
    let value = "11".repeat(32);
    let bytes = load_key32(&value).unwrap();
    assert_eq!(bytes, [0x11; 32]);
}

#[test]
fn key_material_loads_from_file() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("adapt-key-{unique}.txt"));
    fs::write(&path, "22".repeat(32)).unwrap();
    let bytes = load_key32(&format!("file:{}", path.display())).unwrap();
    assert_eq!(bytes, [0x22; 32]);
    let _ = fs::remove_file(path);
}

#[test]
fn client_load_resolves_relative_key_paths() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
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
    assert!(config
        .admission_key
        .contains(dir.to_string_lossy().as_ref()));
    assert!(config
        .server_static_public_key
        .contains(dir.to_string_lossy().as_ref()));
    assert!(config
        .client_static_private_key
        .contains(dir.to_string_lossy().as_ref()));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn server_load_resolves_relative_key_paths() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
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
    assert!(config
        .admission_key
        .contains(dir.to_string_lossy().as_ref()));
    assert!(config.peers[0]
        .client_static_public_key
        .contains(dir.to_string_lossy().as_ref()));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn server_resolve_supports_per_user_authorized_peers() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("adapt-server-per-user-{unique}"));
    fs::create_dir_all(dir.join("clients")).unwrap();
    fs::create_dir_all(dir.join("users")).unwrap();
    for file in [
        "shared-admission.key",
        "server-static-private.key",
        "server-static-public.key",
        "cookie.key",
        "ticket.key",
        "clients/laptop.client-static-public.key",
        "users/laptop.admission.key",
    ] {
        fs::write(dir.join(file), "55".repeat(32)).unwrap();
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
auth_profile = "PerUser"
user_id = "laptop-user"
admission_key = "file:./users/laptop.admission.key"
client_static_public_key = "file:./clients/laptop.client-static-public.key"
tunnel_ipv4 = "10.77.0.2"
"#,
    )
    .unwrap();
    let resolved = ServerConfig::load(dir.join("server.toml"))
        .unwrap()
        .resolve()
        .unwrap();
    assert_eq!(resolved.peers[0].auth_profile, AuthProfile::PerUser);
    assert_eq!(resolved.peers[0].user_id, "laptop-user");
    assert_eq!(resolved.peers[0].admission_key, Some([0x55; 32]));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn placeholder_server_address_is_rejected() {
    let error = resolve_socket_addr("vpn.example.com:51820").unwrap_err();
    assert!(error.to_string().contains("example placeholder"));
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

#[test]
fn client_load_upgrades_missing_phase_two_fields() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("adapt-client-upgrade-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("shared-admission.key"), "11".repeat(32)).unwrap();
    fs::write(dir.join("server-static-public.key"), "22".repeat(32)).unwrap();
    fs::write(dir.join("client-static-private.key"), "33".repeat(32)).unwrap();
    let config_path = dir.join("client.toml");
    fs::write(
        &config_path,
        r#"
server_addr = "198.51.100.10:51820"
endpoint_id = "adapt-demo"
admission_key = "file:./shared-admission.key"
server_static_public_key = "file:./server-static-public.key"
client_static_private_key = "file:./client-static-private.key"
"#,
    )
    .unwrap();
    let loaded = ClientConfig::load(&config_path).unwrap();
    assert_eq!(loaded.runtime_mode, RuntimeMode::Stealth);
    let upgraded = fs::read_to_string(&config_path).unwrap();
    assert!(upgraded.contains("runtime_mode = \"stealth\""));
    assert!(upgraded.contains("preferred_carrier = \"d1\""));
    assert!(upgraded.contains("enable_s1_fallback = true"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn client_resolve_rejects_unimplemented_hybrid_pq() {
    let config = ClientConfig {
        server_addr: "198.51.100.10:51820".to_string(),
        runtime_mode: RuntimeMode::Stealth,
        preferred_carrier: RuntimeCarrierPreference::D1,
        auth_profile: AuthProfile::SharedDeployment,
        endpoint_id: "adapt-demo".to_string(),
        admission_key: "11".repeat(32),
        server_static_public_key: "22".repeat(32),
        client_static_private_key: "33".repeat(32),
        client_identity: None,
        bind: "0.0.0.0:0".parse().unwrap(),
        interface_name: None,
        routes: Vec::new(),
        use_server_pushed_routes: true,
        session_policy: SessionPolicy {
            initial_mode: PolicyMode::StealthFirst,
            allow_speed_first: false,
            allow_hybrid_pq: true,
        },
        enable_s1_fallback: true,
        stream_server_addr: None,
        allow_session_migration: true,
        standby_health_check_secs: 0,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        handshake_timeout_secs: 5,
        handshake_retries: 5,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        state_path: PathBuf::from("client-state.toml"),
    };
    let error = config.resolve().unwrap_err();
    assert!(error.to_string().contains("allow_hybrid_pq"));
}

#[test]
fn server_load_upgrades_missing_phase_two_fields() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("adapt-server-upgrade-{unique}"));
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
    let config_path = dir.join("server.toml");
    fs::write(
        &config_path,
        r#"
bind = "0.0.0.0:51820"
public_endpoint = "203.0.113.10:51820"
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
    let loaded = ServerConfig::load(&config_path).unwrap();
    assert_eq!(loaded.runtime_mode, RuntimeMode::Stealth);
    let upgraded = fs::read_to_string(&config_path).unwrap();
    assert!(upgraded.contains("stream_decoy_surface = false"));
    assert!(upgraded.contains("allow_session_migration = true"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn server_resolve_rejects_unimplemented_hybrid_pq() {
    let config = ServerConfig {
        bind: "0.0.0.0:51820".parse().unwrap(),
        public_endpoint: "203.0.113.10:51820".to_string(),
        runtime_mode: RuntimeMode::Stealth,
        stream_bind: None,
        stream_public_endpoint: None,
        stream_decoy_surface: false,
        endpoint_id: "adapt-demo".to_string(),
        admission_key: "11".repeat(32),
        server_static_private_key: "22".repeat(32),
        server_static_public_key: "33".repeat(32),
        cookie_key: "44".repeat(32),
        ticket_key: "55".repeat(32),
        interface_name: Some("aptsrv0".to_string()),
        tunnel_local_ipv4: Ipv4Addr::new(10, 77, 0, 1),
        tunnel_netmask: Ipv4Addr::new(255, 255, 255, 0),
        tunnel_mtu: 1380,
        egress_interface: Some("eth0".to_string()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
        push_routes: Vec::new(),
        push_dns: Vec::new(),
        session_policy: SessionPolicy {
            initial_mode: PolicyMode::StealthFirst,
            allow_speed_first: false,
            allow_hybrid_pq: true,
        },
        allow_session_migration: true,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        peers: Vec::new(),
    };
    let error = config.resolve().unwrap_err();
    assert!(error.to_string().contains("allow_hybrid_pq"));
}
