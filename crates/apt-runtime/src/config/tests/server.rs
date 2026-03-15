use super::*;
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
    assert_eq!(loaded.mode, Mode::STEALTH);
    let upgraded = fs::read_to_string(&config_path).unwrap();
    assert!(upgraded.contains("allow_session_migration = true"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn server_load_migrates_legacy_runtime_mode_field_to_numeric_mode() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("adapt-server-legacy-mode-{unique}"));
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
runtime_mode = "speed"
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
    assert_eq!(loaded.mode, Mode::SPEED);
    let upgraded = fs::read_to_string(&config_path).unwrap();
    assert!(upgraded.contains("mode = 0"));
    assert!(!upgraded.contains("runtime_mode"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn server_resolve_rejects_unimplemented_hybrid_pq() {
    let config = ServerConfig {
        bind: "0.0.0.0:51820".parse().unwrap(),
        public_endpoint: "203.0.113.10:51820".to_string(),
        mode: Mode::STEALTH,
        d2_bind: None,
        d2_public_endpoint: None,
        d2_certificate: None,
        d2_private_key: None,
        endpoint_id: "adapt-demo".to_string(),
        admission_key: "11".repeat(32),
        server_static_private_key: "22".repeat(32),
        server_static_public_key: "33".repeat(32),
        cookie_key: "44".repeat(32),
        ticket_key: "55".repeat(32),
        interface_name: Some("aptsrv0".to_string()),
        tunnel_local_ipv4: Ipv4Addr::new(10, 77, 0, 1),
        tunnel_netmask: Ipv4Addr::new(255, 255, 255, 0),
        tunnel_local_ipv6: None,
        tunnel_ipv6_prefix_len: None,
        tunnel_mtu: 1380,
        egress_interface: Some("eth0".to_string()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
        enable_ipv6_forwarding: false,
        nat_ipv6: false,
        push_routes: Vec::new(),
        push_dns: Vec::new(),
        session_policy: SessionPolicy {
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

#[test]
fn server_resolve_derives_d2_public_endpoint_when_enabled() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("adapt-server-d2-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    let identity = generate_d2_tls_identity(vec!["198.51.100.10".to_string()]).unwrap();
    let cert_path = dir.join("d2-cert.pem");
    let key_path = dir.join("d2-key.pem");
    fs::write(&cert_path, identity.certificate_pem).unwrap();
    fs::write(&key_path, identity.private_key_pem).unwrap();

    let config = ServerConfig {
        bind: "0.0.0.0:51820".parse().unwrap(),
        public_endpoint: "198.51.100.10:51820".to_string(),
        mode: Mode::STEALTH,
        d2_bind: Some("0.0.0.0:443".parse().unwrap()),
        d2_public_endpoint: None,
        d2_certificate: Some(format!("file:{}", cert_path.display())),
        d2_private_key: Some(format!("file:{}", key_path.display())),
        endpoint_id: "adapt-demo".to_string(),
        admission_key: "11".repeat(32),
        server_static_private_key: "22".repeat(32),
        server_static_public_key: "33".repeat(32),
        cookie_key: "44".repeat(32),
        ticket_key: "55".repeat(32),
        interface_name: Some("aptsrv0".to_string()),
        tunnel_local_ipv4: Ipv4Addr::new(10, 77, 0, 1),
        tunnel_netmask: Ipv4Addr::new(255, 255, 255, 0),
        tunnel_local_ipv6: Some("fd77:77::1".parse().unwrap()),
        tunnel_ipv6_prefix_len: Some(64),
        tunnel_mtu: 1380,
        egress_interface: Some("eth0".to_string()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
        enable_ipv6_forwarding: true,
        nat_ipv6: true,
        push_routes: Vec::new(),
        push_dns: Vec::new(),
        session_policy: SessionPolicy::default(),
        allow_session_migration: true,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        peers: Vec::new(),
    };
    let resolved = config.resolve().unwrap();
    let d2 = resolved.d2.unwrap();
    assert_eq!(d2.public_endpoint, "198.51.100.10:443");
    assert_eq!(
        load_certificate_der(&d2.certificate_spec).unwrap(),
        identity.certificate_der
    );
    let _ = fs::remove_dir_all(dir);
}
