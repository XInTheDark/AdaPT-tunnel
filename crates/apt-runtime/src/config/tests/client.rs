use super::*;
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
    assert_eq!(loaded.mode, Mode::STEALTH);
    let upgraded = fs::read_to_string(&config_path).unwrap();
    assert!(upgraded.contains("mode = 100"));
    assert!(upgraded.contains("preferred_carrier = \"auto\""));
    assert!(upgraded.contains("enable_d2_fallback = true"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn client_load_migrates_legacy_runtime_mode_field_to_numeric_mode() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("adapt-client-legacy-mode-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("shared-admission.key"), "11".repeat(32)).unwrap();
    fs::write(dir.join("server-static-public.key"), "22".repeat(32)).unwrap();
    fs::write(dir.join("client-static-private.key"), "33".repeat(32)).unwrap();
    let config_path = dir.join("client.toml");
    fs::write(
        &config_path,
        r#"
server_addr = "198.51.100.10:51820"
runtime_mode = "balanced"
endpoint_id = "adapt-demo"
admission_key = "file:./shared-admission.key"
server_static_public_key = "file:./server-static-public.key"
client_static_private_key = "file:./client-static-private.key"
"#,
    )
    .unwrap();
    let loaded = ClientConfig::load(&config_path).unwrap();
    assert_eq!(loaded.mode, Mode::BALANCED);
    let upgraded = fs::read_to_string(&config_path).unwrap();
    assert!(upgraded.contains("mode = 50"));
    assert!(!upgraded.contains("runtime_mode"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn client_resolve_rejects_unimplemented_hybrid_pq() {
    let config = ClientConfig {
        server_addr: "198.51.100.10:51820".to_string(),
        mode: Mode::STEALTH,
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
        enable_d2_fallback: false,
        d2_server_addr: None,
        d2_server_certificate: None,
        session_policy: SessionPolicy {
            allow_hybrid_pq: true,
        },
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
fn client_resolve_supports_inline_d2_certificate_material() {
    let identity = generate_d2_tls_identity(vec!["127.0.0.1".to_string()]).unwrap();
    let config = ClientConfig {
        server_addr: "198.51.100.10:51820".to_string(),
        mode: Mode::STEALTH,
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
        enable_d2_fallback: true,
        d2_server_addr: Some("127.0.0.1:443".to_string()),
        d2_server_certificate: Some(
            base64::engine::general_purpose::STANDARD.encode(&identity.certificate_der),
        ),
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
    };
    let resolved = config.resolve().unwrap();
    assert_eq!(resolved.d2.as_ref().unwrap().endpoint.addr.port(), 443);
    assert_eq!(
        resolved.d2.unwrap().server_certificate_der,
        identity.certificate_der
    );
}
