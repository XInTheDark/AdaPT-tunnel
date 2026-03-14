use super::*;

pub(super) fn add_client(
    config: Option<PathBuf>,
    name: Option<String>,
    out_dir: Option<PathBuf>,
    client_ip: Option<Ipv4Addr>,
    yes: bool,
) -> CliResult {
    let config_path = match config {
        Some(path) => path,
        None => match find_server_config() {
            Some(path) => path,
            None if yes => {
                return Err(
                    "could not find a server config; pass --config or run `apt-edge init` first"
                        .into(),
                )
            }
            None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
        },
    };
    let mut server_config = ServerConfig::load(&config_path)?;
    let name = match name {
        Some(value) => value,
        None if yes => return Err("--name is required when using --yes".into()),
        None => prompt_string("Client name", Some("laptop"))?,
    };
    if server_config.peers.iter().any(|peer| peer.name == name) {
        return Err(format!(
            "a client named `{name}` already exists in {}",
            config_path.display()
        )
        .into());
    }
    let bundle_dir = out_dir.unwrap_or_else(|| {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("bundles")
            .join(&name)
    });
    let server_peer_key_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("clients")
        .join(format!("{name}.client-static-public.key"));
    fs::create_dir_all(&bundle_dir)?;
    if let Some(parent) = server_peer_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let client_ip = client_ip.unwrap_or(next_available_client_ipv4(&server_config)?);

    let identity = generate_client_identity()?;
    write_key_file(&server_peer_key_path, &identity.client_static_public_key)?;
    server_config.peers.push(AuthorizedPeerConfig {
        name: name.clone(),
        client_static_public_key: format!("file:{}", server_peer_key_path.display()),
        tunnel_ipv4: client_ip,
    });
    server_config.store(&config_path)?;

    let shared_admission_key = load_key32(&server_config.admission_key)?;
    let server_static_public_key = load_key32(&server_config.server_static_public_key)?;
    write_key_file(
        &bundle_dir.join("shared-admission.key"),
        &shared_admission_key,
    )?;
    write_key_file(
        &bundle_dir.join("server-static-public.key"),
        &server_static_public_key,
    )?;
    write_key_file(
        &bundle_dir.join("client-static-private.key"),
        &identity.client_static_private_key,
    )?;
    write_key_file(
        &bundle_dir.join("client-static-public.key"),
        &identity.client_static_public_key,
    )?;

    let client_config = ClientConfig {
        server_addr: server_config.public_endpoint.clone(),
        runtime_mode: server_config.runtime_mode,
        preferred_carrier: RuntimeCarrierPreference::D1,
        endpoint_id: server_config.endpoint_id.clone(),
        admission_key: "file:./shared-admission.key".to_string(),
        server_static_public_key: "file:./server-static-public.key".to_string(),
        client_static_private_key: "file:./client-static-private.key".to_string(),
        client_identity: Some(name.clone()),
        bind: "0.0.0.0:0".parse()?,
        interface_name: None,
        routes: Vec::new(),
        use_server_pushed_routes: true,
        session_policy: SessionPolicy::default(),
        enable_s1_fallback: true,
        stream_server_addr: server_config.stream_public_endpoint.clone(),
        allow_session_migration: true,
        standby_health_check_secs: 0,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        handshake_timeout_secs: 5,
        handshake_retries: 5,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        state_path: PathBuf::from("./client-state.toml"),
    };
    let client_config_path = bundle_dir.join("client.toml");
    client_config.store(&client_config_path)?;
    write_bundle_readme(&bundle_dir, &name)?;

    println!("\nClient bundle created.\n");
    println!("Updated server config:");
    println!("  • {}", config_path.display());
    println!("Client bundle:");
    println!("  • {}", bundle_dir.display());
    println!("Assigned tunnel IP: {client_ip}");
    println!("\nWhat to do next:");
    println!("  1. Copy this entire folder to the client device:");
    println!("     {}", bundle_dir.display());
    println!("  2. Recommended on the client:");
    println!("     sudo mkdir -p /etc/adapt");
    println!("     sudo cp -R {}/* /etc/adapt/", bundle_dir.display());
    println!("     sudo apt-client up");
    println!("  3. If the server is not already running, start it with:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    Ok(())
}

pub(super) fn write_server_keyset(out_dir: &Path) -> CliResult {
    let keyset = generate_server_keyset()?;
    write_key_file(&out_dir.join("shared-admission.key"), &keyset.admission_key)?;
    write_key_file(
        &out_dir.join("server-static-private.key"),
        &keyset.server_static_private_key,
    )?;
    write_key_file(
        &out_dir.join("server-static-public.key"),
        &keyset.server_static_public_key,
    )?;
    write_key_file(&out_dir.join("cookie.key"), &keyset.cookie_key)?;
    write_key_file(&out_dir.join("ticket.key"), &keyset.ticket_key)?;
    println!("Raw key files written to {}", out_dir.display());
    Ok(())
}

fn write_bundle_readme(bundle_dir: &Path, name: &str) -> io::Result<()> {
    fs::write(
        bundle_dir.join("START-HERE.txt"),
        format!(
            "APT client bundle for {name}\n\nRecommended install location on the client:\n  /etc/adapt\n\nRecommended steps:\n1. Copy this entire folder to the client device.\n2. On the client, install the bundle into /etc/adapt:\n\n   sudo mkdir -p /etc/adapt\n   sudo cp -R ./* /etc/adapt/\n\n3. Start the VPN using the default config location:\n\n   sudo apt-client up\n\nAlternative: you can also run directly from this folder with:\n\n   sudo apt-client up --config client.toml\n\nNote:\n- `client.toml` contains the server address from the server's `public_endpoint` setting.\n- That value must be a client-reachable IP:port or DNS name:port.\n"
        ),
    )
}
