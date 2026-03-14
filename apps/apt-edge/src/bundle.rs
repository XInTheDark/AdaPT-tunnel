use super::*;
use apt_bundle::{store_client_bundle, ClientBundle, DEFAULT_CLIENT_BUNDLE_FILE_NAME};

pub(super) fn add_client(
    config: Option<PathBuf>,
    name: Option<String>,
    auth: Option<CliAuthProfile>,
    out_file: Option<PathBuf>,
    client_ip: Option<Ipv4Addr>,
    yes: bool,
) -> CliResult {
    let config_path =
        match config {
            Some(path) => path,
            None => match find_server_config() {
                Some(path) => path,
                None if yes => return Err(
                    "could not find a server config; pass --config or run `apt-edge init` first"
                        .into(),
                ),
                None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
            },
        };
    let mut server_config = ServerConfig::load(&config_path)?;
    let name = match name {
        Some(value) => value,
        None if yes => return Err("--name is required when using --yes".into()),
        None => prompt_string("Client name", Some("laptop"))?,
    };
    let auth_profile = match auth {
        Some(auth) => AuthProfile::from(auth),
        None if yes => AuthProfile::PerUser,
        None => prompt_auth_profile(CliAuthProfile::PerUser)?,
    };
    if server_config.peers.iter().any(|peer| peer.name == name) {
        return Err(format!(
            "a client named `{name}` already exists in {}",
            config_path.display()
        )
        .into());
    }
    let bundle_path = out_file.unwrap_or_else(|| {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("bundles")
            .join(format!("{name}.aptbundle"))
    });
    let server_peer_key_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("clients")
        .join(format!("{name}.client-static-public.key"));
    if let Some(parent) = bundle_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = server_peer_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let client_ip = client_ip.unwrap_or(next_available_client_ipv4(&server_config)?);

    let identity = generate_client_identity()?;
    write_key_file(&server_peer_key_path, &identity.client_static_public_key)?;
    let user_admission_key_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("users")
        .join(format!("{name}.admission.key"));
    if let Some(parent) = user_admission_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let (bundle_admission_key, admission_key_spec) = match auth_profile {
        AuthProfile::SharedDeployment => (load_key32(&server_config.admission_key)?, None),
        AuthProfile::PerUser => {
            let user_admission_key: [u8; 32] = rand::random();
            write_key_file(&user_admission_key_path, &user_admission_key)?;
            (
                user_admission_key,
                Some(format!("file:{}", user_admission_key_path.display())),
            )
        }
    };
    server_config.peers.push(AuthorizedPeerConfig {
        name: name.clone(),
        auth_profile,
        user_id: matches!(auth_profile, AuthProfile::PerUser).then(|| name.clone()),
        admission_key: admission_key_spec,
        client_static_public_key: format!("file:{}", server_peer_key_path.display()),
        tunnel_ipv4: client_ip,
    });
    server_config.store(&config_path)?;

    let server_static_public_key = load_key32(&server_config.server_static_public_key)?;
    let client_config = ClientConfig {
        server_addr: server_config.public_endpoint.clone(),
        runtime_mode: server_config.runtime_mode,
        preferred_carrier: RuntimeCarrierPreference::D1,
        auth_profile,
        endpoint_id: server_config.endpoint_id.clone(),
        admission_key: encode_key_hex(&bundle_admission_key),
        server_static_public_key: encode_key_hex(&server_static_public_key),
        client_static_private_key: encode_key_hex(&identity.client_static_private_key),
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
        state_path: PathBuf::from("client-state.toml"),
    };
    store_client_bundle(
        &bundle_path,
        &ClientBundle {
            client_name: name.clone(),
            config: client_config,
        },
    )?;

    println!("\nClient bundle created.\n");
    println!("Updated server config:");
    println!("  • {}", config_path.display());
    println!("Client bundle:");
    println!("  • {}", bundle_path.display());
    println!("Assigned tunnel IP: {client_ip}");
    println!("Admission profile: {}", auth_profile_label(auth_profile));
    println!("\nWhat to do next:");
    println!("  1. Copy this single bundle file to the client device:");
    println!("     {}", bundle_path.display());
    println!("  2. Recommended install path on the client:");
    println!("     sudo mkdir -p /etc/adapt");
    println!(
        "     sudo cp /path/to/{name}.aptbundle /etc/adapt/{}",
        DEFAULT_CLIENT_BUNDLE_FILE_NAME
    );
    println!("     sudo apt-client up");
    println!("     # or run it directly with:");
    println!("     sudo apt-client up --bundle /path/to/{name}.aptbundle");
    println!("  3. If the server is not already running, start it with:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    Ok(())
}

pub(super) fn revoke_client(config: Option<PathBuf>, name: Option<String>, yes: bool) -> CliResult {
    let config_path =
        match config {
            Some(path) => path,
            None => match find_server_config() {
                Some(path) => path,
                None if yes => return Err(
                    "could not find a server config; pass --config or run `apt-edge init` first"
                        .into(),
                ),
                None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
            },
        };
    let mut server_config = ServerConfig::load(&config_path)?;
    let name = match name {
        Some(value) => value,
        None if yes => return Err("--name is required when using --yes".into()),
        None => prompt_string("Client name to revoke", Some("laptop"))?,
    };
    let Some(peer_index) = server_config
        .peers
        .iter()
        .position(|peer| peer.name == name)
    else {
        return Err(format!(
            "no client named `{name}` exists in {}",
            config_path.display()
        )
        .into());
    };
    let peer = server_config.peers.remove(peer_index);
    server_config.store(&config_path)?;
    let config_root = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut removed_files = Vec::new();
    for spec in [
        Some(peer.client_static_public_key.as_str()),
        peer.admission_key.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(path) = file_spec_path(spec) {
            if is_path_within(&config_root, &path) && path.exists() {
                fs::remove_file(&path)?;
                removed_files.push(path);
            }
        }
    }

    println!("\nClient revoked.\n");
    println!("Updated server config:");
    println!("  • {}", config_path.display());
    if !removed_files.is_empty() {
        println!("Removed local credential files:");
        for path in &removed_files {
            println!("  • {}", path.display());
        }
    }
    println!("\nThe client bundle is now unauthorized. If copies still exist on devices, remove them there too.");
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

fn auth_profile_label(auth_profile: AuthProfile) -> &'static str {
    match auth_profile {
        AuthProfile::SharedDeployment => "shared-deployment",
        AuthProfile::PerUser => "per-user",
    }
}
