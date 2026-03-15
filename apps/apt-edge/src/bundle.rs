use super::*;
use apt_bundle::{store_client_bundle, ClientBundle, DEFAULT_CLIENT_BUNDLE_FILE_NAME};
use base64::Engine as _;

pub(super) fn add_client(
    config: Option<PathBuf>,
    name: Option<String>,
    auth: Option<CliAuthProfile>,
    out_file: Option<PathBuf>,
    no_import: bool,
    import_host: Option<String>,
    import_bind: Option<SocketAddr>,
    import_timeout_secs: u64,
    client_ip: Option<Ipv4Addr>,
    client_ipv6: Option<Ipv6Addr>,
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
    if client_ipv6.is_some()
        && (server_config.tunnel_local_ipv6.is_none()
            || server_config.tunnel_ipv6_prefix_len.is_none())
    {
        return Err(
            "this server config does not have IPv6 tunnel addressing enabled; remove --client-ipv6 or enable IPv6 in server.toml first"
                .into(),
        );
    }
    let client_ipv6 = match client_ipv6 {
        Some(ipv6) => Some(ipv6),
        None => next_available_client_ipv6(&server_config)?,
    };

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
        tunnel_ipv6: client_ipv6,
    });
    server_config.store(&config_path)?;

    let server_static_public_key = load_key32(&server_config.server_static_public_key)?;
    let d2_bundle = build_client_d2_bundle_fields(&server_config)?;
    let client_config = ClientConfig {
        server_addr: server_config.public_endpoint.clone(),
        mode: server_config.mode,
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
        enable_d2_fallback: d2_bundle.is_some(),
        d2_server_addr: d2_bundle.as_ref().map(|value| value.endpoint.clone()),
        d2_server_certificate: d2_bundle.as_ref().map(|value| value.certificate.clone()),
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
    let import_offer = if no_import {
        None
    } else {
        match crate::import::spawn_client_bundle_import_offer(
            &bundle_path,
            &server_config.public_endpoint,
            import_host.as_deref(),
            import_bind,
            import_timeout_secs,
        ) {
            Ok(offer) => Some(offer),
            Err(error) => {
                eprintln!(
                    "warning: temporary import service could not be started; falling back to local bundle copy instructions: {error}"
                );
                None
            }
        }
    };

    println!("\nClient bundle created.\n");
    println!("Updated server config:");
    println!("  • {}", config_path.display());
    println!("Client bundle:");
    println!("  • {}", bundle_path.display());
    println!("Assigned tunnel IPv4: {client_ip}");
    if let Some(client_ipv6) = client_ipv6 {
        println!("Assigned tunnel IPv6: {client_ipv6}");
    }
    println!("Admission profile: {}", auth_profile_label(auth_profile));
    if let Some(import_offer) = import_offer {
        println!("\nTemporary client import:");
        println!("  • endpoint: {}", import_offer.endpoint);
        println!("  • temporary key: {}", import_offer.temporary_key);
        println!("  • expires in: {} seconds", import_offer.timeout_secs);
        println!("  • client command:");
        println!(
            "     sudo apt-client import --server {} --key {}",
            import_offer.endpoint, import_offer.temporary_key
        );
        println!(
            "     # or specify a custom install path with --bundle /path/to/{}.aptbundle",
            name
        );
        println!(
            "     # if this host is behind a firewall/NAT, make sure port {} is reachable",
            import_offer
                .endpoint
                .rsplit_once(':')
                .map_or_else(|| "?".to_string(), |(_, port)| port.to_string())
        );
    }
    println!("\nManual fallback:");
    println!("  1. Copy this single bundle file to the client device:");
    println!("     {}", bundle_path.display());
    println!("  2. Recommended install path on the client:");
    println!("     sudo mkdir -p /etc/adapt");
    println!(
        "     sudo cp /path/to/{name}.aptbundle /etc/adapt/{}",
        DEFAULT_CLIENT_BUNDLE_FILE_NAME
    );
    println!("     sudo apt-client up");
    println!("     # first run auto-creates /etc/adapt/client.override.toml (blank)");
    println!("     # or run it directly with:");
    println!("     sudo apt-client up --bundle /path/to/{name}.aptbundle");
    println!("  3. If the server is not already running, start it with:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    Ok(())
}

pub(super) fn list_clients(config: Option<PathBuf>) -> CliResult {
    let config_path = match config {
        Some(path) => path,
        None => match find_server_config() {
            Some(path) => path,
            None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
        },
    };
    let server_config = ServerConfig::load(&config_path)?;
    println!(
        "Authorized clients in {}:\n{}",
        config_path.display(),
        render_client_listing(&server_config.peers)
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

fn render_client_listing(peers: &[AuthorizedPeerConfig]) -> String {
    if peers.is_empty() {
        return "  (no authorized clients)".to_string();
    }

    let mut ordered = peers.to_vec();
    ordered.sort_by_key(|peer| {
        (
            u32::from(peer.tunnel_ipv4),
            peer.tunnel_ipv6.map(u128::from),
            peer.name.clone(),
        )
    });

    let mut output = String::new();
    for peer in ordered {
        output.push_str(&format!("- {}\n", peer.name));
        output.push_str(&format!(
            "  auth: {}\n",
            auth_profile_label(peer.auth_profile)
        ));
        if let Some(user_id) = peer.user_id.as_deref() {
            output.push_str(&format!("  user_id: {user_id}\n"));
        }
        output.push_str(&format!("  tunnel_ipv4: {}\n", peer.tunnel_ipv4));
        if let Some(tunnel_ipv6) = peer.tunnel_ipv6 {
            output.push_str(&format!("  tunnel_ipv6: {tunnel_ipv6}\n"));
        }
    }
    output.trim_end().to_string()
}

#[derive(Clone, Debug)]
struct ClientD2BundleFields {
    endpoint: String,
    certificate: String,
}

fn build_client_d2_bundle_fields(
    server_config: &ServerConfig,
) -> CliResult<Option<ClientD2BundleFields>> {
    let any_present = server_config.d2_bind.is_some()
        || server_config.d2_public_endpoint.is_some()
        || server_config.d2_certificate.is_some()
        || server_config.d2_private_key.is_some();
    if !any_present {
        return Ok(None);
    }

    let endpoint = match server_config.d2_public_endpoint.as_ref() {
        Some(value) => value.clone(),
        None => derive_d2_public_endpoint(&server_config.public_endpoint).ok_or_else(|| {
            "D2 is partially configured, but d2_public_endpoint could not be derived".to_string()
        })?,
    };
    let certificate_spec = server_config
        .d2_certificate
        .as_deref()
        .ok_or_else(|| "D2 is partially configured, but d2_certificate is missing".to_string())?;
    let certificate =
        base64::engine::general_purpose::STANDARD.encode(load_certificate_der(certificate_spec)?);
    Ok(Some(ClientD2BundleFields {
        endpoint,
        certificate,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_client_listing_handles_empty_config() {
        assert_eq!(render_client_listing(&[]), "  (no authorized clients)");
    }

    #[test]
    fn render_client_listing_sorts_by_tunnel_ip_and_includes_auth_details() {
        let rendered = render_client_listing(&[
            AuthorizedPeerConfig {
                name: "beta".to_string(),
                auth_profile: AuthProfile::SharedDeployment,
                user_id: None,
                admission_key: None,
                client_static_public_key: "file:/tmp/beta.key".to_string(),
                tunnel_ipv4: Ipv4Addr::new(10, 77, 0, 3),
                tunnel_ipv6: Some("fd77:77::3".parse().unwrap()),
            },
            AuthorizedPeerConfig {
                name: "alpha".to_string(),
                auth_profile: AuthProfile::PerUser,
                user_id: Some("alice".to_string()),
                admission_key: Some("file:/tmp/alice.key".to_string()),
                client_static_public_key: "file:/tmp/alpha.key".to_string(),
                tunnel_ipv4: Ipv4Addr::new(10, 77, 0, 2),
                tunnel_ipv6: Some("fd77:77::2".parse().unwrap()),
            },
        ]);

        assert!(rendered.starts_with("- alpha\n"));
        assert!(rendered.contains("  auth: per-user\n"));
        assert!(rendered.contains("  user_id: alice\n"));
        assert!(rendered.contains("  tunnel_ipv4: 10.77.0.2\n"));
        assert!(rendered.contains("  tunnel_ipv6: fd77:77::2\n"));
        assert!(rendered.ends_with("tunnel_ipv6: fd77:77::3"));
    }
}
