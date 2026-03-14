use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn init_server(
    out_dir: Option<PathBuf>,
    bind: Option<SocketAddr>,
    public_endpoint: Option<String>,
    enable_d2: bool,
    d2_bind: Option<SocketAddr>,
    d2_public_endpoint: Option<String>,
    stream_bind: Option<SocketAddr>,
    stream_public_endpoint: Option<String>,
    stream_decoy_surface: bool,
    endpoint_id: Option<String>,
    egress_interface: Option<String>,
    tunnel_subnet: Option<String>,
    tunnel_subnet6: Option<String>,
    interface_name: Option<String>,
    push_routes: Vec<String>,
    dns_servers: Vec<IpAddr>,
    yes: bool,
) -> CliResult {
    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("/etc/adapt"));
    let bind = match bind {
        Some(bind) => bind,
        None if yes => "0.0.0.0:51820".parse()?,
        None => prompt_parse("UDP listen address", Some("0.0.0.0:51820"))?,
    };
    let public_endpoint =
        match public_endpoint {
            Some(value) => {
                validate_client_reachable_endpoint(&value)?;
                value
            }
            None if yes && !bind.ip().is_unspecified() => {
                let value = bind.to_string();
                validate_client_reachable_endpoint(&value)?;
                value
            }
            None if yes => return Err(
                "--public-endpoint is required when using --yes with an unspecified bind address"
                    .into(),
            ),
            None => loop {
                let value = prompt_string("Client-reachable public IP/DNS and port", None)?;
                match validate_client_reachable_endpoint(&value) {
                    Ok(()) => break value,
                    Err(error) => eprintln!("Invalid value: {error}"),
                }
            },
        };
    let d2_requested = if enable_d2 || d2_bind.is_some() || d2_public_endpoint.is_some() {
        true
    } else if yes {
        false
    } else {
        prompt_bool("Enable optional D2 QUIC carrier", false)?
    };
    let d2_bind = if d2_requested {
        match d2_bind {
            Some(bind) => Some(bind),
            None if yes => Some(d2_default_bind()),
            None => Some(prompt_parse(
                "D2 QUIC listen address",
                Some(&d2_default_bind().to_string()),
            )?),
        }
    } else {
        None
    };
    let d2_public_endpoint = if d2_requested {
        let default_endpoint = derive_d2_public_endpoint(&public_endpoint).ok_or_else(|| {
            "could not derive a default D2 public endpoint from the main public endpoint"
                .to_string()
        })?;
        match d2_public_endpoint {
            Some(value) => {
                validate_client_reachable_endpoint(&value)?;
                Some(value)
            }
            None if yes => Some(default_endpoint),
            None => {
                let value = prompt_string("D2 client-reachable endpoint", Some(&default_endpoint))?;
                validate_client_reachable_endpoint(&value)?;
                Some(value)
            }
        }
    } else {
        None
    };
    let stream_enabled = if stream_bind.is_some() || stream_public_endpoint.is_some() {
        true
    } else if yes {
        true
    } else {
        prompt_bool("Enable optional S1 stream fallback", true)?
    };
    let stream_bind = if stream_enabled {
        match stream_bind {
            Some(bind) => Some(bind),
            None if yes => Some("0.0.0.0:443".parse()?),
            None => Some(prompt_parse(
                "S1 stream listen address",
                Some("0.0.0.0:443"),
            )?),
        }
    } else {
        None
    };
    let stream_public_endpoint = if stream_enabled {
        let default_endpoint =
            derive_stream_public_endpoint(&public_endpoint).ok_or_else(|| {
                "could not derive a default S1 public endpoint from the main public endpoint"
                    .to_string()
            })?;
        match stream_public_endpoint {
            Some(value) => {
                validate_client_reachable_endpoint(&value)?;
                Some(value)
            }
            None if yes => Some(default_endpoint),
            None => {
                let value = prompt_string("S1 client-reachable endpoint", Some(&default_endpoint))?;
                validate_client_reachable_endpoint(&value)?;
                Some(value)
            }
        }
    } else {
        None
    };
    let endpoint_id = match endpoint_id {
        Some(value) => value,
        None if yes => "adapt-prod".to_string(),
        None => prompt_string("Deployment name / endpoint ID", Some("adapt-prod"))?,
    };
    let egress_interface = match egress_interface {
        Some(value) => value,
        None if yes => "eth0".to_string(),
        None => prompt_string("Linux egress interface for internet access", Some("eth0"))?,
    };
    let tunnel_subnet = match tunnel_subnet {
        Some(value) => value,
        None if yes => "10.77.0.0/24".to_string(),
        None => prompt_string("Tunnel subnet (CIDR)", Some("10.77.0.0/24"))?,
    };
    let subnet: Ipv4Net = tunnel_subnet
        .parse()
        .map_err(|error| format!("invalid tunnel subnet `{tunnel_subnet}`: {error}"))?;
    let tunnel_subnet6 = match tunnel_subnet6 {
        Some(value) => Some(value),
        None if yes => None,
        None if prompt_bool("Enable IPv6 tunnel addressing", false)? => Some(prompt_string(
            "IPv6 tunnel subnet (CIDR)",
            Some("fd77:77::/64"),
        )?),
        None => None,
    };
    let subnet6 = tunnel_subnet6
        .as_deref()
        .map(|value| {
            value
                .parse::<Ipv6Net>()
                .map_err(|error| format!("invalid IPv6 tunnel subnet `{value}`: {error}"))
        })
        .transpose()?;
    let interface_name = match interface_name {
        Some(value) => value,
        None if yes => "aptsrv0".to_string(),
        None => prompt_string("Server TUN interface name", Some("aptsrv0"))?,
    };
    let push_routes = if push_routes.is_empty() {
        let mut defaults = vec!["0.0.0.0/0".to_string()];
        if subnet6.is_some() {
            defaults.push("::/0".to_string());
        }
        defaults
    } else {
        push_routes
    };
    let push_routes = push_routes
        .into_iter()
        .map(|route| route.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()?;
    let push_dns = if dns_servers.is_empty() {
        vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        ]
    } else {
        dns_servers
    };

    fs::create_dir_all(&out_dir)?;
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
    fs::create_dir_all(out_dir.join("bundles"))?;
    let d2 = if d2_requested {
        Some(configure_d2_material(
            &out_dir,
            &public_endpoint,
            d2_bind,
            d2_public_endpoint,
        )?)
    } else {
        None
    };

    let server_ip = first_usable_ipv4(subnet)?;
    let server_ipv6 = subnet6
        .as_ref()
        .copied()
        .map(first_usable_ipv6)
        .transpose()?;
    let config = ServerConfig {
        bind,
        public_endpoint,
        runtime_mode: RuntimeMode::Stealth,
        d2_bind: d2.as_ref().map(|value| value.bind),
        d2_public_endpoint: d2.as_ref().map(|value| value.public_endpoint.clone()),
        d2_certificate: d2.as_ref().map(|value| value.certificate_spec.clone()),
        d2_private_key: d2.as_ref().map(|value| value.private_key_spec.clone()),
        stream_bind,
        stream_public_endpoint,
        stream_decoy_surface,
        endpoint_id,
        admission_key: "file:./shared-admission.key".to_string(),
        server_static_private_key: "file:./server-static-private.key".to_string(),
        server_static_public_key: "file:./server-static-public.key".to_string(),
        cookie_key: "file:./cookie.key".to_string(),
        ticket_key: "file:./ticket.key".to_string(),
        interface_name: Some(interface_name.clone()),
        tunnel_local_ipv4: server_ip,
        tunnel_netmask: ipv4_netmask(subnet.prefix_len()),
        tunnel_local_ipv6: server_ipv6,
        tunnel_ipv6_prefix_len: subnet6.as_ref().map(Ipv6Net::prefix_len),
        tunnel_mtu: 1380,
        egress_interface: Some(egress_interface.clone()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
        enable_ipv6_forwarding: server_ipv6.is_some(),
        nat_ipv6: server_ipv6.is_some(),
        push_routes,
        push_dns,
        session_policy: SessionPolicy::default(),
        allow_session_migration: true,
        keepalive_secs: 25,
        session_idle_timeout_secs: 180,
        udp_recv_buffer_bytes: 4 * 1024 * 1024,
        udp_send_buffer_bytes: 4 * 1024 * 1024,
        peers: Vec::new(),
    };
    let config_path = out_dir.join("server.toml");
    config.store(&config_path)?;

    println!("\nAPT server setup complete.\n");
    println!("Created:");
    println!("  • {}", config_path.display());
    println!("  • {}/shared-admission.key", out_dir.display());
    println!("  • {}/server-static-private.key", out_dir.display());
    println!("  • {}/server-static-public.key", out_dir.display());
    println!("  • {}/cookie.key", out_dir.display());
    println!("  • {}/ticket.key", out_dir.display());
    println!(
        "  • {}/bundles/ (single-file client bundles)",
        out_dir.display()
    );
    println!("\nServer summary:");
    println!("  • Listen on: {bind}");
    println!(
        "  • Public endpoint for clients: {}",
        config.public_endpoint
    );
    match &config.d2_public_endpoint {
        Some(endpoint) => println!("  • D2 QUIC endpoint: {endpoint}"),
        None => println!("  • D2 QUIC endpoint: disabled"),
    }
    match &config.stream_public_endpoint {
        Some(endpoint) => println!("  • Stream fallback endpoint: {endpoint}"),
        None => println!("  • Stream fallback endpoint: disabled"),
    }
    println!("  • Tunnel subnet: {}", subnet);
    println!("  • Server tunnel IP: {}", config.tunnel_local_ipv4);
    match (subnet6, config.tunnel_local_ipv6) {
        (Some(subnet6), Some(ipv6)) => {
            println!("  • Tunnel IPv6 subnet: {subnet6}");
            println!("  • Server tunnel IPv6: {ipv6}");
        }
        _ => println!("  • Tunnel IPv6: disabled"),
    }
    println!("  • Egress interface: {egress_interface}");
    println!("\nNext steps:");
    println!("  1. Add a client bundle:");
    println!(
        "     apt-edge add-client --config {} --name laptop --auth per-user",
        config_path.display()
    );
    println!("  2. Start the server:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    Ok(())
}

pub(super) fn enable_d2_for_server(
    config: Option<PathBuf>,
    d2_bind: Option<SocketAddr>,
    d2_public_endpoint: Option<String>,
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
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let d2 = configure_d2_material(
        &config_dir,
        &server_config.public_endpoint,
        d2_bind.or(server_config.d2_bind),
        d2_public_endpoint.or_else(|| server_config.d2_public_endpoint.clone()),
    )?;
    server_config.d2_bind = Some(d2.bind);
    server_config.d2_public_endpoint = Some(d2.public_endpoint.clone());
    server_config.d2_certificate = Some(d2.certificate_spec.clone());
    server_config.d2_private_key = Some(d2.private_key_spec.clone());
    server_config.store(&config_path)?;

    println!("\nD2 carrier enabled.\n");
    println!("Updated server config:");
    println!("  • {}", config_path.display());
    println!("D2 QUIC endpoint:");
    println!("  • {}", d2.public_endpoint);
    println!("Generated certificate files:");
    println!("  • {}/d2-certificate.pem", config_dir.display());
    println!("  • {}/d2-private-key.pem", config_dir.display());
    println!("\nNext steps:");
    println!("  1. Restart the server after any running session drain:");
    println!(
        "     sudo apt-edge start --config {}",
        config_path.display()
    );
    println!("  2. Re-issue client bundles so they contain the pinned D2 certificate:");
    println!(
        "     apt-edge add-client --config {} --name <client-name> --auth per-user",
        config_path.display()
    );
    println!("  3. On a client, test strict D2 with:");
    println!("     sudo apt-client up --carrier d2");
    Ok(())
}

#[derive(Clone, Debug)]
struct D2Material {
    bind: SocketAddr,
    public_endpoint: String,
    certificate_spec: String,
    private_key_spec: String,
}

fn configure_d2_material(
    out_dir: &Path,
    fallback_public_endpoint: &str,
    d2_bind: Option<SocketAddr>,
    d2_public_endpoint: Option<String>,
) -> CliResult<D2Material> {
    let bind = d2_bind.unwrap_or_else(d2_default_bind);
    let public_endpoint = match d2_public_endpoint {
        Some(value) => {
            validate_client_reachable_endpoint(&value)?;
            value
        }
        None => derive_d2_public_endpoint(fallback_public_endpoint).ok_or_else(|| {
            "could not derive a D2 public endpoint; pass --d2-public-endpoint explicitly"
                .to_string()
        })?,
    };
    let identity = generate_d2_tls_identity(d2_certificate_subject_alt_names(&public_endpoint))?;
    write_secret_file(
        &out_dir.join("d2-certificate.pem"),
        identity.certificate_pem.as_bytes(),
    )?;
    write_secret_file(
        &out_dir.join("d2-private-key.pem"),
        identity.private_key_pem.as_bytes(),
    )?;
    Ok(D2Material {
        bind,
        public_endpoint,
        certificate_spec: "file:./d2-certificate.pem".to_string(),
        private_key_spec: "file:./d2-private-key.pem".to_string(),
    })
}
