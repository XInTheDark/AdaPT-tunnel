use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn init_server(
    out_dir: Option<PathBuf>,
    bind: Option<SocketAddr>,
    public_endpoint: Option<String>,
    stream_bind: Option<SocketAddr>,
    stream_public_endpoint: Option<String>,
    stream_decoy_surface: bool,
    endpoint_id: Option<String>,
    egress_interface: Option<String>,
    tunnel_subnet: Option<String>,
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
    let stream_bind = match stream_bind {
        Some(bind) => Some(bind),
        None if yes => Some("0.0.0.0:443".parse()?),
        None => {
            let value = prompt_string(
                "Optional S1 stream listen address (blank to disable)",
                Some("0.0.0.0:443"),
            )?;
            if value.trim().is_empty() {
                None
            } else {
                Some(value.parse()?)
            }
        }
    };
    let stream_public_endpoint = match stream_public_endpoint {
        Some(value) => {
            validate_client_reachable_endpoint(&value)?;
            Some(value)
        }
        None if stream_bind.is_some() && yes => derive_stream_public_endpoint(&public_endpoint),
        None if stream_bind.is_some() => {
            let value = prompt_string(
                "Optional S1 client-reachable endpoint (blank to disable)",
                derive_stream_public_endpoint(&public_endpoint).as_deref(),
            )?;
            if value.trim().is_empty() {
                None
            } else {
                validate_client_reachable_endpoint(&value)?;
                Some(value)
            }
        }
        None => None,
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
    let interface_name = match interface_name {
        Some(value) => value,
        None if yes => "aptsrv0".to_string(),
        None => prompt_string("Server TUN interface name", Some("aptsrv0"))?,
    };
    let push_routes = if push_routes.is_empty() {
        vec!["0.0.0.0/0".to_string()]
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

    let server_ip = first_usable_ipv4(subnet)?;
    let config = ServerConfig {
        bind,
        public_endpoint,
        runtime_mode: RuntimeMode::Stealth,
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
        tunnel_mtu: 1380,
        egress_interface: Some(egress_interface.clone()),
        enable_ipv4_forwarding: true,
        nat_ipv4: true,
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
    match &config.stream_public_endpoint {
        Some(endpoint) => println!("  • Stream fallback endpoint: {endpoint}"),
        None => println!("  • Stream fallback endpoint: disabled"),
    }
    println!("  • Tunnel subnet: {}", subnet);
    println!("  • Server tunnel IP: {}", config.tunnel_local_ipv4);
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
