use super::*;
use crate::startup::{install_and_enable_systemd_service, systemd_is_available};

#[allow(clippy::too_many_arguments)]
pub(super) fn init_server(
    out_dir: Option<PathBuf>,
    bind: Option<SocketAddr>,
    public_endpoint: Option<String>,
    authority: Option<String>,
    endpoint_id: Option<String>,
    egress_interface: Option<String>,
    tunnel_subnet: Option<String>,
    tunnel_subnet6: Option<String>,
    interface_name: Option<String>,
    push_routes: Vec<String>,
    dns_servers: Vec<IpAddr>,
    install_systemd_service: bool,
    yes: bool,
) -> CliResult {
    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("/etc/adapt"));
    let bind = match bind {
        Some(bind) => bind,
        None if yes => "0.0.0.0:443".parse()?,
        None => prompt_parse("H2 listen address", Some("0.0.0.0:443"))?,
    };
    let public_endpoint = resolve_public_endpoint(public_endpoint, bind, yes)?;
    let authority = resolve_authority(authority, &public_endpoint, yes)?;
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
    let install_systemd_service = if install_systemd_service {
        true
    } else if yes || !systemd_is_available() {
        false
    } else {
        prompt_bool(
            "Install and start a systemd service so the server runs on boot",
            false,
        )?
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
    write_h2_tls_material(&out_dir, &public_endpoint, &authority)?;
    fs::create_dir_all(out_dir.join("bundles"))?;

    let server_ip = first_usable_ipv4(subnet)?;
    let server_ipv6 = subnet6
        .as_ref()
        .copied()
        .map(first_usable_ipv6)
        .transpose()?;
    let config = ServerConfig {
        bind,
        public_endpoint,
        authority,
        certificate: "file:./server-certificate.pem".to_string(),
        private_key: "file:./server-private-key.pem".to_string(),
        deployment_strength: V2DeploymentStrength::SelfContained,
        mode: Mode::STEALTH,
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
    let startup_service = if install_systemd_service {
        Some(install_and_enable_systemd_service(&config_path)?)
    } else {
        None
    };

    println!("\nAPT H2 server setup complete.\n");
    println!("Created:");
    println!("  • {}", config_path.display());
    println!("  • {}/shared-admission.key", out_dir.display());
    println!("  • {}/server-static-private.key", out_dir.display());
    println!("  • {}/server-static-public.key", out_dir.display());
    println!("  • {}/cookie.key", out_dir.display());
    println!("  • {}/ticket.key", out_dir.display());
    println!("  • {}/server-certificate.pem", out_dir.display());
    println!("  • {}/server-private-key.pem", out_dir.display());
    println!(
        "  • {}/bundles/ (single-file client bundles)",
        out_dir.display()
    );
    println!("\nServer summary:");
    println!("  • H2 bind: {bind}");
    println!(
        "  • Public endpoint for clients: {}",
        config.public_endpoint
    );
    println!("  • HTTP authority: {}", config.authority);
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
    match startup_service {
        Some(service) => {
            println!("  2. Startup service installed and started:");
            println!("     sudo systemctl status {}", service.service_name);
            println!("     sudo journalctl -u {} -f", service.service_name);
            println!("     unit file: {}", service.service_path.display());
        }
        None => {
            println!("  2. Start the server:");
            println!(
                "     sudo apt-edge start --config {}",
                config_path.display()
            );
        }
    }
    Ok(())
}

pub(super) fn install_systemd_service_for_server(config: Option<PathBuf>, yes: bool) -> CliResult {
    let config_path = match config {
        Some(path) => path,
        None => match find_server_config() {
            Some(path) => path,
            None if yes => {
                return Err(
                    "could not find a server config; pass --config or run `apt-edge init` first"
                        .into(),
                );
            }
            None => prompt_path("Server config path", Some("/etc/adapt/server.toml"))?,
        },
    };
    let _server_config = ServerConfig::load(&config_path)?;
    let startup_service = install_and_enable_systemd_service(&config_path)?;

    println!("\nStartup service installed or refreshed.\n");
    println!("Validated server config:");
    println!("  • {}", config_path.display());
    println!("Systemd unit:");
    println!("  • {}", startup_service.service_name);
    println!("  • {}", startup_service.service_path.display());
    println!("\nThe service has been enabled and started/restarted immediately.");
    println!("Manage it with:");
    println!("  sudo systemctl status {}", startup_service.service_name);
    println!("  sudo journalctl -u {} -f", startup_service.service_name);
    Ok(())
}

fn resolve_public_endpoint(
    public_endpoint: Option<String>,
    bind: SocketAddr,
    yes: bool,
) -> CliResult<String> {
    match public_endpoint {
        Some(value) => {
            validate_client_reachable_endpoint(&value)?;
            Ok(value)
        }
        None if yes && !bind.ip().is_unspecified() => {
            let value = bind.to_string();
            validate_client_reachable_endpoint(&value)?;
            Ok(value)
        }
        None if yes => Err(
            "--public-endpoint is required when using --yes with an unspecified bind address"
                .into(),
        ),
        None => loop {
            let value = prompt_string("Client-reachable public IP/DNS and port", None)?;
            match validate_client_reachable_endpoint(&value) {
                Ok(()) => break Ok(value),
                Err(error) => eprintln!("Invalid value: {error}"),
            }
        },
    }
}

fn resolve_authority(
    authority: Option<String>,
    public_endpoint: &str,
    yes: bool,
) -> CliResult<String> {
    match authority {
        Some(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        Some(_) => Err("--authority cannot be empty".into()),
        None if yes => derive_authority(public_endpoint),
        None => {
            let default = derive_authority(public_endpoint)?;
            let value = prompt_string("HTTP authority / host name", Some(&default))?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err("authority cannot be empty".into())
            } else {
                Ok(trimmed.to_string())
            }
        }
    }
}

fn derive_authority(public_endpoint: &str) -> CliResult<String> {
    let trimmed = public_endpoint.trim();
    if trimmed.is_empty() {
        return Err("public endpoint cannot be empty".into());
    }
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        return Ok(socket_addr.ip().to_string());
    }
    trimmed
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches('[').trim_matches(']').to_string())
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| {
            format!("unable to derive authority from public endpoint `{trimmed}`").into()
        })
}

fn write_h2_tls_material(out_dir: &Path, public_endpoint: &str, authority: &str) -> CliResult {
    let mut names = vec![authority.to_string()];
    for name in h2_certificate_subject_alt_names(public_endpoint) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let identity = generate_d2_tls_identity(names)?;
    write_secret_file(
        &out_dir.join("server-certificate.pem"),
        identity.certificate_pem.as_bytes(),
    )?;
    write_secret_file(
        &out_dir.join("server-private-key.pem"),
        identity.private_key_pem.as_bytes(),
    )?;
    Ok(())
}

fn h2_certificate_subject_alt_names(endpoint: &str) -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(host) = endpoint_host(endpoint) {
        if !names.contains(&host) {
            names.push(host);
        }
    }
    names
}

fn endpoint_host(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        return Some(socket_addr.ip().to_string());
    }
    let (host, _) = trimmed.rsplit_once(':')?;
    Some(host.trim_matches('[').trim_matches(']').to_string())
}
