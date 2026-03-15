use super::*;

pub(super) fn find_server_config() -> Option<PathBuf> {
    [
        PathBuf::from("/etc/adapt/server.toml"),
        PathBuf::from("./server.toml"),
        PathBuf::from("./adapt-server/server.toml"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

pub(super) fn prompt_string(label: &str, default: Option<&str>) -> io::Result<String> {
    let mut stdout = io::stdout();
    match default {
        Some(default) => write!(stdout, "{label} [{default}]: ")?,
        None => write!(stdout, "{label}: ")?,
    }
    stdout.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.unwrap_or_default().to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

pub(super) fn prompt_bool(label: &str, default: bool) -> CliResult<bool> {
    let mut stdout = io::stdout();
    loop {
        write!(
            stdout,
            "{} [{}]: ",
            label,
            if default { "Y/n" } else { "y/N" }
        )?;
        stdout.flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Invalid value: enter `y` or `n`"),
        }
    }
}

pub(super) fn prompt_parse<T>(label: &str, default: Option<&str>) -> CliResult<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    loop {
        let value = prompt_string(label, default)?;
        match value.parse() {
            Ok(parsed) => return Ok(parsed),
            Err(error) => eprintln!("Invalid value: {error}"),
        }
    }
}

pub(super) fn prompt_path(label: &str, default: Option<&str>) -> CliResult<PathBuf> {
    Ok(PathBuf::from(prompt_string(label, default)?))
}

pub(super) fn prompt_auth_profile(default: CliAuthProfile) -> CliResult<AuthProfile> {
    let default_label = match default {
        CliAuthProfile::Shared => "shared",
        CliAuthProfile::PerUser => "per-user",
    };
    loop {
        let value = prompt_string(
            "Admission profile for this client (`shared` or `per-user`)",
            Some(default_label),
        )?;
        match value.trim().to_ascii_lowercase().as_str() {
            "shared" | "shared-deployment" => return Ok(AuthProfile::SharedDeployment),
            "per-user" | "peruser" | "user" => return Ok(AuthProfile::PerUser),
            _ => eprintln!("Invalid value: use `shared` or `per-user`"),
        }
    }
}

pub(super) fn validate_client_reachable_endpoint(endpoint: &str) -> CliResult {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(
            "endpoint cannot be empty; use a client-reachable IP:port or DNS name:port".into(),
        );
    }
    if trimmed.contains("example.com") {
        return Err("endpoint still uses the example placeholder; replace it with the server's real public IP:port or DNS name:port".into());
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return Err("endpoint cannot use 0.0.0.0 or another unspecified address; use the server's real public IP:port or DNS name:port".into());
        }
    }
    Ok(())
}

pub(super) fn derive_stream_public_endpoint(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    let (host, _) = trimmed.rsplit_once(':')?;
    Some(format!("{host}:443"))
}

pub(super) fn first_usable_ipv4(subnet: Ipv4Net) -> CliResult<Ipv4Addr> {
    let network = u32::from(subnet.network());
    let broadcast = u32::from(subnet.broadcast());
    if broadcast <= network + 1 {
        return Err("tunnel subnet is too small to allocate a server IP".into());
    }
    Ok(Ipv4Addr::from(network + 1))
}

pub(super) fn next_available_client_ipv4(config: &ServerConfig) -> CliResult<Ipv4Addr> {
    let subnet = subnet_from(config.tunnel_local_ipv4, config.tunnel_netmask)?;
    let mut used = HashSet::new();
    used.insert(config.tunnel_local_ipv4);
    for peer in &config.peers {
        used.insert(peer.tunnel_ipv4);
    }
    let start = u32::from(subnet.network()) + 1;
    let end = u32::from(subnet.broadcast());
    for candidate in (start + 1)..end {
        let ip = Ipv4Addr::from(candidate);
        if !used.contains(&ip) {
            return Ok(ip);
        }
    }
    Err("no free client IPs remain in the configured tunnel subnet".into())
}

pub(super) fn first_usable_ipv6(subnet: Ipv6Net) -> CliResult<Ipv6Addr> {
    let candidate = Ipv6Addr::from(u128::from(subnet.network()).saturating_add(1));
    if subnet.contains(&candidate) {
        Ok(candidate)
    } else {
        Err("IPv6 tunnel subnet is too small to allocate a server IP".into())
    }
}

pub(super) fn next_available_client_ipv6(config: &ServerConfig) -> CliResult<Option<Ipv6Addr>> {
    let (Some(tunnel_local_ipv6), Some(prefix_len)) =
        (config.tunnel_local_ipv6, config.tunnel_ipv6_prefix_len)
    else {
        return Ok(None);
    };
    let subnet = ipv6_subnet_from(tunnel_local_ipv6, prefix_len)?;
    let mut used = HashSet::new();
    used.insert(tunnel_local_ipv6);
    for peer in &config.peers {
        if let Some(tunnel_ipv6) = peer.tunnel_ipv6 {
            used.insert(tunnel_ipv6);
        }
    }
    let mut candidate = u128::from(subnet.network()).saturating_add(2);
    loop {
        let ip = Ipv6Addr::from(candidate);
        if !subnet.contains(&ip) {
            break;
        }
        if !used.contains(&ip) {
            return Ok(Some(ip));
        }
        candidate = candidate.saturating_add(1);
    }
    Err("no free client IPv6 addresses remain in the configured tunnel subnet".into())
}

pub(super) fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,apt_runtime=info"));
    let _ = fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .without_time()
        .try_init();
}

fn subnet_from(ip: Ipv4Addr, netmask: Ipv4Addr) -> CliResult<Ipv4Net> {
    let mask = u32::from(netmask);
    let prefix = mask.count_ones() as u8;
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Ok(Ipv4Net::new(network, prefix)?)
}

fn ipv6_subnet_from(ip: Ipv6Addr, prefix_len: u8) -> CliResult<Ipv6Net> {
    Ok(Ipv6Net::new(ip, prefix_len)?.trunc())
}

pub(super) fn ipv4_netmask(prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    Ipv4Addr::from(mask)
}

pub(super) fn file_spec_path(spec: &str) -> Option<PathBuf> {
    spec.strip_prefix("file:").map(PathBuf::from)
}

pub(super) fn is_path_within(base: &Path, candidate: &Path) -> bool {
    let Ok(base) = base.canonicalize() else {
        return false;
    };
    let Ok(candidate) = candidate.canonicalize() else {
        return false;
    };
    candidate.starts_with(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_public_endpoint_is_rejected() {
        assert!(validate_client_reachable_endpoint("vpn.example.com:51820").is_err());
    }

    #[test]
    fn unspecified_public_endpoint_is_rejected() {
        assert!(validate_client_reachable_endpoint("0.0.0.0:51820").is_err());
    }

    #[test]
    fn explicit_ip_public_endpoint_is_allowed() {
        assert!(validate_client_reachable_endpoint("203.0.113.10:51820").is_ok());
    }

    #[test]
    fn dns_public_endpoint_is_allowed() {
        assert!(validate_client_reachable_endpoint("vpn.my-domain.test:51820").is_ok());
    }

    #[test]
    fn first_ipv6_server_address_comes_from_the_subnet() {
        let subnet: Ipv6Net = "fd77:77::/64".parse().unwrap();
        assert_eq!(
            first_usable_ipv6(subnet).unwrap(),
            "fd77:77::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn next_client_ipv6_skips_used_assignments() {
        let config = ServerConfig {
            bind: "0.0.0.0:51820".parse().unwrap(),
            public_endpoint: "203.0.113.10:51820".to_string(),
            mode: Mode::STEALTH,
            d2_bind: None,
            d2_public_endpoint: None,
            d2_certificate: None,
            d2_private_key: None,
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
            peers: vec![AuthorizedPeerConfig {
                name: "alpha".to_string(),
                auth_profile: AuthProfile::PerUser,
                user_id: Some("alpha".to_string()),
                admission_key: Some("file:/tmp/alpha.key".to_string()),
                client_static_public_key: "file:/tmp/alpha.pub".to_string(),
                tunnel_ipv4: Ipv4Addr::new(10, 77, 0, 2),
                tunnel_ipv6: Some("fd77:77::2".parse().unwrap()),
            }],
        };
        assert_eq!(
            next_available_client_ipv6(&config).unwrap(),
            Some("fd77:77::3".parse::<Ipv6Addr>().unwrap())
        );
    }
}
