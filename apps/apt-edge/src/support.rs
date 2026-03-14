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

pub(super) fn ipv4_netmask(prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    Ipv4Addr::from(mask)
}

#[cfg(test)]
mod tests {
    use super::validate_client_reachable_endpoint;

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
}
