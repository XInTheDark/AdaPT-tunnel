use super::*;

pub(super) fn configure_server_network(
    interface_name: &str,
    config: &ResolvedServerConfig,
) -> Result<RouteGuard, RuntimeError> {
    #[cfg(target_os = "linux")]
    {
        configure_server_network_linux(interface_name, config)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface_name;
        let _ = config;
        Err(RuntimeError::UnsupportedPlatform(
            "server runtime is currently implemented for Linux only",
        ))
    }
}

#[cfg(target_os = "linux")]
fn configure_server_network_linux(
    interface_name: &str,
    config: &ResolvedServerConfig,
) -> Result<RouteGuard, RuntimeError> {
    let mut guard = RouteGuard::default();
    ensure_linux_tunnel_route(
        &mut guard,
        interface_name,
        subnet_from(config.tunnel_local_ipv4, config.tunnel_netmask),
    )?;
    if let (Some(tunnel_local_ipv6), Some(tunnel_ipv6_prefix_len)) =
        (config.tunnel_local_ipv6, config.tunnel_ipv6_prefix_len)
    {
        ensure_linux_tunnel_route(
            &mut guard,
            interface_name,
            ipv6_subnet_from(tunnel_local_ipv6, tunnel_ipv6_prefix_len),
        )?;
    }

    if config.enable_ipv4_forwarding {
        run_command("sysctl", &["-w".into(), "net.ipv4.ip_forward=1".into()])?;
    }
    if config.enable_ipv6_forwarding {
        run_command(
            "sysctl",
            &["-w".into(), "net.ipv6.conf.all.forwarding=1".into()],
        )?;
    }

    if config.nat_ipv4 {
        let egress = config.egress_interface.as_ref().ok_or_else(|| {
            RuntimeError::InvalidConfig(
                "nat_ipv4 requires egress_interface to be configured".to_string(),
            )
        })?;
        let subnet = subnet_from(config.tunnel_local_ipv4, config.tunnel_netmask).to_string();
        ensure_firewall_rule(
            "iptables",
            &[
                "-t".into(),
                "nat".into(),
                "POSTROUTING".into(),
                "-s".into(),
                subnet.clone(),
                "-o".into(),
                egress.clone(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        )?;
        ensure_firewall_rule(
            "iptables",
            &[
                "FORWARD".into(),
                "-i".into(),
                interface_name.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )?;
        ensure_firewall_rule(
            "iptables",
            &[
                "FORWARD".into(),
                "-o".into(),
                interface_name.into(),
                "-m".into(),
                "state".into(),
                "--state".into(),
                "RELATED,ESTABLISHED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )?;
    }

    if config.nat_ipv6 {
        let egress = config.egress_interface.as_ref().ok_or_else(|| {
            RuntimeError::InvalidConfig(
                "nat_ipv6 requires egress_interface to be configured".to_string(),
            )
        })?;
        let tunnel_local_ipv6 = config.tunnel_local_ipv6.ok_or_else(|| {
            RuntimeError::InvalidConfig(
                "nat_ipv6 requires tunnel_local_ipv6 to be configured".to_string(),
            )
        })?;
        let tunnel_ipv6_prefix_len = config.tunnel_ipv6_prefix_len.ok_or_else(|| {
            RuntimeError::InvalidConfig(
                "nat_ipv6 requires tunnel_ipv6_prefix_len to be configured".to_string(),
            )
        })?;
        let subnet = ipv6_subnet_from(tunnel_local_ipv6, tunnel_ipv6_prefix_len).to_string();
        ensure_firewall_rule(
            "ip6tables",
            &[
                "-t".into(),
                "nat".into(),
                "POSTROUTING".into(),
                "-s".into(),
                subnet.clone(),
                "-o".into(),
                egress.clone(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        )?;
        ensure_firewall_rule(
            "ip6tables",
            &[
                "FORWARD".into(),
                "-i".into(),
                interface_name.into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )?;
        ensure_firewall_rule(
            "ip6tables",
            &[
                "FORWARD".into(),
                "-o".into(),
                interface_name.into(),
                "-m".into(),
                "state".into(),
                "--state".into(),
                "RELATED,ESTABLISHED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        )?;
    }

    info!(
        interface = interface_name,
        ipv4_forwarding = config.enable_ipv4_forwarding,
        ipv6_forwarding = config.enable_ipv6_forwarding,
        nat_ipv4 = config.nat_ipv4,
        nat_ipv6 = config.nat_ipv6,
        "server network configuration applied"
    );
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn ensure_linux_tunnel_route(
    guard: &mut RouteGuard,
    interface_name: &str,
    subnet: IpNet,
) -> Result<(), RuntimeError> {
    let mut args = Vec::new();
    if subnet.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        "replace".to_string(),
        subnet.to_string(),
        "dev".to_string(),
        interface_name.to_string(),
    ]);
    run_command("ip", &args)?;

    let mut cleanup = vec!["ip".to_string()];
    if subnet.is_ipv6() {
        cleanup.push("-6".to_string());
    }
    cleanup.extend([
        "route".to_string(),
        "del".to_string(),
        subnet.to_string(),
        "dev".to_string(),
        interface_name.to_string(),
    ]);
    guard.cleanup_commands.push(cleanup);
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_firewall_rule(program: &str, rule: &[String]) -> Result<(), RuntimeError> {
    let (prefix, remainder) = if rule.len() >= 2 && rule[0] == "-t" {
        (vec!["-t".to_string(), rule[1].clone()], &rule[2..])
    } else {
        (Vec::new(), rule)
    };
    let (chain, rest) = remainder
        .split_first()
        .ok_or_else(|| RuntimeError::InvalidConfig(format!("{program} rule missing chain")))?;

    let mut check_args = prefix.clone();
    check_args.push("-C".to_string());
    check_args.push(chain.clone());
    check_args.extend(rest.iter().cloned());
    let check = Command::new(program).args(&check_args).output()?;
    if check.status.success() {
        return Ok(());
    }

    let mut add_args = prefix;
    add_args.push("-A".to_string());
    add_args.push(chain.clone());
    add_args.extend(rest.iter().cloned());
    run_command(program, &add_args)
}
