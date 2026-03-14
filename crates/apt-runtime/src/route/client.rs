use super::*;

pub(super) fn configure_client_network_for_endpoints(
    interface_name: &str,
    server_addrs: &[SocketAddr],
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    if routes.is_empty() {
        return Ok(RouteGuard::default());
    }
    #[cfg(target_os = "linux")]
    {
        configure_client_network_linux(interface_name, server_addrs, routes)
    }
    #[cfg(target_os = "macos")]
    {
        configure_client_network_macos(interface_name, server_addrs, routes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface_name;
        let _ = server_addrs;
        let _ = routes;
        Err(RuntimeError::UnsupportedPlatform(
            "client route setup is only implemented for Linux and macOS",
        ))
    }
}

#[cfg(target_os = "linux")]
fn configure_client_network_linux(
    interface_name: &str,
    server_addrs: &[SocketAddr],
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    let mut guard = RouteGuard::default();
    if routes.iter().any(is_default_route) {
        for server_ip in unique_server_ips(server_addrs) {
            let route = linux_route_to(server_ip)?;
            let mut args = Vec::new();
            if server_ip.is_ipv6() {
                args.push("-6".to_string());
            }
            args.extend([
                "route".to_string(),
                "replace".to_string(),
                host_prefix(server_ip),
            ]);
            if let Some(gateway) = route.gateway {
                args.push("via".to_string());
                args.push(gateway.to_string());
            }
            args.push("dev".to_string());
            args.push(route.interface_name.clone());
            run_command("ip", &args)?;

            let mut cleanup = Vec::new();
            if server_ip.is_ipv6() {
                cleanup.push("-6".to_string());
            }
            cleanup.extend([
                "route".to_string(),
                "del".to_string(),
                host_prefix(server_ip),
            ]);
            guard
                .cleanup_commands
                .push(std::iter::once("ip".to_string()).chain(cleanup).collect());
        }
    }

    for route in routes {
        match route {
            IpNet::V4(route_v4) if route_v4.prefix_len() == 0 => {
                apply_linux_route(
                    &mut guard,
                    false,
                    vec!["default".to_string()],
                    interface_name,
                )?;
            }
            IpNet::V4(route_v4) => {
                apply_linux_route(
                    &mut guard,
                    false,
                    vec![route_v4.to_string()],
                    interface_name,
                )?;
            }
            IpNet::V6(route_v6) if route_v6.prefix_len() == 0 => {
                apply_linux_route(
                    &mut guard,
                    true,
                    vec!["default".to_string()],
                    interface_name,
                )?;
            }
            IpNet::V6(route_v6) => {
                apply_linux_route(&mut guard, true, vec![route_v6.to_string()], interface_name)?;
            }
        }
    }
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn apply_linux_route(
    guard: &mut RouteGuard,
    ipv6: bool,
    target: Vec<String>,
    interface_name: &str,
) -> Result<(), RuntimeError> {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "replace".to_string()]);
    args.extend(target.clone());
    args.push("dev".to_string());
    args.push(interface_name.to_string());
    run_command("ip", &args)?;

    let mut cleanup = vec!["ip".to_string()];
    if ipv6 {
        cleanup.push("-6".to_string());
    }
    cleanup.extend(["route".to_string(), "del".to_string()]);
    cleanup.extend(target);
    cleanup.push("dev".to_string());
    cleanup.push(interface_name.to_string());
    guard.cleanup_commands.push(cleanup);
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_client_network_macos(
    interface_name: &str,
    server_addrs: &[SocketAddr],
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    let mut guard = RouteGuard::default();
    if routes.iter().any(is_default_route) {
        for server_ip in unique_server_ips(server_addrs) {
            let route = macos_route_to(server_ip)?;
            let gateway = route.gateway.ok_or_else(|| {
                RuntimeError::CommandFailed(
                    "macOS default route lookup returned no gateway".to_string(),
                )
            })?;
            let mut args = vec!["-n".to_string(), "add".to_string()];
            if server_ip.is_ipv6() {
                args.push("-inet6".to_string());
            }
            args.push("-host".to_string());
            args.push(server_ip.to_string());
            args.push(gateway.to_string());
            run_command("route", &args)?;

            let mut cleanup = vec!["route".to_string(), "-n".to_string(), "delete".to_string()];
            if server_ip.is_ipv6() {
                cleanup.push("-inet6".to_string());
            }
            cleanup.push("-host".to_string());
            cleanup.push(server_ip.to_string());
            guard.cleanup_commands.push(cleanup);
        }
    }

    for route in routes {
        match route {
            IpNet::V4(route_v4) if route_v4.prefix_len() == 0 => {
                for (network, prefix_len) in split_default_ipv4_routes() {
                    apply_macos_ipv4_route(
                        &mut guard,
                        interface_name,
                        network.to_string(),
                        prefix_len,
                    )?;
                }
            }
            IpNet::V4(route_v4) => {
                apply_macos_ipv4_route(
                    &mut guard,
                    interface_name,
                    route_v4.network().to_string(),
                    route_v4.prefix_len(),
                )?;
            }
            IpNet::V6(route_v6) if route_v6.prefix_len() == 0 => {
                for (network, prefix_len) in split_default_ipv6_routes() {
                    apply_macos_ipv6_route(
                        &mut guard,
                        interface_name,
                        format!("{network}/{prefix_len}"),
                    )?;
                }
            }
            IpNet::V6(route_v6) => {
                apply_macos_ipv6_route(&mut guard, interface_name, route_v6.to_string())?;
            }
        }
    }
    Ok(guard)
}

#[cfg(target_os = "macos")]
fn apply_macos_ipv4_route(
    guard: &mut RouteGuard,
    interface_name: &str,
    network: String,
    prefix_len: u8,
) -> Result<(), RuntimeError> {
    let netmask = ipv4_netmask(prefix_len).to_string();
    run_command(
        "route",
        &[
            "-n".into(),
            "add".into(),
            "-net".into(),
            network.clone(),
            "-netmask".into(),
            netmask.clone(),
            "-interface".into(),
            interface_name.into(),
        ],
    )?;
    guard.cleanup_commands.push(vec![
        "route".into(),
        "-n".into(),
        "delete".into(),
        "-net".into(),
        network,
        "-netmask".into(),
        netmask,
    ]);
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_ipv6_route(
    guard: &mut RouteGuard,
    interface_name: &str,
    network: String,
) -> Result<(), RuntimeError> {
    run_command(
        "route",
        &[
            "-n".into(),
            "add".into(),
            "-inet6".into(),
            "-net".into(),
            network.clone(),
            "-interface".into(),
            interface_name.into(),
        ],
    )?;
    guard.cleanup_commands.push(vec![
        "route".into(),
        "-n".into(),
        "delete".into(),
        "-inet6".into(),
        "-net".into(),
        network,
    ]);
    Ok(())
}
