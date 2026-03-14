use crate::{config::ResolvedServerConfig, error::RuntimeError};
use ipnet::IpNet;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
};
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::info;

#[derive(Debug, Default)]
pub struct RouteGuard {
    cleanup_commands: Vec<Vec<String>>,
}

impl RouteGuard {
    pub fn cleanup(&mut self) {
        for command in self.cleanup_commands.iter().rev() {
            if let Some((program, args)) = command.split_first() {
                let _ = Command::new(program).args(args).status();
            }
        }
        self.cleanup_commands.clear();
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn configure_client_network(
    interface_name: &str,
    server_addr: SocketAddr,
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    if routes.is_empty() {
        return Ok(RouteGuard::default());
    }
    #[cfg(target_os = "linux")]
    {
        configure_client_network_linux(interface_name, server_addr, routes)
    }
    #[cfg(target_os = "macos")]
    {
        configure_client_network_macos(interface_name, server_addr, routes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface_name;
        let _ = server_addr;
        let _ = routes;
        Err(RuntimeError::UnsupportedPlatform(
            "client route setup is only implemented for Linux and macOS",
        ))
    }
}

pub fn configure_server_network(
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
fn configure_client_network_linux(
    interface_name: &str,
    server_addr: SocketAddr,
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    let mut guard = RouteGuard::default();
    if routes.iter().any(is_default_route) {
        let server_ip = server_addr.ip();
        let route = linux_route_to(server_ip)?;
        let mut args = vec![
            "route".to_string(),
            "replace".to_string(),
            host_prefix(server_ip),
        ];
        if let Some(gateway) = route.gateway {
            args.push("via".to_string());
            args.push(gateway.to_string());
        }
        args.push("dev".to_string());
        args.push(route.interface_name.clone());
        run_command("ip", &args)?;
        guard.cleanup_commands.push(vec![
            "ip".to_string(),
            "route".to_string(),
            "del".to_string(),
            host_prefix(server_ip),
        ]);
    }

    for route in routes {
        if let IpNet::V4(route_v4) = route {
            if route_v4.prefix_len() == 0 {
                run_command(
                    "ip",
                    &[
                        "route".into(),
                        "replace".into(),
                        "default".into(),
                        "dev".into(),
                        interface_name.into(),
                    ],
                )?;
                guard.cleanup_commands.push(vec![
                    "ip".into(),
                    "route".into(),
                    "del".into(),
                    "default".into(),
                    "dev".into(),
                    interface_name.into(),
                ]);
            } else {
                run_command(
                    "ip",
                    &[
                        "route".into(),
                        "replace".into(),
                        route_v4.to_string(),
                        "dev".into(),
                        interface_name.into(),
                    ],
                )?;
                guard.cleanup_commands.push(vec![
                    "ip".into(),
                    "route".into(),
                    "del".into(),
                    route_v4.to_string(),
                    "dev".into(),
                    interface_name.into(),
                ]);
            }
        }
    }
    Ok(guard)
}

#[cfg(target_os = "macos")]
fn configure_client_network_macos(
    interface_name: &str,
    server_addr: SocketAddr,
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    let mut guard = RouteGuard::default();
    if routes.iter().any(is_default_route) {
        let server_ip = server_addr.ip();
        let route = macos_route_to(server_ip)?;
        let gateway = route.gateway.ok_or_else(|| {
            RuntimeError::CommandFailed(
                "macOS default route lookup returned no gateway".to_string(),
            )
        })?;
        run_command(
            "route",
            &[
                "-n".into(),
                "add".into(),
                "-host".into(),
                server_ip.to_string(),
                gateway.to_string(),
            ],
        )?;
        guard.cleanup_commands.push(vec![
            "route".into(),
            "-n".into(),
            "delete".into(),
            "-host".into(),
            server_ip.to_string(),
        ]);
    }

    for route in routes {
        match route {
            IpNet::V4(route_v4) if route_v4.prefix_len() == 0 => {
                for (network, prefix_len) in split_default_ipv4_routes() {
                    let netmask = ipv4_netmask(prefix_len).to_string();
                    run_command(
                        "route",
                        &[
                            "-n".into(),
                            "add".into(),
                            "-net".into(),
                            network.to_string(),
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
                        network.to_string(),
                        "-netmask".into(),
                        netmask,
                    ]);
                }
            }
            IpNet::V4(route_v4) => {
                run_command(
                    "route",
                    &[
                        "-n".into(),
                        "add".into(),
                        "-net".into(),
                        route_v4.addr().to_string(),
                        "-netmask".into(),
                        ipv4_netmask(route_v4.prefix_len()).to_string(),
                        "-interface".into(),
                        interface_name.into(),
                    ],
                )?;
                guard.cleanup_commands.push(vec![
                    "route".into(),
                    "-n".into(),
                    "delete".into(),
                    "-net".into(),
                    route_v4.addr().to_string(),
                    "-netmask".into(),
                    ipv4_netmask(route_v4.prefix_len()).to_string(),
                ]);
            }
            IpNet::V6(_) => {}
        }
    }
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn configure_server_network_linux(
    interface_name: &str,
    config: &ResolvedServerConfig,
) -> Result<RouteGuard, RuntimeError> {
    let mut guard = RouteGuard::default();
    if config.enable_ipv4_forwarding {
        run_command("sysctl", &["-w".into(), "net.ipv4.ip_forward=1".into()])?;
    }

    if config.nat_ipv4 {
        let egress = config.egress_interface.as_ref().ok_or_else(|| {
            RuntimeError::InvalidConfig(
                "nat_ipv4 requires egress_interface to be configured".to_string(),
            )
        })?;
        let subnet = subnet_from(config.tunnel_local_ipv4, config.tunnel_netmask).to_string();
        ensure_iptables_rule(&[
            "-t".into(),
            "nat".into(),
            "POSTROUTING".into(),
            "-s".into(),
            subnet.clone(),
            "-o".into(),
            egress.clone(),
            "-j".into(),
            "MASQUERADE".into(),
        ])?;
        ensure_iptables_rule(&[
            "FORWARD".into(),
            "-i".into(),
            interface_name.into(),
            "-j".into(),
            "ACCEPT".into(),
        ])?;
        ensure_iptables_rule(&[
            "FORWARD".into(),
            "-o".into(),
            interface_name.into(),
            "-m".into(),
            "state".into(),
            "--state".into(),
            "RELATED,ESTABLISHED".into(),
            "-j".into(),
            "ACCEPT".into(),
        ])?;
    }

    info!(
        interface = interface_name,
        "server network configuration applied"
    );
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn host_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ResolvedRoute {
    interface_name: String,
    gateway: Option<IpAddr>,
}

#[cfg(target_os = "linux")]
fn linux_route_to(ip: IpAddr) -> Result<ResolvedRoute, RuntimeError> {
    let output = Command::new("ip")
        .args(["route", "get", &ip.to_string()])
        .output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "ip route get {} failed: {}",
            ip,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let tokens: Vec<&str> = stdout.split_whitespace().collect();
    let mut interface_name = None;
    let mut gateway = None;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index] {
            "dev" if index + 1 < tokens.len() => {
                interface_name = Some(tokens[index + 1].to_string())
            }
            "via" if index + 1 < tokens.len() => gateway = tokens[index + 1].parse().ok(),
            _ => {}
        }
        index += 1;
    }
    Ok(ResolvedRoute {
        interface_name: interface_name.ok_or_else(|| {
            RuntimeError::CommandFailed("unable to parse output from ip route get".to_string())
        })?,
        gateway,
    })
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct ResolvedRoute {
    gateway: Option<IpAddr>,
}

#[cfg(target_os = "macos")]
fn macos_route_to(ip: IpAddr) -> Result<ResolvedRoute, RuntimeError> {
    let output = Command::new("route")
        .args(["-n", "get", &ip.to_string()])
        .output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "route -n get {} failed: {}",
            ip,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gateway = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = value.trim().parse().ok();
        }
    }
    Ok(ResolvedRoute { gateway })
}

#[cfg(target_os = "linux")]
fn ensure_iptables_rule(rule: &[String]) -> Result<(), RuntimeError> {
    let (prefix, remainder) = if rule.len() >= 2 && rule[0] == "-t" {
        (vec!["-t".to_string(), rule[1].clone()], &rule[2..])
    } else {
        (Vec::new(), rule)
    };
    let (chain, rest) = remainder
        .split_first()
        .ok_or_else(|| RuntimeError::InvalidConfig("iptables rule missing chain".to_string()))?;

    let mut check_args = prefix.clone();
    check_args.push("-C".to_string());
    check_args.push(chain.clone());
    check_args.extend(rest.iter().cloned());
    let check = Command::new("iptables").args(&check_args).output()?;
    if check.status.success() {
        return Ok(());
    }
    let mut add_args = prefix;
    add_args.push("-A".to_string());
    add_args.push(chain.clone());
    add_args.extend(rest.iter().cloned());
    run_command("iptables", &add_args)
}

fn run_command(program: &str, args: &[String]) -> Result<(), RuntimeError> {
    debug!(program, args = ?args, "running system command");
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(RuntimeError::CommandFailed(format!(
        "{} {} failed: {}",
        program,
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn ipv4_netmask(prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    };
    Ipv4Addr::from(mask)
}

#[cfg(any(test, target_os = "linux"))]
fn subnet_from(ip: Ipv4Addr, netmask: Ipv4Addr) -> IpNet {
    let mask = u32::from(netmask);
    let prefix = mask.count_ones() as u8;
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    IpNet::new(network.into(), prefix).expect("validated IPv4 network")
}

fn is_default_route(route: &IpNet) -> bool {
    match route {
        IpNet::V4(route_v4) => route_v4.prefix_len() == 0,
        IpNet::V6(route_v6) => route_v6.prefix_len() == 0,
    }
}

fn split_default_ipv4_routes() -> [(Ipv4Addr, u8); 2] {
    [
        (Ipv4Addr::new(0, 0, 0, 0), 1),
        (Ipv4Addr::new(128, 0, 0, 0), 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_netmask_is_correct() {
        assert_eq!(ipv4_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn subnet_conversion_is_correct() {
        let subnet = subnet_from(Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(subnet.to_string(), "10.77.0.0/24");
    }

    #[test]
    fn default_route_is_split_into_two_half_routes() {
        let halves = split_default_ipv4_routes();
        assert_eq!(halves[0], (Ipv4Addr::new(0, 0, 0, 0), 1));
        assert_eq!(halves[1], (Ipv4Addr::new(128, 0, 0, 0), 1));
    }
}
