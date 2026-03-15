use crate::{config::ResolvedServerConfig, error::RuntimeError};
use ipnet::IpNet;
#[cfg(any(test, target_os = "linux"))]
use ipnet::Ipv6Net;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Command,
};
#[cfg(target_os = "linux")]
use tracing::info;
use tracing::{debug, warn};

mod client;
mod server;

#[derive(Debug, Default)]
pub struct RouteGuard {
    cleanup_commands: Vec<Vec<String>>,
}

impl RouteGuard {
    pub fn cleanup(&mut self) {
        for error in self.cleanup_errors() {
            warn!(error = %error, "route cleanup command failed");
        }
    }

    pub fn cleanup_errors(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        for command in self.cleanup_commands.iter().rev() {
            if let Some((program, args)) = command.split_first() {
                match Command::new(program).args(args).output() {
                    Ok(output) if output.status.success() => {}
                    Ok(output) => errors.push(format!(
                        "{} {} failed: {}",
                        program,
                        args.join(" "),
                        String::from_utf8_lossy(&output.stderr)
                    )),
                    Err(error) => {
                        errors.push(format!("{} {} failed: {}", program, args.join(" "), error))
                    }
                }
            }
        }
        self.cleanup_commands.clear();
        errors
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[allow(dead_code)]
pub fn configure_client_network(
    interface_name: &str,
    server_addr: SocketAddr,
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    configure_client_network_for_endpoints(interface_name, &[server_addr], routes)
}

pub fn configure_client_network_for_endpoints(
    interface_name: &str,
    server_addrs: &[SocketAddr],
    routes: &[IpNet],
) -> Result<RouteGuard, RuntimeError> {
    client::configure_client_network_for_endpoints(interface_name, server_addrs, routes)
}

pub fn configure_server_network(
    interface_name: &str,
    config: &ResolvedServerConfig,
) -> Result<RouteGuard, RuntimeError> {
    server::configure_server_network(interface_name, config)
}

fn unique_server_ips(server_addrs: &[SocketAddr]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for addr in server_addrs {
        if !ips.contains(&addr.ip()) {
            ips.push(addr.ip());
        }
    }
    ips
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

fn split_default_ipv6_routes() -> [(Ipv6Addr, u8); 2] {
    [
        (Ipv6Addr::UNSPECIFIED, 1),
        (Ipv6Addr::from(1_u128 << 127), 1),
    ]
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

#[cfg(any(test, target_os = "linux"))]
fn ipv6_subnet_from(ip: Ipv6Addr, prefix_len: u8) -> IpNet {
    IpNet::V6(
        Ipv6Net::new(ip, prefix_len)
            .expect("validated IPv6 network")
            .trunc(),
    )
}

#[cfg(target_os = "linux")]
fn host_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedRoute {
    pub interface_name: Option<String>,
    pub gateway: Option<IpAddr>,
}

#[cfg(target_os = "linux")]
fn linux_route_to(ip: IpAddr) -> Result<ResolvedRoute, RuntimeError> {
    let mut args = Vec::<String>::new();
    if ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.push("route".to_string());
    args.push("get".to_string());
    args.push(ip.to_string());
    let output = Command::new("ip").args(&args).output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "ip {} failed: {}",
            args.join(" "),
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
        interface_name: Some(interface_name.ok_or_else(|| {
            RuntimeError::CommandFailed("unable to parse output from ip route get".to_string())
        })?),
        gateway,
    })
}

#[cfg(target_os = "macos")]
fn macos_route_to(ip: IpAddr) -> Result<ResolvedRoute, RuntimeError> {
    let mut args = vec!["-n".to_string(), "get".to_string()];
    if ip.is_ipv6() {
        args.push("-inet6".to_string());
    }
    args.push(ip.to_string());
    let output = Command::new("route").args(&args).output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "route {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interface_name = None;
    let mut gateway = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = value.trim().parse().ok();
        } else if let Some(value) = trimmed.strip_prefix("interface:") {
            interface_name = Some(value.trim().to_string());
        }
    }
    Ok(ResolvedRoute {
        interface_name,
        gateway,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn resolved_route_to(ip: IpAddr) -> Result<ResolvedRoute, RuntimeError> {
    #[cfg(target_os = "linux")]
    {
        linux_route_to(ip)
    }
    #[cfg(target_os = "macos")]
    {
        macos_route_to(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_netmask_is_correct() {
        assert_eq!(ipv4_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn ipv4_subnet_conversion_is_correct() {
        let subnet = subnet_from(Ipv4Addr::new(10, 77, 0, 1), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(subnet.to_string(), "10.77.0.0/24");
    }

    #[test]
    fn ipv6_subnet_conversion_is_correct() {
        let subnet = ipv6_subnet_from("fd77:77::1".parse().unwrap(), 64);
        assert_eq!(subnet.to_string(), "fd77:77::/64");
    }

    #[test]
    fn default_route_is_split_into_two_ipv4_half_routes() {
        let halves = split_default_ipv4_routes();
        assert_eq!(halves[0], (Ipv4Addr::new(0, 0, 0, 0), 1));
        assert_eq!(halves[1], (Ipv4Addr::new(128, 0, 0, 0), 1));
    }

    #[test]
    fn default_route_is_split_into_two_ipv6_half_routes() {
        let halves = split_default_ipv6_routes();
        assert_eq!(halves[0], (Ipv6Addr::UNSPECIFIED, 1));
        assert_eq!(halves[1], (Ipv6Addr::from(1_u128 << 127), 1));
    }
}
