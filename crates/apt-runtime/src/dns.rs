use crate::error::RuntimeError;
use std::{env, net::IpAddr, path::Path, process::Command};
use tracing::{debug, info};

#[derive(Debug, Default)]
pub struct DnsGuard {
    cleanup_commands: Vec<Vec<String>>,
}

impl DnsGuard {
    pub fn cleanup(&mut self) {
        for command in self.cleanup_commands.iter().rev() {
            if let Some((program, args)) = command.split_first() {
                let _ = Command::new(program).args(args).output();
            }
        }
        self.cleanup_commands.clear();
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn configure_client_dns(
    interface_name: &str,
    dns_servers: &[IpAddr],
) -> Result<DnsGuard, RuntimeError> {
    if dns_servers.is_empty() {
        return Ok(DnsGuard::default());
    }
    #[cfg(target_os = "linux")]
    {
        configure_client_dns_linux(interface_name, dns_servers)
    }
    #[cfg(target_os = "macos")]
    {
        configure_client_dns_macos(interface_name, dns_servers)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface_name;
        let _ = dns_servers;
        Ok(DnsGuard::default())
    }
}

#[cfg(target_os = "linux")]
fn configure_client_dns_linux(
    interface_name: &str,
    dns_servers: &[IpAddr],
) -> Result<DnsGuard, RuntimeError> {
    if !command_in_path("resolvectl") {
        return Err(RuntimeError::UnsupportedPlatform(
            "automatic DNS configuration on Linux requires resolvectl/systemd-resolved",
        ));
    }

    let mut guard = DnsGuard::default();
    let mut dns_args = vec!["dns".to_string(), interface_name.to_string()];
    dns_args.extend(dns_servers.iter().map(ToString::to_string));
    run_command("resolvectl", &dns_args)?;
    run_command(
        "resolvectl",
        &[
            "domain".to_string(),
            interface_name.to_string(),
            "~.".to_string(),
        ],
    )?;
    guard.cleanup_commands.push(vec![
        "resolvectl".to_string(),
        "revert".to_string(),
        interface_name.to_string(),
    ]);

    info!(
        interface = interface_name,
        dns_servers = ?dns_servers,
        "applied pushed DNS settings with resolvectl"
    );
    Ok(guard)
}

#[cfg(target_os = "macos")]
fn configure_client_dns_macos(
    interface_name: &str,
    dns_servers: &[IpAddr],
) -> Result<DnsGuard, RuntimeError> {
    if !command_in_path("networksetup") {
        return Err(RuntimeError::UnsupportedPlatform(
            "automatic DNS configuration on macOS requires networksetup",
        ));
    }

    let default_interface = macos_default_interface()?;
    let service = macos_service_for_device(&default_interface)?.ok_or_else(|| {
        RuntimeError::CommandFailed(format!(
            "unable to map default macOS network device `{default_interface}` to a network service"
        ))
    })?;
    let original_dns = macos_dns_servers(&service)?;

    let mut guard = DnsGuard::default();
    let mut set_args = vec!["-setdnsservers".to_string(), service.clone()];
    set_args.extend(dns_servers.iter().map(ToString::to_string));
    run_command("networksetup", &set_args)?;

    let cleanup_args = if original_dns.is_empty() {
        vec![
            "networksetup".to_string(),
            "-setdnsservers".to_string(),
            service.clone(),
            "empty".to_string(),
        ]
    } else {
        let mut args = vec![
            "networksetup".to_string(),
            "-setdnsservers".to_string(),
            service.clone(),
        ];
        args.extend(original_dns.iter().map(ToString::to_string));
        args
    };
    guard.cleanup_commands.push(cleanup_args);

    info!(
        tunnel_interface = interface_name,
        service = service,
        dns_servers = ?dns_servers,
        "applied pushed DNS settings on the primary macOS network service"
    );
    Ok(guard)
}

#[cfg(target_os = "macos")]
fn macos_default_interface() -> Result<String, RuntimeError> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "route -n get default failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    parse_macos_default_interface(&String::from_utf8_lossy(&output.stdout)).ok_or_else(|| {
        RuntimeError::CommandFailed(
            "unable to parse the default macOS interface from `route -n get default`".to_string(),
        )
    })
}

#[cfg(target_os = "macos")]
fn macos_service_for_device(device: &str) -> Result<Option<String>, RuntimeError> {
    let output = Command::new("networksetup")
        .arg("-listnetworkserviceorder")
        .output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "networksetup -listnetworkserviceorder failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(parse_macos_service_for_device(
        &String::from_utf8_lossy(&output.stdout),
        device,
    ))
}

#[cfg(target_os = "macos")]
fn macos_dns_servers(service: &str) -> Result<Vec<IpAddr>, RuntimeError> {
    let output = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()?;
    if !output.status.success() {
        return Err(RuntimeError::CommandFailed(format!(
            "networksetup -getdnsservers {} failed: {}",
            service,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    parse_macos_dns_servers(&String::from_utf8_lossy(&output.stdout))
}

fn command_in_path(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).exists();
    }
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).any(|dir| dir.join(program).exists()))
        .unwrap_or(false)
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

#[cfg(target_os = "macos")]
fn parse_macos_default_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|value| value.trim().to_string())
    })
}

#[cfg(target_os = "macos")]
fn parse_macos_service_for_device(output: &str, device: &str) -> Option<String> {
    let mut current_service = None::<String>;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("Device:") {
            let Some(service) = current_service.as_ref() else {
                continue;
            };
            let Some(device_fragment) = trimmed.split("Device: ").nth(1) else {
                continue;
            };
            let candidate = device_fragment
                .split(')')
                .next()
                .map(str::trim)
                .unwrap_or_default();
            if candidate == device {
                return Some(service.clone());
            }
            continue;
        }
        if trimmed.starts_with('(') && !trimmed.contains("Hardware Port:") {
            if let Some((_, service)) = trimmed.split_once(')') {
                current_service = Some(service.trim().to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn parse_macos_dns_servers(output: &str) -> Result<Vec<IpAddr>, RuntimeError> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed.contains("There aren't any DNS Servers set") {
        return Ok(Vec::new());
    }
    trimmed
        .lines()
        .map(|line| {
            line.trim().parse::<IpAddr>().map_err(|error| {
                RuntimeError::CommandFailed(format!(
                    "unexpected output from networksetup -getdnsservers: {error}"
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::{
        parse_macos_default_interface, parse_macos_dns_servers, parse_macos_service_for_device,
    };

    #[cfg(target_os = "macos")]
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_default_interface() {
        let output = r#"
route to: default
destination: default
mask: default
gateway: 192.0.2.1
interface: en0
flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"#;
        assert_eq!(
            parse_macos_default_interface(output).as_deref(),
            Some("en0")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_service_order_for_device() {
        let output = r#"
An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)
"#;
        assert_eq!(
            parse_macos_service_for_device(output, "en0").as_deref(),
            Some("Wi-Fi")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_existing_macos_dns_servers() {
        let parsed = parse_macos_dns_servers("1.1.1.1\n1.0.0.1\n").unwrap();
        assert_eq!(
            parsed,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_absent_macos_dns_servers() {
        let parsed =
            parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n").unwrap();
        assert!(parsed.is_empty());
    }
}
