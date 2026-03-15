use super::*;
use crate::config::ResolvedClientConfig;
#[cfg(target_os = "macos")]
use crate::dns::macos_service_for_device;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::route::resolved_route_to;
use sha2::{Digest, Sha256};
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{fs, path::Path};

pub(crate) fn discover_client_network_context(
    config: &ResolvedClientConfig,
) -> LocalNetworkContext {
    let public_route = configured_public_route_hint(config);

    #[cfg(target_os = "linux")]
    {
        return discover_client_network_context_linux(config, public_route);
    }
    #[cfg(target_os = "macos")]
    {
        return discover_client_network_context_macos(config, public_route);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        build_client_network_context(config.endpoint_id.as_str(), &public_route.0)
    }
}

pub(crate) fn build_client_network_context(
    endpoint_label: &str,
    public_route_label: &str,
) -> LocalNetworkContext {
    canonicalize_local_network_context(&LocalNetworkContext {
        link_type: LinkType::Unknown,
        gateway: GatewayFingerprint(hash_label("default-gateway")),
        local_label: endpoint_label.trim().to_string(),
        public_route: PublicRouteHint(public_route_label.to_string()),
    })
}

pub(crate) fn canonicalize_local_network_context(
    context: &LocalNetworkContext,
) -> LocalNetworkContext {
    LocalNetworkContext {
        link_type: canonicalize_link_type(&context.link_type),
        gateway: GatewayFingerprint(normalize_token(&context.gateway.0)),
        local_label: normalize_token(&context.local_label),
        public_route: PublicRouteHint(normalize_token(&context.public_route.0)),
    }
}

pub(crate) fn local_network_profile_key(context: &LocalNetworkContext) -> String {
    let context = canonicalize_local_network_context(context);
    let mut hasher = Sha256::new();
    hasher.update(b"adapt-local-network-context-v1\n");
    hasher.update(link_type_key(&context.link_type).as_bytes());
    hasher.update(b"\n");
    hasher.update(context.gateway.0.as_bytes());
    hasher.update(b"\n");
    hasher.update(context.local_label.as_bytes());
    hasher.update(b"\n");
    hasher.update(context.public_route.0.as_bytes());
    hasher.update(b"\n");
    hex_digest(hasher.finalize().as_slice())
}

#[cfg(target_os = "linux")]
fn discover_client_network_context_linux(
    config: &ResolvedClientConfig,
    public_route: PublicRouteHint,
) -> LocalNetworkContext {
    let route = resolved_route_to(config.server_addr.ip()).ok();
    let interface_name = route
        .as_ref()
        .and_then(|route| route.interface_name.as_deref())
        .or(config.interface_name.as_deref());
    let link_type = interface_name
        .map(classify_linux_link_type)
        .unwrap_or(LinkType::Unknown);
    let local_label = interface_name
        .and_then(linux_wifi_ssid_hash)
        .unwrap_or_else(|| interface_name.unwrap_or("default").to_ascii_lowercase());
    let gateway_source = route
        .as_ref()
        .and_then(|route| route.gateway.map(|gateway| gateway.to_string()))
        .or_else(|| interface_name.map(str::to_string))
        .unwrap_or_else(|| "default-gateway".to_string());
    canonicalize_local_network_context(&LocalNetworkContext {
        link_type,
        gateway: GatewayFingerprint(hash_label(&gateway_source)),
        local_label,
        public_route,
    })
}

#[cfg(target_os = "macos")]
fn discover_client_network_context_macos(
    config: &ResolvedClientConfig,
    public_route: PublicRouteHint,
) -> LocalNetworkContext {
    let route = resolved_route_to(config.server_addr.ip()).ok();
    let interface_name = route
        .as_ref()
        .and_then(|route| route.interface_name.clone())
        .or_else(|| config.interface_name.clone());
    let service_name = interface_name
        .as_deref()
        .and_then(|device| macos_service_for_device(device).ok().flatten());
    let link_type = classify_macos_link_type(interface_name.as_deref(), service_name.as_deref());
    let local_label = interface_name
        .as_deref()
        .and_then(macos_wifi_network_hash)
        .or_else(|| {
            service_name
                .as_deref()
                .map(hash_label)
                .or_else(|| interface_name.as_deref().map(hash_label))
        })
        .unwrap_or_else(|| hash_label(config.endpoint_id.as_str()));
    let gateway_source = route
        .as_ref()
        .and_then(|route| route.gateway.map(|gateway| gateway.to_string()))
        .or(service_name.clone())
        .or(interface_name.clone())
        .unwrap_or_else(|| "default-gateway".to_string());
    canonicalize_local_network_context(&LocalNetworkContext {
        link_type,
        gateway: GatewayFingerprint(hash_label(&gateway_source)),
        local_label,
        public_route,
    })
}

fn configured_public_route_hint(config: &ResolvedClientConfig) -> PublicRouteHint {
    let mut endpoints = vec![format!("d1:{}", canonical_socket_addr(config.server_addr))];
    if let Some(d2) = &config.d2 {
        endpoints.push(format!(
            "d2:{}@{}",
            d2.endpoint.server_name.to_ascii_lowercase(),
            canonical_socket_addr(d2.endpoint.addr)
        ));
    }
    endpoints.sort();
    endpoints.dedup();
    PublicRouteHint(endpoints.join("|"))
}

fn canonical_socket_addr(addr: std::net::SocketAddr) -> String {
    match addr {
        std::net::SocketAddr::V4(addr) => format!("{}:{}", addr.ip(), addr.port()),
        std::net::SocketAddr::V6(addr) => format!("[{}]:{}", addr.ip(), addr.port()),
    }
}

fn canonicalize_link_type(link_type: &LinkType) -> LinkType {
    match link_type {
        LinkType::Unknown => LinkType::Unknown,
        LinkType::Wifi => LinkType::Wifi,
        LinkType::Cellular => LinkType::Cellular,
        LinkType::Ethernet => LinkType::Ethernet,
        LinkType::Virtual => LinkType::Virtual,
        LinkType::Named(name) => LinkType::Named(normalize_token(name)),
    }
}

fn link_type_key(link_type: &LinkType) -> String {
    match link_type {
        LinkType::Unknown => "unknown".to_string(),
        LinkType::Wifi => "wifi".to_string(),
        LinkType::Cellular => "cellular".to_string(),
        LinkType::Ethernet => "ethernet".to_string(),
        LinkType::Virtual => "virtual".to_string(),
        LinkType::Named(name) => format!("named:{}", normalize_token(name)),
    }
}

fn normalize_token(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

fn hash_label(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(normalize_token(value).as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(target_os = "linux")]
fn classify_linux_link_type(interface_name: &str) -> LinkType {
    let normalized = interface_name.to_ascii_lowercase();
    let sysfs = Path::new("/sys/class/net").join(interface_name);
    if normalized.starts_with("tun")
        || normalized.starts_with("tap")
        || normalized.starts_with("wg")
        || normalized.starts_with("veth")
        || fs::canonicalize(&sysfs)
            .ok()
            .and_then(|path| path.to_str().map(str::to_string))
            .is_some_and(|path| path.contains("/virtual/"))
    {
        return LinkType::Virtual;
    }
    if sysfs.join("wireless").exists()
        || normalized.starts_with("wl")
        || normalized.starts_with("wlan")
    {
        return LinkType::Wifi;
    }
    if normalized.starts_with("wwan")
        || normalized.starts_with("rmnet")
        || normalized.starts_with("ccmni")
        || normalized.starts_with("pdp")
    {
        return LinkType::Cellular;
    }
    if normalized.starts_with("en") || normalized.starts_with("eth") || normalized.starts_with("em")
    {
        return LinkType::Ethernet;
    }
    LinkType::Unknown
}

#[cfg(target_os = "linux")]
fn linux_wifi_ssid_hash(interface_name: &str) -> Option<String> {
    let output = Command::new("iwgetid")
        .args([interface_name, "-r"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ssid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!ssid.is_empty()).then(|| hash_label(&ssid))
}

#[cfg(target_os = "macos")]
fn classify_macos_link_type(interface_name: Option<&str>, service_name: Option<&str>) -> LinkType {
    let service = service_name.map(str::to_ascii_lowercase);
    if service
        .as_deref()
        .is_some_and(|value| value.contains("wi-fi") || value.contains("airport"))
    {
        return LinkType::Wifi;
    }
    if service
        .as_deref()
        .is_some_and(|value| value.contains("iphone usb") || value.contains("cellular"))
    {
        return LinkType::Cellular;
    }
    if interface_name.is_some_and(|name| {
        let normalized = name.to_ascii_lowercase();
        normalized.starts_with("utun")
            || normalized.starts_with("tun")
            || normalized.starts_with("wg")
    }) {
        return LinkType::Virtual;
    }
    if service_name.is_some() || interface_name.is_some() {
        return LinkType::Ethernet;
    }
    LinkType::Unknown
}

#[cfg(target_os = "macos")]
fn macos_wifi_network_hash(device: &str) -> Option<String> {
    let output = Command::new("networksetup")
        .args(["-getairportnetwork", device])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let network = stdout
        .split(':')
        .nth(1)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(hash_label(network))
}
