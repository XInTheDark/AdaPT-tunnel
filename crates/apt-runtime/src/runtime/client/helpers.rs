use super::*;
use apt_client_control::ClientSessionInfo;

pub(super) fn disconnected_client_status(
    config: &ResolvedClientConfig,
    transport: &SessionTransportParameters,
    interface_name: &str,
    active_binding: Option<CarrierBinding>,
    standby_binding: Option<CarrierBinding>,
    mode: Mode,
) -> ClientStatus {
    ClientStatus::new(
        RuntimeStatus::Disconnected,
        config.server_addr.to_string(),
        Some(IpAddr::V4(transport.client_ipv4)),
        tunnel_addresses(transport),
        Some(interface_name.to_string()),
        active_binding,
        standby_binding,
        Some(mode),
    )
}

pub(super) fn session_info(
    config: &ResolvedClientConfig,
    transport: &SessionTransportParameters,
    interface_name: &str,
    carrier: CarrierBinding,
    negotiated_mode: Mode,
    routes: &[ipnet::IpNet],
) -> ClientSessionInfo {
    ClientSessionInfo {
        server: config.server_addr.to_string(),
        interface_name: interface_name.to_string(),
        carrier: match carrier {
            CarrierBinding::S1EncryptedStream => "h2".to_string(),
            _ => carrier.as_str().to_string(),
        },
        negotiated_mode: negotiated_mode.value(),
        tunnel_ipv4: Some(transport.client_ipv4),
        tunnel_ipv6: transport.client_ipv6,
        server_tunnel_ipv4: Some(transport.server_ipv4),
        server_tunnel_ipv6: transport.server_ipv6,
        tunnel_addresses: tunnel_addresses(transport),
        routes: routes.iter().map(ToString::to_string).collect(),
    }
}
