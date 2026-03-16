use super::*;

pub(crate) fn assign_transport_parameters(
    config: &ResolvedServerConfig,
    peer: ResolvedAuthorizedPeer,
    tunnel_mtu: u16,
) -> SessionTransportParameters {
    SessionTransportParameters {
        client_ipv4: peer.tunnel_ipv4,
        server_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        client_ipv6: peer.tunnel_ipv6,
        server_ipv6: config.tunnel_local_ipv6,
        ipv6_prefix_len: config.tunnel_ipv6_prefix_len,
        mtu: tunnel_mtu,
        routes: config.push_routes.clone(),
        dns_servers: config.push_dns.clone(),
    }
}

pub(crate) fn authorize_established_session(
    config: &ResolvedServerConfig,
    session: &EstablishedSession,
) -> Result<ResolvedAuthorizedPeer, RuntimeError> {
    let client_static_public = session
        .client_static_public
        .ok_or(RuntimeError::UnauthorizedPeer)?;
    config
        .peers
        .iter()
        .find(|peer| peer.client_static_public_key == client_static_public)
        .cloned()
        .ok_or(RuntimeError::UnauthorizedPeer)
}

pub(crate) fn extract_tunnel_parameters(
    session: &EstablishedSession,
) -> Result<SessionTransportParameters, RuntimeError> {
    for extension in &session.optional_extensions {
        let decoded: ServerSessionExtension = bincode::deserialize(extension)?;
        match decoded {
            ServerSessionExtension::TunnelParameters(parameters) => return Ok(parameters),
        }
    }
    Err(RuntimeError::InvalidConfig(
        "server did not provide tunnel transport parameters".to_string(),
    ))
}
