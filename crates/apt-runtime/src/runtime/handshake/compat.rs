use super::*;

pub(crate) fn decode_client_admission_packet(
    config: &ResolvedClientConfig,
    carrier: &D1Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<AdmissionWirePacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_d1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_datagram(carrier, &config.endpoint_id, &outer_key, datagram).ok()
        })
}

pub(crate) fn decode_client_d2_admission_packet(
    config: &ResolvedClientConfig,
    carrier: &D2Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<AdmissionWirePacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_d2_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_d2_datagram(carrier, &config.endpoint_id, &outer_key, datagram).ok()
        })
}

pub(crate) fn decode_server_admission_packet(
    config: &ResolvedServerConfig,
    carrier: &D1Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<DecodedServerAdmissionPacket> {
    server_admission_keys(config)
        .into_iter()
        .find_map(|admission_key| {
            candidate_epoch_slots(now_secs)
                .into_iter()
                .find_map(|epoch_slot| {
                    let outer_key =
                        derive_d1_admission_outer_key(&admission_key, epoch_slot).ok()?;
                    let packet = decode_admission_datagram(
                        carrier,
                        &config.endpoint_id,
                        &outer_key,
                        datagram,
                    )
                    .ok()?;
                    Some(DecodedServerAdmissionPacket { packet, outer_key })
                })
        })
}

pub(crate) fn decode_server_d2_admission_packet(
    config: &ResolvedServerConfig,
    carrier: &D2Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<DecodedServerAdmissionPacket> {
    server_admission_keys(config)
        .into_iter()
        .find_map(|admission_key| {
            candidate_epoch_slots(now_secs)
                .into_iter()
                .find_map(|epoch_slot| {
                    let outer_key =
                        derive_d2_admission_outer_key(&admission_key, epoch_slot).ok()?;
                    let packet = decode_admission_d2_datagram(
                        carrier,
                        &config.endpoint_id,
                        &outer_key,
                        datagram,
                    )
                    .ok()?;
                    Some(DecodedServerAdmissionPacket { packet, outer_key })
                })
        })
}

#[derive(Clone, Debug)]
pub(crate) struct DecodedServerAdmissionPacket {
    pub(crate) packet: AdmissionWirePacket,
    pub(crate) outer_key: [u8; 32],
}

fn server_admission_keys(config: &ResolvedServerConfig) -> Vec<[u8; 32]> {
    let mut keys = vec![config.admission_key];
    for peer in &config.peers {
        if let Some(admission_key) = peer.admission_key {
            if !keys.contains(&admission_key) {
                keys.push(admission_key);
            }
        }
    }
    keys
}

pub(crate) fn admission_config(
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
) -> AdmissionConfig {
    let mut admission = AdmissionConfig::conservative(config.endpoint_id.clone());
    admission.allowed_carriers = vec![CarrierBinding::D1DatagramUdp];
    if config.d2.is_some() {
        admission
            .allowed_carriers
            .push(CarrierBinding::D2EncryptedDatagram);
    }
    admission.default_mode = config.mode;
    admission.max_record_size = carriers.d1().max_record_size();
    admission.tunnel_mtu = effective_tunnel_mtu;
    admission.allowed_suites = vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s];
    admission
}

pub(crate) fn assign_transport_parameters(
    config: &ResolvedServerConfig,
    peer: ResolvedAuthorizedPeer,
    effective_tunnel_mtu: u16,
) -> SessionTransportParameters {
    SessionTransportParameters {
        client_ipv4: peer.tunnel_ipv4,
        server_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        client_ipv6: peer.tunnel_ipv6,
        server_ipv6: config.tunnel_local_ipv6,
        ipv6_prefix_len: config.tunnel_ipv6_prefix_len,
        mtu: effective_tunnel_mtu,
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
