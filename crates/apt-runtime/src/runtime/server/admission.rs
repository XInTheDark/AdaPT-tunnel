use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_server_admission_datagram(
    socket: &UdpSocket,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
    peer_addr: SocketAddr,
    received_len: usize,
    packet: AdmissionPacket,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_client_ip: &mut HashMap<Ipv4Addr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<bool, RuntimeError> {
    match admission.handle_c0(
        &peer_addr.to_string(),
        carriers.d1(),
        &packet,
        received_len,
        now_secs(),
    ) {
        ServerResponse::Reply(reply) => {
            let outer_key = derive_d1_admission_outer_key(
                &config.admission_key,
                now_secs() / DEFAULT_ADMISSION_EPOCH_SLOT_SECS,
            )?;
            let bytes =
                encode_admission_datagram(carriers.d1(), &config.endpoint_id, &outer_key, &reply)?;
            socket.send_to(&bytes, peer_addr).await?;
            return Ok(true);
        }
        ServerResponse::Drop(_) => {}
    }

    let server_reply = match admission.handle_c2_with_extension_builder(
        &peer_addr.to_string(),
        carriers.d1(),
        &packet,
        now_secs(),
        |session| {
            let peer = authorize_established_session(config, session)
                .map_err(|_| AdmissionError::Validation("unauthorized peer"))?;
            Ok(vec![bincode::serialize(
                &ServerSessionExtension::TunnelParameters(assign_transport_parameters(
                    config,
                    peer,
                    effective_tunnel_mtu,
                )),
            )?])
        },
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => return Ok(false),
    };

    let peer = authorize_established_session(config, &server_reply.session)?;
    let confirmation_outer_key =
        derive_d1_confirmation_outer_key(&server_reply.session.secrets.send_ctrl)?;
    let bytes = encode_confirmation_datagram(
        carriers.d1(),
        &config.endpoint_id,
        &confirmation_outer_key,
        &server_reply.packet,
    )?;
    socket.send_to(&bytes, peer_addr).await?;

    install_server_session(
        config,
        sessions,
        path_to_session,
        sessions_by_client_ip,
        telemetry,
        observability,
        server_reply.session,
        peer,
        PathHandle::Datagram(peer_addr),
        CarrierBinding::D1DatagramUdp,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_server_admission_stream(
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
    conn_id: u64,
    packet: AdmissionPacket,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_client_ip: &mut HashMap<Ipv4Addr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<bool, RuntimeError> {
    let Some(peer) = stream_peers.get(&conn_id) else {
        return Ok(false);
    };
    match admission.handle_c0(
        &peer.peer_addr.to_string(),
        carriers.s1(),
        &packet,
        0,
        now_secs(),
    ) {
        ServerResponse::Reply(reply) => {
            let outer_key = derive_s1_admission_outer_key(
                &config.admission_key,
                now_secs() / DEFAULT_ADMISSION_EPOCH_SLOT_SECS,
            )?;
            let payload = encode_admission_stream_payload(&config.endpoint_id, &outer_key, &reply)?;
            queue_path_payload(&PathSender::Stream(peer.sender.clone()), payload)?;
            return Ok(true);
        }
        ServerResponse::Drop(_) => {}
    }

    let server_reply = match admission.handle_c2_with_extension_builder(
        &peer.peer_addr.to_string(),
        carriers.s1(),
        &packet,
        now_secs(),
        |session| {
            let authorized = authorize_established_session(config, session)
                .map_err(|_| AdmissionError::Validation("unauthorized peer"))?;
            Ok(vec![bincode::serialize(
                &ServerSessionExtension::TunnelParameters(assign_transport_parameters(
                    config,
                    authorized,
                    effective_tunnel_mtu,
                )),
            )?])
        },
    ) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(_) => return Ok(false),
    };

    let authorized = authorize_established_session(config, &server_reply.session)?;
    let confirmation_outer_key =
        derive_s1_confirmation_outer_key(&server_reply.session.secrets.send_ctrl)?;
    let payload = encode_confirmation_stream_payload(
        &config.endpoint_id,
        &confirmation_outer_key,
        &server_reply.packet,
    )?;
    queue_path_payload(&PathSender::Stream(peer.sender.clone()), payload)?;

    install_server_session(
        config,
        sessions,
        path_to_session,
        sessions_by_client_ip,
        telemetry,
        observability,
        server_reply.session,
        authorized,
        PathHandle::Stream(conn_id),
        CarrierBinding::S1EncryptedStream,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_server_session(
    config: &ResolvedServerConfig,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_client_ip: &mut HashMap<Ipv4Addr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    session: EstablishedSession,
    peer: ResolvedAuthorizedPeer,
    path_handle: PathHandle,
    binding: CarrierBinding,
) -> Result<bool, RuntimeError> {
    let primary_path = ServerPathState {
        handle: path_handle,
        binding,
        last_send_secs: now_secs(),
        last_recv_secs: now_secs(),
    };
    let session_id = session.session_id;
    if let Some(existing_session_id) = sessions_by_client_ip.insert(peer.tunnel_ipv4, session_id) {
        sessions.remove(&existing_session_id);
    }
    path_to_session.insert(path_handle, session_id);
    let adaptive = AdaptiveDatapath::new_server(
        session.chosen_carrier,
        session.secrets.persona_seed,
        session.policy_mode,
        config.session_policy.allow_speed_first,
        admission_path_profile(None),
        now_secs(),
    );
    let tunnel = TunnelSession::new(
        session_id,
        SessionRole::Responder,
        session.secrets.clone(),
        session.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now_secs(),
    );
    sessions.insert(
        session_id,
        ServerSessionState {
            session_id,
            assigned_ipv4: peer.tunnel_ipv4,
            tunnel,
            adaptive,
            outer_keys: RuntimeOuterKeys {
                d1: derive_d1_tunnel_outer_keys(&session.secrets)?,
                s1: derive_s1_tunnel_outer_keys(&session.secrets)?,
            },
            encapsulation: TunnelEncapsulation::for_policy(session.policy_mode),
            primary_path,
            standby_path: None,
            pending_validation: None,
        },
    );

    let credential_label = redact_credential(&session.credential_identity);
    info!(
        peer = %peer.name,
        assigned_ipv4 = %peer.tunnel_ipv4,
        credential = %credential_label,
        carrier = %binding.as_str(),
        "server session established"
    );
    record_event(
        telemetry,
        &AptEvent::AdmissionAccepted {
            session_id,
            carrier: session.chosen_carrier,
            credential_identity: credential_label,
        },
        None,
        observability,
    );
    record_event(
        telemetry,
        &AptEvent::TunnelEstablished {
            session_id,
            carrier: session.chosen_carrier,
            mode: session.policy_mode,
        },
        None,
        observability,
    );
    Ok(true)
}
