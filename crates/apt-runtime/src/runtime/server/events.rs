use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_datagram_event(
    udp_socket: &Arc<UdpSocket>,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_tunnel_ip: &mut HashMap<IpAddr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    peer_addr: SocketAddr,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    let path = PathHandle::Datagram(peer_addr);
    if let Some(session_id) = path_to_session.get(&path).copied() {
        process_known_server_path(
            udp_socket,
            d2_peers,
            stream_peers,
            carriers,
            config,
            tun_tx,
            sessions,
            path_to_session,
            session_id,
            path,
            CarrierBinding::D1DatagramUdp,
            bytes,
        )
        .await?;
        return Ok(());
    }

    if let Some(decoded) = decode_server_admission_packet(config, carriers.d1(), &bytes, now_secs())
    {
        if handle_server_admission_datagram(
            udp_socket,
            admission,
            config,
            carriers,
            effective_tunnel_mtu,
            peer_addr,
            bytes.len(),
            decoded,
            sessions,
            path_to_session,
            sessions_by_tunnel_ip,
            telemetry,
            observability,
        )
        .await?
        {
            return Ok(());
        }
    }

    if config.allow_session_migration {
        if let Some(matched) = try_match_server_session(
            sessions,
            carriers,
            &config.endpoint_id,
            CarrierBinding::D1DatagramUdp,
            &bytes,
            now_secs(),
        )? {
            process_migrated_server_path(
                udp_socket,
                d2_peers,
                stream_peers,
                carriers,
                config,
                tun_tx,
                sessions,
                path_to_session,
                matched,
                path,
                CarrierBinding::D1DatagramUdp,
                telemetry,
                observability,
            )
            .await?;
        }
    }

    Ok(())
}

pub(super) fn handle_d2_opened(
    d2_peers: &mut HashMap<u64, ServerD2Peer>,
    conn_id: u64,
    peer_addr: SocketAddr,
    sender: mpsc::UnboundedSender<Vec<u8>>,
) {
    d2_peers.insert(conn_id, ServerD2Peer { peer_addr, sender });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_d2_datagram_event(
    udp_socket: &Arc<UdpSocket>,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_tunnel_ip: &mut HashMap<IpAddr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    conn_id: u64,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    let path = PathHandle::D2(conn_id);
    if let Some(session_id) = path_to_session.get(&path).copied() {
        process_known_server_path(
            udp_socket,
            d2_peers,
            stream_peers,
            carriers,
            config,
            tun_tx,
            sessions,
            path_to_session,
            session_id,
            path,
            CarrierBinding::D2EncryptedDatagram,
            bytes,
        )
        .await?;
        return Ok(());
    }

    if let Some(carrier) = carriers.d2() {
        if let Some(decoded) =
            decode_server_d2_admission_packet(config, carrier, &bytes, now_secs())
        {
            if handle_server_admission_d2(
                d2_peers,
                admission,
                config,
                carriers,
                effective_tunnel_mtu,
                conn_id,
                bytes.len(),
                decoded,
                sessions,
                path_to_session,
                sessions_by_tunnel_ip,
                telemetry,
                observability,
            )
            .await?
            {
                return Ok(());
            }
        }
    }

    if config.allow_session_migration {
        if let Some(matched) = try_match_server_session(
            sessions,
            carriers,
            &config.endpoint_id,
            CarrierBinding::D2EncryptedDatagram,
            &bytes,
            now_secs(),
        )? {
            process_migrated_server_path(
                udp_socket,
                d2_peers,
                stream_peers,
                carriers,
                config,
                tun_tx,
                sessions,
                path_to_session,
                matched,
                path,
                CarrierBinding::D2EncryptedDatagram,
                telemetry,
                observability,
            )
            .await?;
        }
    }

    Ok(())
}

pub(super) fn handle_d2_closed(
    d2_peers: &mut HashMap<u64, ServerD2Peer>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    conn_id: u64,
) {
    let path = PathHandle::D2(conn_id);
    d2_peers.remove(&conn_id);
    if let Some(session_id) = path_to_session.remove(&path) {
        if let Some(session) = sessions.get_mut(&session_id) {
            handle_server_path_loss(
                session,
                path,
                path_to_session,
                &HashMap::new(),
                telemetry,
                observability,
            );
        }
    }
}

pub(super) fn handle_stream_opened(
    stream_peers: &mut HashMap<u64, ServerStreamPeer>,
    conn_id: u64,
    peer_addr: SocketAddr,
    sender: mpsc::UnboundedSender<StreamWrite>,
) {
    stream_peers.insert(conn_id, ServerStreamPeer { peer_addr, sender });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_stream_record_event(
    udp_socket: &Arc<UdpSocket>,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &mut HashMap<u64, ServerStreamPeer>,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
    effective_tunnel_mtu: u16,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_tunnel_ip: &mut HashMap<IpAddr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    conn_id: u64,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    let path = PathHandle::Stream(conn_id);
    if let Some(session_id) = path_to_session.get(&path).copied() {
        process_known_server_path(
            udp_socket,
            d2_peers,
            stream_peers,
            carriers,
            config,
            tun_tx,
            sessions,
            path_to_session,
            session_id,
            path,
            CarrierBinding::S1EncryptedStream,
            bytes,
        )
        .await?;
        return Ok(());
    }

    if let Some(decoded) = decode_server_stream_admission_packet(config, &bytes, now_secs()) {
        if handle_server_admission_stream(
            stream_peers,
            admission,
            config,
            carriers,
            effective_tunnel_mtu,
            conn_id,
            decoded,
            sessions,
            path_to_session,
            sessions_by_tunnel_ip,
            telemetry,
            observability,
        )
        .await?
        {
            return Ok(());
        }
    }

    if config.allow_session_migration {
        if let Some(matched) = try_match_server_session(
            sessions,
            carriers,
            &config.endpoint_id,
            CarrierBinding::S1EncryptedStream,
            &bytes,
            now_secs(),
        )? {
            process_migrated_server_path(
                udp_socket,
                d2_peers,
                stream_peers,
                carriers,
                config,
                tun_tx,
                sessions,
                path_to_session,
                matched,
                path,
                CarrierBinding::S1EncryptedStream,
                telemetry,
                observability,
            )
            .await?;
            return Ok(());
        }
    }

    send_invalid_stream_response(stream_peers, conn_id, config.stream_decoy_surface)?;
    stream_peers.remove(&conn_id);
    Ok(())
}

pub(super) fn handle_stream_closed(
    stream_peers: &mut HashMap<u64, ServerStreamPeer>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    stream_decoy_surface: bool,
    conn_id: u64,
    malformed: bool,
) {
    let path = PathHandle::Stream(conn_id);
    if malformed && !path_to_session.contains_key(&path) {
        let _ = send_invalid_stream_response(stream_peers, conn_id, stream_decoy_surface);
    }
    stream_peers.remove(&conn_id);
    if let Some(session_id) = path_to_session.remove(&path) {
        if let Some(session) = sessions.get_mut(&session_id) {
            handle_server_path_loss(
                session,
                path,
                path_to_session,
                stream_peers,
                telemetry,
                observability,
            );
        }
    }
}
