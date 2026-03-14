use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_known_server_path(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    config: &ResolvedServerConfig,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    session_id: SessionId,
    path: PathHandle,
    binding: CarrierBinding,
    bytes: Vec<u8>,
) -> Result<(), RuntimeError> {
    let Some(session) = sessions.get_mut(&session_id) else {
        path_to_session.remove(&path);
        return Ok(());
    };
    let tunnel_bytes = decode_server_tunnel_packet(
        carriers,
        &config.endpoint_id,
        &session.outer_keys,
        session.encapsulation,
        binding,
        &bytes,
    )?;
    let decoded = session.tunnel.decode_packet(&tunnel_bytes, now_secs())?;
    handle_server_decoded_packet(
        udp_socket,
        d2_peers,
        stream_peers,
        carriers,
        &config.endpoint_id,
        tun_tx,
        session,
        path_to_session,
        path,
        binding,
        decoded,
        tunnel_bytes.len(),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_migrated_server_path(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    config: &ResolvedServerConfig,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    matched: MatchedServerPacket,
    path: PathHandle,
    binding: CarrierBinding,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<(), RuntimeError> {
    let Some(session) = sessions.get_mut(&matched.session_id) else {
        return Ok(());
    };
    session.tunnel = matched.tunnel;
    handle_server_decoded_packet(
        udp_socket,
        d2_peers,
        stream_peers,
        carriers,
        &config.endpoint_id,
        tun_tx,
        session,
        path_to_session,
        path,
        binding,
        matched.decoded,
        matched.tunnel_bytes_len,
        Some((telemetry, observability)),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_decoded_packet(
    udp_socket: &UdpSocket,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    session: &mut ServerSessionState,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    path: PathHandle,
    binding: CarrierBinding,
    decoded: apt_tunnel::DecodedPacket,
    tunnel_bytes_len: usize,
    telemetry: Option<(&mut TelemetrySnapshot, &ObservabilityConfig)>,
) -> Result<(), RuntimeError> {
    let now = now_secs();
    let path_known = session.primary_path.handle == path
        || session
            .standby_path
            .as_ref()
            .is_some_and(|standby| standby.handle == path);
    let path_validated = path_known;
    let mut response_frames = decoded.ack_suggestions;
    let mut deliver_ip = path_validated;
    let mut saw_switchworthy_traffic = false;
    let mut validated_now = false;

    if session.primary_path.handle == path {
        session.primary_path.last_recv_secs = now;
    }
    if let Some(standby) = &mut session.standby_path {
        if standby.handle == path {
            standby.last_recv_secs = now;
        }
    }
    session
        .adaptive
        .record_inbound(tunnel_bytes_len, now_millis());
    session.adaptive.note_activity(now);

    for frame in decoded.frames {
        match frame {
            Frame::IpData(packet) => {
                if deliver_ip {
                    saw_switchworthy_traffic = true;
                    let _ = tun_tx.send(packet).await;
                }
            }
            Frame::PathChallenge { challenge, .. } => {
                let control_id = session.tunnel.next_control_id();
                response_frames.push(Frame::PathResponse {
                    control_id,
                    challenge,
                });
                if !path_known && session.pending_validation.is_none() {
                    let challenge: [u8; 8] = rand::random();
                    session.pending_validation = Some(PendingPathValidation {
                        handle: path,
                        binding,
                        challenge,
                        issued_secs: now,
                        retries: 0,
                    });
                    response_frames.push(Frame::PathChallenge {
                        control_id: session.tunnel.next_control_id(),
                        challenge,
                    });
                }
            }
            Frame::PathResponse { challenge, .. } => {
                if session
                    .pending_validation
                    .as_ref()
                    .is_some_and(|pending| pending.handle == path && pending.challenge == challenge)
                {
                    validated_now = true;
                    deliver_ip = true;
                    path_to_session.insert(path, session.session_id);
                    let validated_path = ServerPathState {
                        handle: path,
                        binding,
                        last_send_secs: now,
                        last_recv_secs: now,
                    };
                    if session.primary_path.handle != path {
                        session.standby_path = Some(validated_path);
                    }
                    session.pending_validation = None;
                }
            }
            Frame::Close { .. } => {
                path_to_session.remove(&path);
                return Ok(());
            }
            Frame::Ping if path_validated || validated_now => {
                saw_switchworthy_traffic = true;
            }
            Frame::Ping => {}
            _ => {}
        }
    }

    if validated_now {
        if let Some((telemetry, observability)) = telemetry {
            record_event(
                telemetry,
                &AptEvent::CarrierMigrated {
                    session_id: session.session_id,
                    from: Some(session.primary_path.binding),
                    to: binding,
                },
                None,
                observability,
            );
        }
    }

    if saw_switchworthy_traffic {
        if session.primary_path.handle != path {
            let previous = session.primary_path.clone();
            session.primary_path = ServerPathState {
                handle: path,
                binding,
                last_send_secs: now,
                last_recv_secs: now,
            };
            session.standby_path = Some(previous);
        }
    }

    if !response_frames.is_empty() {
        send_frames_to_server_path(
            udp_socket,
            d2_peers,
            stream_peers,
            carriers,
            endpoint_id,
            session,
            path,
            binding,
            &response_frames,
            now,
        )
        .await?;
    }

    Ok(())
}

pub(super) fn handle_server_path_loss(
    session: &mut ServerSessionState,
    path: PathHandle,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) {
    let _ = stream_peers;
    path_to_session.remove(&path);
    if session.primary_path.handle == path {
        if let Some(standby) = session.standby_path.take() {
            session.primary_path = standby.clone();
            path_to_session.insert(standby.handle, session.session_id);
            record_event(
                telemetry,
                &AptEvent::CarrierMigrated {
                    session_id: session.session_id,
                    from: Some(session.primary_path.binding),
                    to: standby.binding,
                },
                None,
                observability,
            );
        }
    } else if session
        .standby_path
        .as_ref()
        .is_some_and(|standby| standby.handle == path)
    {
        session.standby_path = None;
    }
}

pub(super) fn expire_server_session(
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_tunnel_ip: &mut HashMap<IpAddr, SessionId>,
    session_id: SessionId,
) {
    if let Some(session) = sessions.remove(&session_id) {
        path_to_session.remove(&session.primary_path.handle);
        if let Some(standby) = session.standby_path {
            path_to_session.remove(&standby.handle);
        }
        sessions_by_tunnel_ip.remove(&IpAddr::V4(session.assigned_ipv4));
        if let Some(ipv6) = session.assigned_ipv6 {
            sessions_by_tunnel_ip.remove(&IpAddr::V6(ipv6));
        }
    }
}

pub(super) fn try_match_server_session(
    sessions: &HashMap<SessionId, ServerSessionState>,
    endpoint_id: &apt_types::EndpointId,
    binding: CarrierBinding,
    bytes: &[u8],
    now: u64,
) -> Result<Option<MatchedServerPacket>, RuntimeError> {
    for (session_id, session) in sessions {
        let tunnel_bytes = match decode_server_tunnel_packet_direct(
            endpoint_id,
            &session.outer_keys,
            session.encapsulation,
            binding,
            bytes,
        ) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let mut tunnel = session.tunnel.clone();
        let decoded = match tunnel.decode_packet(&tunnel_bytes, now) {
            Ok(decoded) => decoded,
            Err(_) => continue,
        };
        return Ok(Some(MatchedServerPacket {
            session_id: *session_id,
            tunnel,
            decoded,
            tunnel_bytes_len: tunnel_bytes.len(),
        }));
    }
    Ok(None)
}
