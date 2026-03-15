use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_tun_packet(
    udp_socket: &Arc<UdpSocket>,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    config: &ResolvedServerConfig,
    tun_rx: &mut mpsc::Receiver<Vec<u8>>,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    sessions_by_tunnel_ip: &HashMap<IpAddr, SessionId>,
    packet: Vec<u8>,
) -> Result<(), RuntimeError> {
    if let Some(destination) = extract_destination_ip(&packet) {
        if let Some(session_id) = sessions_by_tunnel_ip.get(&destination).copied() {
            if let Some(session) = sessions.get_mut(&session_id) {
                let (frames, payload_bytes, burst_len) = collect_outbound_tun_frames(
                    packet,
                    tun_rx,
                    &session.adaptive,
                    session.primary_path.binding,
                );
                send_frames_to_server_path(
                    udp_socket,
                    d2_peers,
                    stream_peers,
                    carriers,
                    &config.endpoint_id,
                    session,
                    session.primary_path.handle,
                    session.primary_path.binding,
                    &frames,
                    now_secs(),
                )
                .await?;
                session.primary_path.last_send_secs = now_secs();
                session
                    .adaptive
                    .record_outbound(payload_bytes, burst_len, now_millis());
                session
                    .adaptive
                    .note_activity(session.primary_path.last_send_secs);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_tick(
    udp_socket: &Arc<UdpSocket>,
    d2_peers: &HashMap<u64, ServerD2Peer>,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    config: &ResolvedServerConfig,
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_tunnel_ip: &mut HashMap<IpAddr, SessionId>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<(), RuntimeError> {
    let now = now_secs();
    let mut expired = Vec::new();
    for (session_id, session) in sessions.iter_mut() {
        if let Some(mode) = session.adaptive.maybe_observe_stability(now) {
            record_event(
                telemetry,
                &AptEvent::ModeChanged {
                    session_id: *session_id,
                    mode: mode.into(),
                },
                None,
                observability,
            );
        }
        if let Some(mode) = session.adaptive.maybe_observe_quiet_impairment(
            now,
            session.primary_path.last_send_secs,
            session.primary_path.last_recv_secs,
        ) {
            record_event(
                telemetry,
                &AptEvent::ModeChanged {
                    session_id: *session_id,
                    mode: mode.into(),
                },
                None,
                observability,
            );
        }
        if now.saturating_sub(session.primary_path.last_recv_secs)
            > config.session_idle_timeout_secs
        {
            expired.push(*session_id);
            continue;
        }
        if let Some(pending) = &mut session.pending_validation {
            if now.saturating_sub(pending.issued_secs) >= PATH_VALIDATION_TIMEOUT_SECS {
                session.pending_validation = None;
            } else if now.saturating_sub(pending.issued_secs) >= PATH_VALIDATION_RETRY_SECS
                && pending.retries < 2
            {
                let control_id = session.tunnel.next_control_id();
                let frame = Frame::PathChallenge {
                    control_id,
                    challenge: pending.challenge,
                };
                let _ = send_frames_to_path_handle(
                    udp_socket,
                    d2_peers,
                    stream_peers,
                    carriers,
                    &config.endpoint_id,
                    &session.outer_keys,
                    session.encapsulation,
                    &pending.handle,
                    pending.binding,
                    &mut session.tunnel,
                    &[frame],
                    now,
                )
                .await;
                pending.issued_secs = now;
                pending.retries = pending.retries.saturating_add(1);
            }
        }
        let mut frames = session.tunnel.collect_due_control_frames(now);
        if session.adaptive.keepalive_due(now) {
            frames.extend(session.adaptive.build_keepalive_frames(64));
        }
        match session.tunnel.rekey_status(now) {
            RekeyStatus::SoftLimitReached => {
                if let Ok(frame) = session.tunnel.initiate_rekey(now) {
                    frames.push(frame);
                }
            }
            RekeyStatus::HardLimitReached => {
                expired.push(*session_id);
            }
            RekeyStatus::Healthy => {}
        }
        if !frames.is_empty() {
            let payload_bytes = approximate_frame_bytes(&frames);
            let burst_len = frames
                .iter()
                .filter(|frame| matches!(frame, Frame::IpData(_)))
                .count()
                .max(1);
            send_frames_to_server_path(
                udp_socket,
                d2_peers,
                stream_peers,
                carriers,
                &config.endpoint_id,
                session,
                session.primary_path.handle,
                session.primary_path.binding,
                &frames,
                now,
            )
            .await?;
            session.primary_path.last_send_secs = now;
            session
                .adaptive
                .record_outbound(payload_bytes, burst_len, now_millis());
            if frames.iter().any(|frame| matches!(frame, Frame::Ping)) {
                session.adaptive.note_keepalive_sent(now);
            } else {
                session.adaptive.note_activity(now);
            }
        }
    }
    for session_id in expired {
        expire_server_session(sessions, path_to_session, sessions_by_tunnel_ip, session_id);
    }
    Ok(())
}
