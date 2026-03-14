use super::*;

mod admission;
mod session;

use self::{
    admission::{handle_server_admission_datagram, handle_server_admission_stream},
    session::{
        expire_server_session, handle_server_path_loss, process_known_server_path,
        process_migrated_server_path, try_match_server_session,
    },
};

pub(super) async fn run_server(
    config: ResolvedServerConfig,
) -> Result<ServerRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-edge");
    let bootstrap_carriers = RuntimeCarriers::new(config.tunnel_mtu, config.stream_decoy_surface);
    let effective_tunnel_mtu =
        effective_runtime_tunnel_mtu(config.tunnel_mtu, &config.endpoint_id, &bootstrap_carriers);
    if effective_tunnel_mtu < config.tunnel_mtu {
        warn!(
            configured_mtu = config.tunnel_mtu,
            effective_mtu = effective_tunnel_mtu,
            carrier = CarrierBinding::D1DatagramUdp.as_str(),
            "configured tunnel MTU exceeds the safe D1 payload budget; capping runtime MTU"
        );
    }
    let carriers = RuntimeCarriers::new(effective_tunnel_mtu, config.stream_decoy_surface);

    let udp_socket = Arc::new(build_udp_socket(
        config.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?);
    let tcp_listener = if config.allow_session_migration || config.stream_bind.is_some() {
        let bind = config.stream_bind.unwrap_or(config.bind);
        Some(TcpListener::bind(bind).await?)
    } else {
        None
    };

    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: config.tunnel_local_ipv4,
        peer_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        mtu: effective_tunnel_mtu,
    })
    .await?;
    let _server_net_guard = configure_server_network(&tun.interface_name, &config)?;

    let mut credentials = CredentialStore::default();
    credentials.set_shared_deployment_key(config.admission_key);
    let mut admission = AdmissionServer::new(
        admission_config(&config, &carriers, effective_tunnel_mtu),
        credentials,
        AdmissionServerSecrets {
            static_keypair: StaticKeypair {
                private: config.server_static_private_key,
                public: config.server_static_public_key,
            },
            cookie_key: config.cookie_key,
            ticket_key: config.ticket_key,
        },
    );

    let (transport_tx, mut transport_rx) = mpsc::unbounded_channel();
    spawn_server_udp_receiver(udp_socket.clone(), transport_tx.clone());
    if let Some(listener) = tcp_listener {
        spawn_server_tcp_listener(listener, transport_tx.clone(), carriers.s1());
    }

    let mut sessions: HashMap<SessionId, ServerSessionState> = HashMap::new();
    let mut path_to_session: HashMap<PathHandle, SessionId> = HashMap::new();
    let mut sessions_by_client_ip: HashMap<Ipv4Addr, SessionId> = HashMap::new();
    let mut stream_peers: HashMap<u64, ServerStreamPeer> = HashMap::new();
    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();

    loop {
        tokio::select! {
            maybe_event = transport_rx.recv() => {
                let Some(event) = maybe_event else { break; };
                match event {
                    ServerTransportEvent::Datagram { peer_addr, bytes } => {
                        let path = PathHandle::Datagram(peer_addr);
                        if let Some(session_id) = path_to_session.get(&path).copied() {
                            process_known_server_path(
                                &udp_socket,
                                &stream_peers,
                                &carriers,
                                &config,
                                &tun_tx,
                                &mut sessions,
                                &mut path_to_session,
                                session_id,
                                path,
                                CarrierBinding::D1DatagramUdp,
                                bytes,
                            )
                            .await?;
                            continue;
                        }

                        if let Some(packet) = decode_server_admission_packet(
                            &config,
                            carriers.d1(),
                            &bytes,
                            now_secs(),
                        ) {
                            if handle_server_admission_datagram(
                                &udp_socket,
                                &mut admission,
                                &config,
                                &carriers,
                                effective_tunnel_mtu,
                                peer_addr,
                                bytes.len(),
                                packet,
                                &mut sessions,
                                &mut path_to_session,
                                &mut sessions_by_client_ip,
                                &mut telemetry,
                                &observability,
                            )
                            .await? {
                                continue;
                            }
                        }

                        if config.allow_session_migration {
                            if let Some(matched) = try_match_server_session(
                                &sessions,
                                &config.endpoint_id,
                                CarrierBinding::D1DatagramUdp,
                                &bytes,
                                now_secs(),
                            )? {
                                process_migrated_server_path(
                                    &udp_socket,
                                    &stream_peers,
                                    &carriers,
                                    &config,
                                    &tun_tx,
                                    &mut sessions,
                                    &mut path_to_session,
                                    matched,
                                    path,
                                    CarrierBinding::D1DatagramUdp,
                                    &mut telemetry,
                                    &observability,
                                )
                                .await?;
                            }
                        }
                    }
                    ServerTransportEvent::StreamOpened { conn_id, peer_addr, sender } => {
                        stream_peers.insert(conn_id, ServerStreamPeer { peer_addr, sender });
                    }
                    ServerTransportEvent::StreamRecord { conn_id, bytes } => {
                        let path = PathHandle::Stream(conn_id);
                        if let Some(session_id) = path_to_session.get(&path).copied() {
                            process_known_server_path(
                                &udp_socket,
                                &stream_peers,
                                &carriers,
                                &config,
                                &tun_tx,
                                &mut sessions,
                                &mut path_to_session,
                                session_id,
                                path,
                                CarrierBinding::S1EncryptedStream,
                                bytes,
                            )
                            .await?;
                            continue;
                        }

                        if let Some(packet) = decode_server_stream_admission_packet(
                            &config,
                            &bytes,
                            now_secs(),
                        ) {
                            if handle_server_admission_stream(
                                &stream_peers,
                                &mut admission,
                                &config,
                                &carriers,
                                effective_tunnel_mtu,
                                conn_id,
                                packet,
                                &mut sessions,
                                &mut path_to_session,
                                &mut sessions_by_client_ip,
                                &mut telemetry,
                                &observability,
                            )
                            .await? {
                                continue;
                            }
                        }

                        if config.allow_session_migration {
                            if let Some(matched) = try_match_server_session(
                                &sessions,
                                &config.endpoint_id,
                                CarrierBinding::S1EncryptedStream,
                                &bytes,
                                now_secs(),
                            )? {
                                process_migrated_server_path(
                                    &udp_socket,
                                    &stream_peers,
                                    &carriers,
                                    &config,
                                    &tun_tx,
                                    &mut sessions,
                                    &mut path_to_session,
                                    matched,
                                    path,
                                    CarrierBinding::S1EncryptedStream,
                                    &mut telemetry,
                                    &observability,
                                )
                                .await?;
                                continue;
                            }
                        }

                        send_invalid_stream_response(&stream_peers, conn_id, config.stream_decoy_surface)?;
                        stream_peers.remove(&conn_id);
                    }
                    ServerTransportEvent::StreamClosed { conn_id, malformed } => {
                        let path = PathHandle::Stream(conn_id);
                        if malformed && !path_to_session.contains_key(&path) {
                            let _ = send_invalid_stream_response(&stream_peers, conn_id, config.stream_decoy_surface);
                        }
                        stream_peers.remove(&conn_id);
                        if let Some(session_id) = path_to_session.remove(&path) {
                            if let Some(session) = sessions.get_mut(&session_id) {
                                handle_server_path_loss(session, path, &mut path_to_session, &stream_peers, &mut telemetry, &observability);
                            }
                        }
                    }
                }
            }
            tun_packet = tun_rx.recv() => {
                if let Some(packet) = tun_packet {
                    if let Some(destination) = extract_destination_ipv4(&packet) {
                        if let Some(session_id) = sessions_by_client_ip.get(&destination).copied() {
                            if let Some(session) = sessions.get_mut(&session_id) {
                                let (frames, payload_bytes, burst_len) = collect_outbound_tun_frames(
                                    packet,
                                    &mut tun_rx,
                                    &session.adaptive,
                                    session.primary_path.binding,
                                );
                                send_frames_to_server_path(
                                    &udp_socket,
                                    &stream_peers,
                                    &carriers,
                                    &config.endpoint_id,
                                    session,
                                    session.primary_path.handle,
                                    session.primary_path.binding,
                                    &frames,
                                    now_secs(),
                                )
                                .await?;
                                session.primary_path.last_send_secs = now_secs();
                                session.adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                                session.adaptive.note_activity(session.primary_path.last_send_secs);
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            _ = tick.tick() => {
                let now = now_secs();
                let mut expired = Vec::new();
                for (session_id, session) in &mut sessions {
                    if let Some(mode) = session.adaptive.maybe_observe_stability(now) {
                        record_event(
                            &mut telemetry,
                            &AptEvent::PolicyModeChanged { session_id: *session_id, mode },
                            None,
                            &observability,
                        );
                    }
                    if let Some(mode) = session.adaptive.maybe_observe_quiet_impairment(now, session.primary_path.last_recv_secs) {
                        record_event(
                            &mut telemetry,
                            &AptEvent::PolicyModeChanged { session_id: *session_id, mode },
                            None,
                            &observability,
                        );
                    }
                    if now.saturating_sub(session.primary_path.last_recv_secs) > config.session_idle_timeout_secs {
                        expired.push(*session_id);
                        continue;
                    }
                    if let Some(pending) = &mut session.pending_validation {
                        if now.saturating_sub(pending.issued_secs) >= PATH_VALIDATION_TIMEOUT_SECS {
                            session.pending_validation = None;
                        } else if now.saturating_sub(pending.issued_secs) >= PATH_VALIDATION_RETRY_SECS && pending.retries < 2 {
                            let control_id = session.tunnel.next_control_id();
                            let frame = Frame::PathChallenge { control_id, challenge: pending.challenge };
                            let _ = send_frames_to_path_handle(
                                &udp_socket,
                                &stream_peers,
                                &carriers,
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
                    if session.adaptive.keepalive_due(now, session.primary_path.last_send_secs) {
                        frames.extend(session.adaptive.build_keepalive_frames(64, now));
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
                        let burst_len = frames.iter().filter(|frame| matches!(frame, Frame::IpData(_))).count().max(1);
                        send_frames_to_server_path(
                            &udp_socket,
                            &stream_peers,
                            &carriers,
                            &config.endpoint_id,
                            session,
                            session.primary_path.handle,
                            session.primary_path.binding,
                            &frames,
                            now,
                        )
                        .await?;
                        session.primary_path.last_send_secs = now;
                        session.adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                        session.adaptive.note_activity(now);
                    }
                }
                for session_id in expired {
                    expire_server_session(&mut sessions, &mut path_to_session, &mut sessions_by_client_ip, session_id);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }
        }
    }

    Ok(ServerRuntimeResult {
        status: ServerStatus {
            bind: config.bind.to_string(),
            interface_name: Some(tun.interface_name),
            listening_carriers: vec![
                CarrierBinding::D1DatagramUdp,
                CarrierBinding::S1EncryptedStream,
            ],
            active_sessions: sessions.len(),
            active_carrier: None,
            standby_carrier: None,
            policy_mode: None,
        },
        telemetry,
    })
}
