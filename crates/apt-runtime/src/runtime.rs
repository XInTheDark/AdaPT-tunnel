use crate::{
    adaptive::{admission_path_profile, build_client_network_context, AdaptiveDatapath},
    config::{
        ClientPersistentState, PersistedNetworkProfile, ResolvedAuthorizedPeer,
        ResolvedClientConfig, ResolvedServerConfig, ServerSessionExtension,
        SessionTransportParameters,
    },
    error::RuntimeError,
    route::{configure_client_network, configure_server_network},
    status::{ClientStatus, RuntimeStatus, ServerStatus},
    tun::{spawn_tun_worker, TunHandle, TunInterfaceConfig},
    wire::{
        decode_admission_datagram, decode_confirmation_datagram, decode_tunnel_datagram,
        derive_d1_admission_outer_key, derive_d1_confirmation_outer_key,
        derive_d1_tunnel_outer_keys, encode_admission_datagram, encode_confirmation_datagram,
        encode_tunnel_datagram, D1OuterKeys,
    },
};
use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionError, AdmissionPacket, AdmissionServer,
    AdmissionServerSecrets, ClientCredential, ClientSessionRequest, CredentialStore,
    EstablishedSession, ServerConfirmationPacket, ServerResponse,
};
use apt_carriers::{CarrierProfile, D1Carrier};
use apt_crypto::{SealedEnvelope, StaticKeypair};
use apt_observability::{record_event, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_tunnel::{Frame, RekeyStatus, TunnelSession};
use apt_types::{
    AuthProfile, CarrierBinding, CipherSuite, CredentialIdentity, SessionRole,
    DEFAULT_ADMISSION_EPOCH_SLOT_SECS, MINIMUM_REPLAY_WINDOW,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime},
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    time::{interval, sleep, timeout},
};
use tracing::{debug, info};

const DATAGRAM_BUFFER_SIZE: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRuntimeResult {
    pub status: ClientStatus,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerRuntimeResult {
    pub status: ServerStatus,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Debug)]
struct ServerSessionState {
    session_id: apt_types::SessionId,
    peer_addr: SocketAddr,
    assigned_ipv4: Ipv4Addr,
    tunnel: TunnelSession,
    adaptive: AdaptiveDatapath,
    outer_keys: D1OuterKeys,
    last_send_secs: u64,
    last_recv_secs: u64,
}

pub async fn run_client(config: ResolvedClientConfig) -> Result<ClientRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-client");
    let carrier = runtime_d1_carrier(1_380);
    let socket = build_udp_socket(
        config.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?;
    socket.connect(config.server_addr).await?;

    let mut persistent_state = ClientPersistentState::load(&config.state_path)?;
    persistent_state.last_status = Some(RuntimeStatus::Starting);
    persistent_state.store(&config.state_path)?;

    let established =
        perform_client_handshake(&socket, &config, &mut persistent_state, &carrier).await?;
    let transport = extract_tunnel_parameters(&established)?;
    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: transport.client_ipv4,
        peer_ipv4: transport.server_ipv4,
        netmask: transport.netmask,
        mtu: transport.mtu,
    })
    .await?;

    let effective_routes = if config.use_server_pushed_routes && !transport.routes.is_empty() {
        transport.routes.clone()
    } else {
        config.routes.clone()
    };
    let _route_guard =
        configure_client_network(&tun.interface_name, config.server_addr, &effective_routes)?;

    info!(
        server = %config.server_addr,
        tunnel_ip = %transport.client_ipv4,
        server_tunnel_ip = %transport.server_ipv4,
        interface = %tun.interface_name,
        routes = ?effective_routes,
        "client session established"
    );

    let credential_label = redact_credential(&established.credential_identity);
    record_event(
        &mut telemetry,
        &AptEvent::AdmissionAccepted {
            session_id: established.session_id,
            carrier: established.chosen_carrier,
            credential_identity: credential_label,
        },
        None,
        &observability,
    );
    record_event(
        &mut telemetry,
        &AptEvent::TunnelEstablished {
            session_id: established.session_id,
            carrier: established.chosen_carrier,
            mode: established.policy_mode,
        },
        None,
        &observability,
    );

    let status = run_client_session_loop(
        &socket,
        &config,
        &carrier,
        tun,
        established,
        transport,
        &mut persistent_state,
        &mut telemetry,
        &observability,
    )
    .await?;
    persistent_state.last_status = Some(status.status.clone());
    persistent_state.store(&config.state_path)?;
    Ok(ClientRuntimeResult { status, telemetry })
}

pub async fn run_server(config: ResolvedServerConfig) -> Result<ServerRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-edge");
    let carrier = runtime_d1_carrier(config.tunnel_mtu);
    let socket = build_udp_socket(
        config.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?;
    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: config.tunnel_local_ipv4,
        peer_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        mtu: config.tunnel_mtu,
    })
    .await?;
    let _server_net_guard = configure_server_network(&tun.interface_name, &config)?;

    let mut credentials = CredentialStore::default();
    credentials.set_shared_deployment_key(config.admission_key);
    let mut admission = AdmissionServer::new(
        admission_config(&config, &carrier),
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

    let mut sessions_by_addr: HashMap<SocketAddr, ServerSessionState> = HashMap::new();
    let mut sessions_by_client_ip: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut recv_buf) => {
                let (len, peer_addr) = recv?;
                let bytes = &recv_buf[..len];
                let now = now_secs();
                if let Some(session) = sessions_by_addr.get_mut(&peer_addr) {
                    if process_server_tunnel_packet(
                        &socket,
                        &carrier,
                        &config.endpoint_id,
                        session,
                        bytes,
                        now,
                        &tun_tx,
                    ).await? {
                        continue;
                    }
                }

                if let Some(packet) = decode_server_admission_packet(&config, &carrier, bytes, now) {
                    if handle_server_admission_packet(
                        &socket,
                        &mut admission,
                        &config,
                        &carrier,
                        peer_addr,
                        len,
                        packet,
                        &mut sessions_by_addr,
                        &mut sessions_by_client_ip,
                        &mut telemetry,
                        &observability,
                    )
                    .await?
                    {
                        continue;
                    }
                }
            }
            tun_packet = tun_rx.recv() => {
                if let Some(packet) = tun_packet {
                    if let Some(destination) = extract_destination_ipv4(&packet) {
                        if let Some(peer_addr) = sessions_by_client_ip.get(&destination).copied() {
                            if let Some(session) = sessions_by_addr.get_mut(&peer_addr) {
                                if let Some(delay) = session.adaptive.pacing_delay(packet.len(), 1) {
                                    sleep(delay).await;
                                }
                                let (frames, payload_bytes, burst_len) =
                                    collect_outbound_tun_frames(packet, &mut tun_rx, &session.adaptive);
                                send_frames_to_peer(
                                    &socket,
                                    &carrier,
                                    &config.endpoint_id,
                                    &session.outer_keys.send,
                                    peer_addr,
                                    &mut session.tunnel,
                                    &frames,
                                    now_secs(),
                                )
                                .await?;
                                session.last_send_secs = now_secs();
                                session.adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                                session.adaptive.note_activity(session.last_send_secs);
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
                for (peer_addr, session) in &mut sessions_by_addr {
                    if let Some(mode) = session.adaptive.maybe_observe_stability(now) {
                        record_event(
                            &mut telemetry,
                            &AptEvent::PolicyModeChanged {
                                session_id: session.session_id,
                                mode,
                            },
                            None,
                            &observability,
                        );
                    }
                    if let Some(mode) = session.adaptive.maybe_observe_quiet_impairment(now, session.last_recv_secs) {
                        record_event(
                            &mut telemetry,
                            &AptEvent::PolicyModeChanged {
                                session_id: session.session_id,
                                mode,
                            },
                            None,
                            &observability,
                        );
                    }
                    if now.saturating_sub(session.last_recv_secs) > config.session_idle_timeout_secs {
                        expired.push(*peer_addr);
                        continue;
                    }
                    let mut frames = session.tunnel.collect_due_control_frames(now);
                    if session.adaptive.keepalive_due(now, session.last_send_secs) {
                        frames.extend(session.adaptive.build_keepalive_frames(64, now));
                    }
                    match session.tunnel.rekey_status(now) {
                        RekeyStatus::SoftLimitReached => {
                            if let Ok(frame) = session.tunnel.initiate_rekey(now) {
                                frames.push(frame);
                            }
                        }
                        RekeyStatus::HardLimitReached => {
                            expired.push(*peer_addr);
                        }
                        RekeyStatus::Healthy => {}
                    }
                    if !frames.is_empty() {
                        let payload_bytes = approximate_frame_bytes(&frames);
                        let burst_len = frames.iter().filter(|frame| matches!(frame, Frame::IpData(_))).count().max(1);
                        send_frames_to_peer(
                            &socket,
                            &carrier,
                            &config.endpoint_id,
                            &session.outer_keys.send,
                            *peer_addr,
                            &mut session.tunnel,
                            &frames,
                            now,
                        )
                        .await?;
                        session.last_send_secs = now;
                        session.adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                        session.adaptive.note_activity(now);
                    }
                }
                for peer_addr in expired {
                    if let Some(removed) = sessions_by_addr.remove(&peer_addr) {
                        sessions_by_client_ip.remove(&removed.assigned_ipv4);
                    }
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
            active_sessions: sessions_by_addr.len(),
        },
        telemetry,
    })
}

async fn perform_client_handshake(
    socket: &UdpSocket,
    config: &ResolvedClientConfig,
    persistent_state: &mut ClientPersistentState,
    carrier: &D1Carrier,
) -> Result<EstablishedSession, RuntimeError> {
    let resume_ticket = persistent_state
        .resume_ticket
        .as_ref()
        .map(|bytes| bincode::deserialize::<SealedEnvelope>(bytes))
        .transpose()?;

    for _attempt in 0..config.handshake_retries {
        let now = now_secs();
        let current_epoch_slot = now / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
        let outer_key = derive_d1_admission_outer_key(&config.admission_key, current_epoch_slot)?;
        let credential = ClientCredential {
            auth_profile: AuthProfile::SharedDeployment,
            user_id: config.client_identity.clone(),
            client_static_private: Some(config.client_static_private_key),
            admission_key: config.admission_key,
            server_static_public: config.server_static_public_key,
            enable_lookup_hint: false,
        };
        let mut request = ClientSessionRequest::conservative(config.endpoint_id.clone(), now);
        request.preferred_carrier = CarrierBinding::D1DatagramUdp;
        request.supported_carriers = vec![CarrierBinding::D1DatagramUdp];
        request.policy_mode = config.session_policy.initial_mode;
        request.policy_flags.allow_speed_first = config.session_policy.allow_speed_first;
        request.policy_flags.allow_hybrid_pq = config.session_policy.allow_hybrid_pq;
        request.path_profile = admission_path_profile(
            persistent_state
                .network_profile
                .as_ref()
                .map(|profile| &profile.normality),
        );
        request.resume_ticket = resume_ticket.clone();
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c0.packet,
        )?;
        socket.send(&c0_bytes).await?;

        let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
        let s1_bytes = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            socket.recv(&mut recv_buf),
        )
        .await
        {
            Ok(Ok(len)) => len,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s1 = match decode_client_admission_packet(
            config,
            carrier,
            &recv_buf[..s1_bytes],
            now_secs(),
        ) {
            Some(packet) => packet,
            None => continue,
        };
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier)?;
        let c2_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c2.packet,
        )?;
        socket.send(&c2_bytes).await?;

        let confirmation_outer_key =
            derive_d1_confirmation_outer_key(prepared_c2.state.confirmation_recv_ctrl_key())?;
        let s3_bytes = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            socket.recv(&mut recv_buf),
        )
        .await
        {
            Ok(Ok(len)) => len,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s3: ServerConfirmationPacket = decode_confirmation_datagram(
            carrier,
            &config.endpoint_id,
            &confirmation_outer_key,
            &recv_buf[..s3_bytes],
        )?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        persistent_state.resume_ticket = session
            .resume_ticket
            .as_ref()
            .map(bincode::serialize)
            .transpose()?;
        persistent_state.store(&config.state_path)?;
        return Ok(session);
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

#[allow(clippy::too_many_arguments)]
async fn run_client_session_loop(
    socket: &UdpSocket,
    config: &ResolvedClientConfig,
    carrier: &D1Carrier,
    tun: TunHandle,
    established: EstablishedSession,
    transport: SessionTransportParameters,
    persistent_state: &mut ClientPersistentState,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<ClientStatus, RuntimeError> {
    let outer_keys = derive_d1_tunnel_outer_keys(&established.secrets)?;
    let mut adaptive = AdaptiveDatapath::new_client(
        established.chosen_carrier,
        established.secrets.persona_seed,
        persistent_state
            .network_profile
            .as_ref()
            .map(|profile| profile.context.clone())
            .unwrap_or_else(|| {
                build_client_network_context(
                    config.endpoint_id.as_str(),
                    &config.server_addr.to_string(),
                )
            }),
        persistent_state
            .network_profile
            .as_ref()
            .map(|profile| profile.normality.clone()),
        persistent_state
            .network_profile
            .as_ref()
            .and_then(|profile| profile.remembered_profile.clone()),
        config.session_policy.initial_mode,
        config.session_policy.allow_speed_first,
        admission_path_profile(
            persistent_state
                .network_profile
                .as_ref()
                .map(|profile| &profile.normality),
        ),
        now_secs(),
    );
    adaptive.note_successful_session();
    persist_client_learning(persistent_state, &adaptive);
    persistent_state.store(&config.state_path)?;

    let session_id = established.session_id;
    let mut tunnel = TunnelSession::new(
        established.session_id,
        SessionRole::Initiator,
        established.secrets,
        established.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now_secs(),
    );
    let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();
    let mut last_send_secs = now_secs();
    let mut last_recv_secs = now_secs();

    loop {
        tokio::select! {
            recv = socket.recv(&mut recv_buf) => {
                let len = recv?;
                let tunnel_bytes = decode_tunnel_datagram(
                    carrier,
                    &config.endpoint_id,
                    &outer_keys.recv,
                    &recv_buf[..len],
                )?;
                let decoded = tunnel.decode_packet(&tunnel_bytes, now_secs())?;
                last_recv_secs = now_secs();
                adaptive.record_inbound(tunnel_bytes.len(), now_millis());
                adaptive.note_activity(last_recv_secs);
                for frame in decoded.frames {
                    match frame {
                        Frame::IpData(packet) => {
                            let _ = tun_tx.send(packet).await;
                        }
                        Frame::Close { .. } => {
                            persist_client_learning(persistent_state, &adaptive);
                            persistent_state.last_status = Some(RuntimeStatus::Disconnected);
                            persistent_state.store(&config.state_path)?;
                            let status = ClientStatus::new(
                                RuntimeStatus::Disconnected,
                                config.server_addr.to_string(),
                                Some(IpAddr::V4(transport.client_ipv4)),
                                Some(tun.interface_name.clone()),
                            );
                            return Ok(status);
                        }
                        _ => {}
                    }
                }
                if !decoded.ack_suggestions.is_empty() {
                    let payload_bytes = approximate_frame_bytes(&decoded.ack_suggestions);
                    send_frames_connected(
                        socket,
                        carrier,
                        &config.endpoint_id,
                        &outer_keys.send,
                        &mut tunnel,
                        &decoded.ack_suggestions,
                        now_secs(),
                    )
                    .await?;
                    last_send_secs = now_secs();
                    adaptive.record_outbound(payload_bytes, 1, now_millis());
                    adaptive.note_activity(last_send_secs);
                }
            }
            packet = tun_rx.recv() => {
                match packet {
                    Some(packet) => {
                        if let Some(delay) = adaptive.pacing_delay(packet.len(), 1) {
                            sleep(delay).await;
                        }
                        let (frames, payload_bytes, burst_len) =
                            collect_outbound_tun_frames(packet, &mut tun_rx, &adaptive);
                        send_frames_connected(
                            socket,
                            carrier,
                            &config.endpoint_id,
                            &outer_keys.send,
                            &mut tunnel,
                            &frames,
                            now_secs(),
                        )
                        .await?;
                        last_send_secs = now_secs();
                        adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                        adaptive.note_activity(last_send_secs);
                    }
                    None => break,
                }
            }
            _ = tick.tick() => {
                let now = now_secs();
                if let Some(mode) = adaptive.maybe_observe_stability(now) {
                    record_event(
                        telemetry,
                        &AptEvent::PolicyModeChanged { session_id, mode },
                        None,
                        observability,
                    );
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                }
                if let Some(mode) = adaptive.maybe_observe_quiet_impairment(now, last_recv_secs) {
                    record_event(
                        telemetry,
                        &AptEvent::PolicyModeChanged { session_id, mode },
                        None,
                        observability,
                    );
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                }
                if now.saturating_sub(last_recv_secs) > config.session_idle_timeout_secs {
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                    return Err(RuntimeError::Timeout("live session"));
                }
                let mut frames = tunnel.collect_due_control_frames(now);
                if adaptive.keepalive_due(now, last_send_secs) {
                    frames.extend(adaptive.build_keepalive_frames(64, now));
                }
                match tunnel.rekey_status(now) {
                    RekeyStatus::SoftLimitReached => {
                        if let Ok(frame) = tunnel.initiate_rekey(now) {
                            frames.push(frame);
                        }
                    }
                    RekeyStatus::HardLimitReached => {
                        persist_client_learning(persistent_state, &adaptive);
                        persistent_state.store(&config.state_path)?;
                        return Err(RuntimeError::Timeout("rekey hard limit reached"));
                    }
                    RekeyStatus::Healthy => {}
                }
                if !frames.is_empty() {
                    let payload_bytes = approximate_frame_bytes(&frames);
                    let burst_len = frames.iter().filter(|frame| matches!(frame, Frame::IpData(_))).count().max(1);
                    send_frames_connected(
                        socket,
                        carrier,
                        &config.endpoint_id,
                        &outer_keys.send,
                        &mut tunnel,
                        &frames,
                        now,
                    )
                    .await?;
                    last_send_secs = now;
                    adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                    adaptive.note_activity(now);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    persist_client_learning(persistent_state, &adaptive);
    let status = ClientStatus::new(
        RuntimeStatus::Disconnected,
        config.server_addr.to_string(),
        Some(IpAddr::V4(transport.client_ipv4)),
        Some(tun.interface_name),
    );
    persistent_state.last_status = Some(status.status.clone());
    Ok(status)
}

async fn process_server_tunnel_packet(
    socket: &UdpSocket,
    carrier: &D1Carrier,
    endpoint_id: &apt_types::EndpointId,
    session: &mut ServerSessionState,
    bytes: &[u8],
    now: u64,
    tun_tx: &mpsc::Sender<Vec<u8>>,
) -> Result<bool, RuntimeError> {
    let tunnel_bytes = match decode_tunnel_datagram(
        carrier,
        endpoint_id,
        &session.outer_keys.recv,
        bytes,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            debug!(error = %error, peer = %session.peer_addr, "failed to decode outer tunnel datagram; attempting admission parse");
            return Ok(false);
        }
    };
    match session.tunnel.decode_packet(&tunnel_bytes, now) {
        Ok(decoded) => {
            session.last_recv_secs = now;
            session
                .adaptive
                .record_inbound(tunnel_bytes.len(), now_millis());
            session.adaptive.note_activity(now);
            for frame in decoded.frames {
                match frame {
                    Frame::IpData(packet) => {
                        let _ = tun_tx.send(packet).await;
                    }
                    Frame::Close { .. } => {
                        return Ok(false);
                    }
                    _ => {}
                }
            }
            if !decoded.ack_suggestions.is_empty() {
                let payload_bytes = approximate_frame_bytes(&decoded.ack_suggestions);
                send_frames_to_peer(
                    socket,
                    carrier,
                    endpoint_id,
                    &session.outer_keys.send,
                    session.peer_addr,
                    &mut session.tunnel,
                    &decoded.ack_suggestions,
                    now,
                )
                .await?;
                session.last_send_secs = now;
                session
                    .adaptive
                    .record_outbound(payload_bytes, 1, now_millis());
                session.adaptive.note_activity(now);
            }
            Ok(true)
        }
        Err(error) => {
            debug!(error = %error, peer = %session.peer_addr, "failed to decode tunnel packet; attempting admission parse");
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_admission_packet(
    socket: &UdpSocket,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carrier: &D1Carrier,
    peer_addr: SocketAddr,
    received_len: usize,
    packet: AdmissionPacket,
    sessions_by_addr: &mut HashMap<SocketAddr, ServerSessionState>,
    sessions_by_client_ip: &mut HashMap<Ipv4Addr, SocketAddr>,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<bool, RuntimeError> {
    match admission.handle_c0(
        &peer_addr.to_string(),
        carrier,
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
                encode_admission_datagram(carrier, &config.endpoint_id, &outer_key, &reply)?;
            socket.send_to(&bytes, peer_addr).await?;
            return Ok(true);
        }
        ServerResponse::Drop(_) => {}
    }

    let server_reply = match admission.handle_c2_with_extension_builder(
        &peer_addr.to_string(),
        carrier,
        &packet,
        now_secs(),
        |session| {
            let peer = authorize_established_session(config, session)
                .map_err(|_| AdmissionError::Validation("unauthorized peer"))?;
            Ok(vec![bincode::serialize(
                &ServerSessionExtension::TunnelParameters(assign_transport_parameters(
                    config, peer,
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
        carrier,
        &config.endpoint_id,
        &confirmation_outer_key,
        &server_reply.packet,
    )?;
    socket.send_to(&bytes, peer_addr).await?;

    if let Some(existing_addr) = sessions_by_client_ip.insert(peer.tunnel_ipv4, peer_addr) {
        sessions_by_addr.remove(&existing_addr);
    }
    let outer_keys = derive_d1_tunnel_outer_keys(&server_reply.session.secrets)?;
    let adaptive = AdaptiveDatapath::new_server(
        server_reply.session.chosen_carrier,
        server_reply.session.secrets.persona_seed,
        server_reply.session.policy_mode,
        config.session_policy.allow_speed_first,
        admission_path_profile(None),
        now_secs(),
    );
    let tunnel = TunnelSession::new(
        server_reply.session.session_id,
        SessionRole::Responder,
        server_reply.session.secrets,
        server_reply.session.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now_secs(),
    );
    sessions_by_addr.insert(
        peer_addr,
        ServerSessionState {
            session_id: server_reply.session.session_id,
            peer_addr,
            assigned_ipv4: peer.tunnel_ipv4,
            tunnel,
            adaptive,
            outer_keys,
            last_send_secs: now_secs(),
            last_recv_secs: now_secs(),
        },
    );

    let credential_label = redact_credential(&server_reply.session.credential_identity);
    info!(
        peer = %peer_addr,
        assigned_ipv4 = %peer.tunnel_ipv4,
        credential = %credential_label,
        "server session established"
    );
    record_event(
        telemetry,
        &AptEvent::AdmissionAccepted {
            session_id: server_reply.session.session_id,
            carrier: server_reply.session.chosen_carrier,
            credential_identity: credential_label,
        },
        None,
        observability,
    );
    record_event(
        telemetry,
        &AptEvent::TunnelEstablished {
            session_id: server_reply.session.session_id,
            carrier: server_reply.session.chosen_carrier,
            mode: server_reply.session.policy_mode,
        },
        None,
        observability,
    );
    Ok(true)
}

async fn send_frames_connected(
    socket: &UdpSocket,
    carrier: &D1Carrier,
    endpoint_id: &apt_types::EndpointId,
    outer_key: &[u8; 32],
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    let datagram = encode_tunnel_datagram(carrier, endpoint_id, outer_key, &encoded.bytes)?;
    socket.send(&datagram).await?;
    Ok(())
}

async fn send_frames_to_peer(
    socket: &UdpSocket,
    carrier: &D1Carrier,
    endpoint_id: &apt_types::EndpointId,
    outer_key: &[u8; 32],
    peer_addr: SocketAddr,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    let datagram = encode_tunnel_datagram(carrier, endpoint_id, outer_key, &encoded.bytes)?;
    socket.send_to(&datagram, peer_addr).await?;
    Ok(())
}

fn extract_tunnel_parameters(
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

fn authorize_established_session(
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

fn assign_transport_parameters(
    config: &ResolvedServerConfig,
    peer: ResolvedAuthorizedPeer,
) -> SessionTransportParameters {
    SessionTransportParameters {
        client_ipv4: peer.tunnel_ipv4,
        server_ipv4: config.tunnel_local_ipv4,
        netmask: config.tunnel_netmask,
        mtu: config.tunnel_mtu,
        routes: config.push_routes.clone(),
        dns_servers: config.push_dns.clone(),
    }
}

fn admission_config(config: &ResolvedServerConfig, carrier: &D1Carrier) -> AdmissionConfig {
    let mut admission = AdmissionConfig::conservative(config.endpoint_id.clone());
    admission.allowed_carriers = vec![CarrierBinding::D1DatagramUdp];
    admission.default_policy = config.session_policy.initial_mode;
    admission.max_record_size = carrier.max_record_size();
    admission.tunnel_mtu = config.tunnel_mtu;
    admission.allowed_suites = vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s];
    admission
}

fn runtime_d1_carrier(tunnel_mtu: u16) -> D1Carrier {
    D1Carrier::new(1_472, tunnel_mtu)
}

fn build_udp_socket(
    bind: SocketAddr,
    recv_buffer_bytes: usize,
    send_buffer_bytes: usize,
) -> Result<UdpSocket, RuntimeError> {
    let domain = match bind {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_recv_buffer_size(recv_buffer_bytes)?;
    socket.set_send_buffer_size(send_buffer_bytes)?;
    socket.bind(&bind.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

fn decode_client_admission_packet(
    config: &ResolvedClientConfig,
    carrier: &D1Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_d1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_datagram(carrier, &config.endpoint_id, &outer_key, datagram).ok()
        })
}

fn decode_server_admission_packet(
    config: &ResolvedServerConfig,
    carrier: &D1Carrier,
    datagram: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_d1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_datagram(carrier, &config.endpoint_id, &outer_key, datagram).ok()
        })
}

fn candidate_epoch_slots(now_secs: u64) -> [u64; 3] {
    let slot = now_secs / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
    [slot.saturating_sub(1), slot, slot.saturating_add(1)]
}

fn collect_outbound_tun_frames(
    first_packet: Vec<u8>,
    tun_rx: &mut mpsc::Receiver<Vec<u8>>,
    adaptive: &AdaptiveDatapath,
) -> (Vec<Frame>, usize, usize) {
    let mut frames = vec![Frame::IpData(first_packet)];
    let mut payload_bytes = match &frames[0] {
        Frame::IpData(packet) => packet.len(),
        _ => 0,
    };
    let mut burst_len = 1;
    while burst_len < adaptive.burst_cap() {
        match tun_rx.try_recv() {
            Ok(packet) => {
                payload_bytes = payload_bytes.saturating_add(packet.len());
                frames.push(Frame::IpData(packet));
                burst_len += 1;
            }
            Err(_) => break,
        }
    }
    if let Some(padding) = adaptive.maybe_padding_frame(payload_bytes, false) {
        payload_bytes = payload_bytes.saturating_add(padding_len(&padding));
        frames.push(padding);
    }
    (frames, payload_bytes, burst_len)
}

fn approximate_frame_bytes(frames: &[Frame]) -> usize {
    frames.iter().map(frame_weight).sum::<usize>().max(64)
}

fn frame_weight(frame: &Frame) -> usize {
    match frame {
        Frame::IpData(packet) | Frame::Padding(packet) => packet.len(),
        Frame::CtrlAck { .. } => 16,
        Frame::PathChallenge { .. } | Frame::PathResponse { .. } => 24,
        Frame::SessionUpdate { .. } => 48,
        Frame::Ping => 8,
        Frame::Close { reason, .. } => 16 + reason.len(),
    }
}

fn padding_len(frame: &Frame) -> usize {
    match frame {
        Frame::Padding(bytes) => bytes.len(),
        _ => 0,
    }
}

fn persist_client_learning(
    persistent_state: &mut ClientPersistentState,
    adaptive: &AdaptiveDatapath,
) {
    persistent_state.network_profile =
        adaptive
            .local_normality_profile()
            .map(|normality| PersistedNetworkProfile {
                context: normality.context.clone(),
                normality,
                remembered_profile: adaptive.remembered_profile(),
                last_mode: adaptive.current_mode(),
            });
}

fn extract_destination_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    let version = packet.first().map(|value| value >> 4)?;
    if version == 4 && packet.len() >= 20 {
        Some(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))
    } else {
        None
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn redact_credential(identity: &CredentialIdentity) -> String {
    match identity {
        CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
        CredentialIdentity::User(user) => format!("user:{user}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_destination_parsing_works() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 77, 0, 2, 8, 8, 8, 8,
        ];
        assert_eq!(
            extract_destination_ipv4(&packet),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
    }

    #[test]
    fn candidate_epoch_slots_cover_adjacent_slots() {
        assert_eq!(
            candidate_epoch_slots(DEFAULT_ADMISSION_EPOCH_SLOT_SECS),
            [0, 1, 2]
        );
    }
}
