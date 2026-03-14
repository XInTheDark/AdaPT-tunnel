use crate::{
    adaptive::{admission_path_profile, build_client_network_context, AdaptiveDatapath},
    config::{
        ClientPersistentState, PersistedNetworkProfile, ResolvedAuthorizedPeer,
        ResolvedClientConfig, ResolvedServerConfig, ServerSessionExtension,
        SessionTransportParameters,
    },
    error::RuntimeError,
    route::{configure_client_network_for_endpoints, configure_server_network},
    status::{ClientStatus, RuntimeStatus, ServerStatus},
    tun::{spawn_tun_worker, TunHandle, TunInterfaceConfig},
    wire::{
        decode_admission_datagram, decode_admission_stream_payload, decode_confirmation_datagram,
        decode_confirmation_stream_payload, decode_tunnel_datagram, decode_tunnel_stream_payload,
        derive_d1_admission_outer_key, derive_d1_confirmation_outer_key,
        derive_d1_tunnel_outer_keys, derive_s1_admission_outer_key,
        derive_s1_confirmation_outer_key, derive_s1_tunnel_outer_keys, encode_admission_datagram,
        encode_admission_stream_payload, encode_confirmation_datagram,
        encode_confirmation_stream_payload, encode_tunnel_datagram, encode_tunnel_stream_payload,
        D1OuterKeys, S1OuterKeys,
    },
};
use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionError, AdmissionPacket, AdmissionServer,
    AdmissionServerSecrets, ClientCredential, ClientSessionRequest, CredentialStore,
    EstablishedSession, ServerConfirmationPacket, ServerResponse,
};
use apt_carriers::{CarrierError, CarrierProfile, D1Carrier, S1Carrier};
use apt_crypto::{SealedEnvelope, StaticKeypair};
use apt_observability::{record_event, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_tunnel::{Frame, RekeyStatus, TunnelSession};
use apt_types::{
    AuthProfile, CarrierBinding, CipherSuite, CredentialIdentity, PathSignalEvent, SessionId,
    SessionRole, DEFAULT_ADMISSION_EPOCH_SLOT_SECS, MINIMUM_REPLAY_WINDOW,
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time::{interval, sleep, timeout},
};
use tracing::{debug, info, warn};

const DATAGRAM_BUFFER_SIZE: usize = 65_535;
const PATH_VALIDATION_TIMEOUT_SECS: u64 = 10;
const PATH_VALIDATION_RETRY_SECS: u64 = 2;
const STREAM_DECOY_BODY: &str = "<html><body><h1>It works</h1></body></html>";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PathHandle {
    Datagram(SocketAddr),
    Stream(u64),
}

#[derive(Clone, Debug)]
struct RuntimeOuterKeys {
    d1: D1OuterKeys,
    s1: S1OuterKeys,
}

impl RuntimeOuterKeys {
    fn send_for(&self, binding: CarrierBinding) -> Result<&[u8; 32], RuntimeError> {
        match binding {
            CarrierBinding::D1DatagramUdp => Ok(&self.d1.send),
            CarrierBinding::S1EncryptedStream => Ok(&self.s1.send),
            _ => Err(RuntimeError::InvalidConfig(format!(
                "unsupported runtime carrier {binding:?}"
            ))),
        }
    }

    fn recv_for(&self, binding: CarrierBinding) -> Result<&[u8; 32], RuntimeError> {
        match binding {
            CarrierBinding::D1DatagramUdp => Ok(&self.d1.recv),
            CarrierBinding::S1EncryptedStream => Ok(&self.s1.recv),
            _ => Err(RuntimeError::InvalidConfig(format!(
                "unsupported runtime carrier {binding:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
enum StreamWrite {
    CarrierPayload(Vec<u8>),
    Raw(Vec<u8>),
}

#[derive(Clone, Debug)]
enum PathSender {
    Datagram(mpsc::UnboundedSender<Vec<u8>>),
    Stream(mpsc::UnboundedSender<StreamWrite>),
}

#[derive(Debug)]
struct ClientPathState {
    id: u64,
    binding: CarrierBinding,
    sender: PathSender,
    validated: bool,
    pending_probe_challenge: Option<[u8; 8]>,
    last_send_secs: u64,
    last_recv_secs: u64,
}

#[derive(Debug)]
enum ClientTransportEvent {
    Inbound { path_id: u64, bytes: Vec<u8> },
    Closed { path_id: u64, reason: &'static str },
}

#[derive(Debug)]
enum HandshakeTransport {
    Datagram(UdpSocket),
    Stream(TcpStream),
}

#[derive(Debug)]
struct HandshakeSuccess {
    binding: CarrierBinding,
    established: EstablishedSession,
    transport: HandshakeTransport,
}

#[derive(Clone, Debug)]
struct ServerPathState {
    handle: PathHandle,
    binding: CarrierBinding,
    last_send_secs: u64,
    last_recv_secs: u64,
}

#[derive(Clone, Debug)]
struct PendingPathValidation {
    handle: PathHandle,
    binding: CarrierBinding,
    challenge: [u8; 8],
    issued_secs: u64,
    retries: u8,
}

#[derive(Debug)]
struct ServerSessionState {
    session_id: SessionId,
    assigned_ipv4: Ipv4Addr,
    tunnel: TunnelSession,
    adaptive: AdaptiveDatapath,
    outer_keys: RuntimeOuterKeys,
    primary_path: ServerPathState,
    standby_path: Option<ServerPathState>,
    pending_validation: Option<PendingPathValidation>,
}

#[derive(Clone, Debug)]
struct ServerStreamPeer {
    peer_addr: SocketAddr,
    sender: mpsc::UnboundedSender<StreamWrite>,
}

#[derive(Debug)]
enum ServerTransportEvent {
    Datagram {
        peer_addr: SocketAddr,
        bytes: Vec<u8>,
    },
    StreamOpened {
        conn_id: u64,
        peer_addr: SocketAddr,
        sender: mpsc::UnboundedSender<StreamWrite>,
    },
    StreamRecord {
        conn_id: u64,
        bytes: Vec<u8>,
    },
    StreamClosed {
        conn_id: u64,
        malformed: bool,
    },
}

#[derive(Debug)]
struct MatchedServerPacket {
    session_id: SessionId,
    tunnel: TunnelSession,
    decoded: apt_tunnel::DecodedPacket,
    tunnel_bytes_len: usize,
}

pub async fn run_client(config: ResolvedClientConfig) -> Result<ClientRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-client");
    let carriers = RuntimeCarriers::new(1_380, false);

    let mut persistent_state = ClientPersistentState::load(&config.state_path)?;
    persistent_state.last_status = Some(RuntimeStatus::Starting);
    persistent_state.store(&config.state_path)?;

    let handshake = perform_client_handshake(
        &config,
        &mut persistent_state,
        &carriers,
        &mut telemetry,
        &observability,
    )
    .await?;
    let transport = extract_tunnel_parameters(&handshake.established)?;
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
    let exempt_endpoints = client_route_exempt_endpoints(&config);
    let _route_guard = configure_client_network_for_endpoints(
        &tun.interface_name,
        &exempt_endpoints,
        &effective_routes,
    )?;

    info!(
        server = %config.server_addr,
        tunnel_ip = %transport.client_ipv4,
        server_tunnel_ip = %transport.server_ipv4,
        interface = %tun.interface_name,
        routes = ?effective_routes,
        carrier = %handshake.binding.as_str(),
        "client session established"
    );

    let credential_label = redact_credential(&handshake.established.credential_identity);
    record_event(
        &mut telemetry,
        &AptEvent::AdmissionAccepted {
            session_id: handshake.established.session_id,
            carrier: handshake.established.chosen_carrier,
            credential_identity: credential_label,
        },
        None,
        &observability,
    );
    record_event(
        &mut telemetry,
        &AptEvent::TunnelEstablished {
            session_id: handshake.established.session_id,
            carrier: handshake.established.chosen_carrier,
            mode: handshake.established.policy_mode,
        },
        None,
        &observability,
    );

    let status = run_client_session_loop(
        &config,
        tun,
        handshake,
        transport,
        &mut persistent_state,
        &mut telemetry,
        &observability,
        &carriers,
    )
    .await?;
    persistent_state.last_status = Some(status.status.clone());
    persistent_state.store(&config.state_path)?;
    Ok(ClientRuntimeResult { status, telemetry })
}

pub async fn run_server(config: ResolvedServerConfig) -> Result<ServerRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-edge");
    let carriers = RuntimeCarriers::new(config.tunnel_mtu, config.stream_decoy_surface);

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
        mtu: config.tunnel_mtu,
    })
    .await?;
    let _server_net_guard = configure_server_network(&tun.interface_name, &config)?;

    let mut credentials = CredentialStore::default();
    credentials.set_shared_deployment_key(config.admission_key);
    let mut admission = AdmissionServer::new(
        admission_config(&config, &carriers),
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
                                if let Some(delay) = session.adaptive.pacing_delay(packet.len(), 1) {
                                    sleep(delay).await;
                                }
                                let (frames, payload_bytes, burst_len) =
                                    collect_outbound_tun_frames(packet, &mut tun_rx, &session.adaptive);
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

async fn run_client_session_loop(
    config: &ResolvedClientConfig,
    tun: TunHandle,
    handshake: HandshakeSuccess,
    transport: SessionTransportParameters,
    persistent_state: &mut ClientPersistentState,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    carriers: &RuntimeCarriers,
) -> Result<ClientStatus, RuntimeError> {
    let outer_keys = RuntimeOuterKeys {
        d1: derive_d1_tunnel_outer_keys(&handshake.established.secrets)?,
        s1: derive_s1_tunnel_outer_keys(&handshake.established.secrets)?,
    };
    let mut adaptive = AdaptiveDatapath::new_client(
        handshake.established.chosen_carrier,
        handshake.established.secrets.persona_seed,
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
    persistent_state.last_successful_carrier = Some(handshake.binding);
    persistent_state.store(&config.state_path)?;

    let session_id = handshake.established.session_id;
    let mut tunnel = TunnelSession::new(
        handshake.established.session_id,
        SessionRole::Initiator,
        handshake.established.secrets,
        handshake.established.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now_secs(),
    );
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let mut paths = HashMap::new();
    let mut next_path_id = 1_u64;
    let active_path = spawn_client_transport_path(
        next_path_id,
        handshake.binding,
        handshake.transport,
        event_tx.clone(),
        carriers,
    )?;
    let mut active_path_id = active_path.id;
    let mut standby_path_id = None;
    next_path_id += 1;
    paths.insert(active_path.id, active_path);

    let mut tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();
    let mut migration_pressure = 0_u8;
    let mut next_standby_probe_secs =
        schedule_next_standby_probe(now_secs(), config.standby_health_check_secs, &adaptive);

    loop {
        tokio::select! {
            maybe_event = event_rx.recv() => {
                let Some(event) = maybe_event else { break; };
                match event {
                    ClientTransportEvent::Inbound { path_id, bytes } => {
                        let Some(path) = paths.get_mut(&path_id) else { continue; };
                        let tunnel_bytes = decode_client_tunnel_packet(
                            carriers,
                            &config.endpoint_id,
                            &outer_keys,
                            path.binding,
                            &bytes,
                        )?;
                        let decoded = tunnel.decode_packet(&tunnel_bytes, now_secs())?;
                        path.last_recv_secs = now_secs();
                        adaptive.record_inbound(tunnel_bytes.len(), now_millis());
                        adaptive.note_activity(path.last_recv_secs);
                        if path_id != active_path_id && path.validated {
                            active_path_id = path_id;
                            persistent_state.last_successful_carrier = Some(path.binding);
                            record_event(
                                telemetry,
                                &AptEvent::CarrierMigrated {
                                    session_id,
                                    from: None,
                                    to: path.binding,
                                },
                                None,
                                observability,
                            );
                        }
                        let mut response_frames = decoded.ack_suggestions;
                        let mut saw_data = false;
                        let mut saw_probe_response = false;
                        for frame in decoded.frames {
                            match frame {
                                Frame::IpData(packet) => {
                                    saw_data = true;
                                    let _ = tun_tx.send(packet).await;
                                }
                                Frame::PathChallenge { challenge, .. } => {
                                    let control_id = tunnel.next_control_id();
                                    response_frames.push(Frame::PathResponse { control_id, challenge });
                                }
                                Frame::PathResponse { challenge, .. } => {
                                    if path.pending_probe_challenge == Some(challenge) {
                                        path.validated = true;
                                        path.pending_probe_challenge = None;
                                        standby_path_id = Some(path_id).filter(|id| *id != active_path_id);
                                        saw_probe_response = true;
                                        record_event(
                                            telemetry,
                                            &AptEvent::StandbyProbeResult {
                                                session_id,
                                                carrier: path.binding,
                                                success: true,
                                            },
                                            None,
                                            observability,
                                        );
                                    }
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
                                        Some(paths.get(&active_path_id).map(|state| state.binding).unwrap_or(handshake.binding)),
                                        standby_path_id.and_then(|id| paths.get(&id).map(|state| state.binding)),
                                        Some(adaptive.current_mode()),
                                    );
                                    return Ok(status);
                                }
                                _ => {}
                            }
                        }
                        if saw_data && path_id != active_path_id {
                            active_path_id = path_id;
                            persistent_state.last_successful_carrier = Some(path.binding);
                            record_event(
                                telemetry,
                                &AptEvent::CarrierMigrated {
                                    session_id,
                                    from: None,
                                    to: path.binding,
                                },
                                None,
                                observability,
                            );
                        }
                        if saw_probe_response {
                            migration_pressure = 0;
                        }
                        if !response_frames.is_empty() {
                            let payload_bytes = approximate_frame_bytes(&response_frames);
                            send_frames_on_client_path(
                                carriers,
                                &config.endpoint_id,
                                &outer_keys,
                                paths.get(&path_id).expect("path exists"),
                                &mut tunnel,
                                &response_frames,
                                now_secs(),
                            )
                            .await?;
                            if let Some(path) = paths.get_mut(&path_id) {
                                path.last_send_secs = now_secs();
                            }
                            adaptive.record_outbound(payload_bytes, 1, now_millis());
                            adaptive.note_activity(now_secs());
                        }
                    }
                    ClientTransportEvent::Closed { path_id, reason } => {
                        let binding = paths.get(&path_id).map(|path| path.binding);
                        paths.remove(&path_id);
                        if standby_path_id == Some(path_id) {
                            standby_path_id = None;
                        }
                        if Some(path_id) == Some(active_path_id) {
                            migration_pressure = migration_pressure.saturating_add(1);
                            if let Some(mode) = adaptive.apply_signal(PathSignalEvent::ImmediateReset, now_secs()) {
                                record_event(
                                    telemetry,
                                    &AptEvent::PolicyModeChanged { session_id, mode },
                                    None,
                                    observability,
                                );
                            }
                            if let Some(standby_id) = standby_path_id {
                                if let Some(standby) = paths.get(&standby_id) {
                                    active_path_id = standby.id;
                                    persistent_state.last_successful_carrier = Some(standby.binding);
                                    record_event(
                                        telemetry,
                                        &AptEvent::CarrierMigrated {
                                            session_id,
                                            from: binding,
                                            to: standby.binding,
                                        },
                                        None,
                                        observability,
                                    );
                                }
                            } else if reason == "stream closed" {
                                record_event(
                                    telemetry,
                                    &AptEvent::CarrierFallback {
                                        session_id,
                                        from: binding,
                                        to: CarrierBinding::D1DatagramUdp,
                                        reason,
                                    },
                                    None,
                                    observability,
                                );
                            }
                        }
                    }
                }
            }
            packet = tun_rx.recv() => {
                match packet {
                    Some(packet) => {
                        let Some(active_path) = paths.get(&active_path_id) else {
                            return Err(RuntimeError::Timeout("all transports closed"));
                        };
                        if let Some(delay) = adaptive.pacing_delay(packet.len(), 1) {
                            sleep(delay).await;
                        }
                        let (frames, payload_bytes, burst_len) =
                            collect_outbound_tun_frames(packet, &mut tun_rx, &adaptive);
                        send_frames_on_client_path(
                            carriers,
                            &config.endpoint_id,
                            &outer_keys,
                            active_path,
                            &mut tunnel,
                            &frames,
                            now_secs(),
                        )
                        .await?;
                        if let Some(active_path) = paths.get_mut(&active_path_id) {
                            active_path.last_send_secs = now_secs();
                        }
                        adaptive.record_outbound(payload_bytes, burst_len, now_millis());
                        adaptive.note_activity(now_secs());
                    }
                    None => break,
                }
            }
            _ = tick.tick() => {
                let now = now_secs();
                if let Some(mode) = adaptive.maybe_observe_stability(now) {
                    migration_pressure = migration_pressure.saturating_sub(1);
                    record_event(
                        telemetry,
                        &AptEvent::PolicyModeChanged { session_id, mode },
                        None,
                        observability,
                    );
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                }
                if let Some(mode) = adaptive.maybe_observe_quiet_impairment(
                    now,
                    paths.get(&active_path_id).map_or(now, |path| path.last_recv_secs),
                ) {
                    migration_pressure = migration_pressure.saturating_add(1);
                    record_event(
                        telemetry,
                        &AptEvent::PolicyModeChanged { session_id, mode },
                        None,
                        observability,
                    );
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                }
                let active_last_recv = paths.get(&active_path_id).map_or(0, |path| path.last_recv_secs);
                if active_last_recv > 0 && now.saturating_sub(active_last_recv) > config.session_idle_timeout_secs {
                    if let Some(standby_id) = standby_path_id {
                        if let Some(standby) = paths.get(&standby_id) {
                            active_path_id = standby.id;
                            persistent_state.last_successful_carrier = Some(standby.binding);
                            record_event(
                                telemetry,
                                &AptEvent::CarrierMigrated {
                                    session_id,
                                    from: None,
                                    to: standby.binding,
                                },
                                None,
                                observability,
                            );
                        }
                    } else {
                        persist_client_learning(persistent_state, &adaptive);
                        persistent_state.store(&config.state_path)?;
                        return Err(RuntimeError::Timeout("live session"));
                    }
                }
                if migration_pressure >= adaptive.migration_threshold() {
                    if let Some(standby_id) = standby_path_id {
                        if let Some(standby) = paths.get(&standby_id) {
                            active_path_id = standby.id;
                            migration_pressure = 0;
                            persistent_state.last_successful_carrier = Some(standby.binding);
                            record_event(
                                telemetry,
                                &AptEvent::CarrierMigrated {
                                    session_id,
                                    from: None,
                                    to: standby.binding,
                                },
                                None,
                                observability,
                            );
                        }
                    }
                }
                if config.allow_session_migration && standby_path_id.is_none() && now >= next_standby_probe_secs {
                    if let Some(binding) = next_standby_candidate(config, &adaptive, &paths, active_path_id) {
                        match open_client_standby_path(
                            next_path_id,
                            binding,
                            config,
                            carriers,
                            event_tx.clone(),
                        )
                        .await {
                            Ok(mut path) => {
                                next_path_id = next_path_id.saturating_add(1);
                                let challenge: [u8; 8] = rand::random();
                                let control_id = tunnel.next_control_id();
                                path.pending_probe_challenge = Some(challenge);
                                send_frames_on_client_path(
                                    carriers,
                                    &config.endpoint_id,
                                    &outer_keys,
                                    &path,
                                    &mut tunnel,
                                    &[Frame::PathChallenge {
                                        control_id,
                                        challenge,
                                    }],
                                    now,
                                )
                                .await?;
                                record_event(
                                    telemetry,
                                    &AptEvent::StandbyProbeResult {
                                        session_id,
                                        carrier: binding,
                                        success: true,
                                    },
                                    None,
                                    observability,
                                );
                                path.last_send_secs = now;
                                standby_path_id = Some(path.id);
                                paths.insert(path.id, path);
                            }
                            Err(error) => {
                                warn!(carrier = %binding.as_str(), error = %error, "standby path open failed");
                                migration_pressure = migration_pressure.saturating_add(1);
                                if let Some(mode) = adaptive.apply_signal(PathSignalEvent::FallbackFailure, now) {
                                    record_event(
                                        telemetry,
                                        &AptEvent::PolicyModeChanged { session_id, mode },
                                        None,
                                        observability,
                                    );
                                }
                                record_event(
                                    telemetry,
                                    &AptEvent::StandbyProbeResult {
                                        session_id,
                                        carrier: binding,
                                        success: false,
                                    },
                                    None,
                                    observability,
                                );
                            }
                        }
                    }
                    next_standby_probe_secs = schedule_next_standby_probe(
                        now,
                        config.standby_health_check_secs,
                        &adaptive,
                    );
                }
                let mut frames = tunnel.collect_due_control_frames(now);
                if let Some(active_path) = paths.get(&active_path_id) {
                    if adaptive.keepalive_due(now, active_path.last_send_secs) {
                        frames.extend(adaptive.build_keepalive_frames(64, now));
                    }
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
                    let Some(active_path) = paths.get(&active_path_id) else {
                        return Err(RuntimeError::Timeout("active path missing"));
                    };
                    send_frames_on_client_path(
                        carriers,
                        &config.endpoint_id,
                        &outer_keys,
                        active_path,
                        &mut tunnel,
                        &frames,
                        now,
                    )
                    .await?;
                    if let Some(active_path) = paths.get_mut(&active_path_id) {
                        active_path.last_send_secs = now;
                    }
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
        paths.get(&active_path_id).map(|state| state.binding),
        standby_path_id.and_then(|id| paths.get(&id).map(|state| state.binding)),
        Some(adaptive.current_mode()),
    );
    persistent_state.last_status = Some(status.status.clone());
    Ok(status)
}

async fn perform_client_handshake(
    config: &ResolvedClientConfig,
    persistent_state: &mut ClientPersistentState,
    carriers: &RuntimeCarriers,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
) -> Result<HandshakeSuccess, RuntimeError> {
    let resume_ticket = persistent_state
        .resume_ticket
        .as_ref()
        .map(|bytes| bincode::deserialize::<SealedEnvelope>(bytes))
        .transpose()?;
    let order = client_carrier_attempt_order(config, persistent_state);
    let mut last_error = None;

    for (index, binding) in order.iter().copied().enumerate() {
        let attempt = match binding {
            CarrierBinding::D1DatagramUdp => {
                attempt_client_handshake_d1(
                    config,
                    persistent_state,
                    carriers.d1(),
                    resume_ticket.clone(),
                    &order,
                )
                .await
            }
            CarrierBinding::S1EncryptedStream => {
                attempt_client_handshake_s1(
                    config,
                    persistent_state,
                    carriers.s1(),
                    resume_ticket.clone(),
                    &order,
                )
                .await
            }
            _ => continue,
        };
        match attempt {
            Ok(success) => {
                persistent_state.resume_ticket = success
                    .established
                    .resume_ticket
                    .as_ref()
                    .map(bincode::serialize)
                    .transpose()?;
                persistent_state.last_successful_carrier = Some(binding);
                persistent_state.store(&config.state_path)?;
                if index > 0 {
                    record_event(
                        telemetry,
                        &AptEvent::CarrierFallback {
                            session_id: success.established.session_id,
                            from: None,
                            to: binding,
                            reason: "fallback-success",
                        },
                        None,
                        observability,
                    );
                }
                return Ok(success);
            }
            Err(error) => {
                warn!(carrier = %binding.as_str(), error = %error, "handshake attempt failed");
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or(RuntimeError::Timeout("admission handshake")))
}

async fn attempt_client_handshake_d1(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    carrier: &D1Carrier,
    resume_ticket: Option<SealedEnvelope>,
    supported_carriers: &[CarrierBinding],
) -> Result<HandshakeSuccess, RuntimeError> {
    let socket = build_udp_socket(
        config.bind,
        config.udp_recv_buffer_bytes,
        config.udp_send_buffer_bytes,
    )?;
    socket.connect(config.server_addr).await?;

    for _ in 0..config.handshake_retries {
        let now = now_secs();
        let current_epoch_slot = now / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
        let outer_key = derive_d1_admission_outer_key(&config.admission_key, current_epoch_slot)?;
        let credential = client_credential(config);
        let request = client_session_request(
            config,
            persistent_state,
            CarrierBinding::D1DatagramUdp,
            supported_carriers,
            resume_ticket.clone(),
            now,
        );
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_bytes = encode_admission_datagram(
            carrier,
            &config.endpoint_id,
            &outer_key,
            &prepared_c0.packet,
        )?;
        socket.send(&c0_bytes).await?;

        let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
        let s1_len = match timeout(
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
            &recv_buf[..s1_len],
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
        let s3_len = match timeout(
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
            &recv_buf[..s3_len],
        )?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        return Ok(HandshakeSuccess {
            binding: CarrierBinding::D1DatagramUdp,
            established: session,
            transport: HandshakeTransport::Datagram(socket),
        });
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

async fn attempt_client_handshake_s1(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    carrier: &S1Carrier,
    resume_ticket: Option<SealedEnvelope>,
    supported_carriers: &[CarrierBinding],
) -> Result<HandshakeSuccess, RuntimeError> {
    let Some(server_addr) = config.stream_server_addr else {
        return Err(RuntimeError::InvalidConfig(
            "stream fallback is enabled but no stream_server_addr is configured".to_string(),
        ));
    };
    for _ in 0..config.handshake_retries {
        let mut stream = TcpStream::connect(server_addr).await?;
        let _ = stream.set_nodelay(true);
        let now = now_secs();
        let current_epoch_slot = now / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
        let outer_key = derive_s1_admission_outer_key(&config.admission_key, current_epoch_slot)?;
        let credential = client_credential(config);
        let request = client_session_request(
            config,
            persistent_state,
            CarrierBinding::S1EncryptedStream,
            supported_carriers,
            resume_ticket.clone(),
            now,
        );
        let prepared_c0 = initiate_c0(credential, request, carrier)?;
        let c0_payload =
            encode_admission_stream_payload(&config.endpoint_id, &outer_key, &prepared_c0.packet)?;
        write_s1_payload(&mut stream, carrier, &c0_payload).await?;

        let s1_payload = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            read_s1_payload(&mut stream, carrier),
        )
        .await
        {
            Ok(Ok(payload)) => payload,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s1 = match decode_client_stream_admission_packet(config, &s1_payload, now_secs()) {
            Some(packet) => packet,
            None => continue,
        };
        let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier)?;
        let c2_payload =
            encode_admission_stream_payload(&config.endpoint_id, &outer_key, &prepared_c2.packet)?;
        write_s1_payload(&mut stream, carrier, &c2_payload).await?;

        let confirmation_outer_key =
            derive_s1_confirmation_outer_key(prepared_c2.state.confirmation_recv_ctrl_key())?;
        let s3_payload = match timeout(
            Duration::from_secs(config.handshake_timeout_secs),
            read_s1_payload(&mut stream, carrier),
        )
        .await
        {
            Ok(Ok(payload)) => payload,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        };
        let s3: ServerConfirmationPacket = decode_confirmation_stream_payload(
            &config.endpoint_id,
            &confirmation_outer_key,
            &s3_payload,
        )?;
        let session = prepared_c2.state.handle_s3(&s3, carrier)?;
        return Ok(HandshakeSuccess {
            binding: CarrierBinding::S1EncryptedStream,
            established: session,
            transport: HandshakeTransport::Stream(stream),
        });
    }

    Err(RuntimeError::Timeout("admission handshake"))
}

async fn handle_server_admission_datagram(
    socket: &UdpSocket,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
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

async fn handle_server_admission_stream(
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    admission: &mut AdmissionServer,
    config: &ResolvedServerConfig,
    carriers: &RuntimeCarriers,
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
                    config, authorized,
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

async fn process_known_server_path(
    udp_socket: &UdpSocket,
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
        binding,
        &bytes,
    )?;
    let decoded = session.tunnel.decode_packet(&tunnel_bytes, now_secs())?;
    handle_server_decoded_packet(
        udp_socket,
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

async fn process_migrated_server_path(
    udp_socket: &UdpSocket,
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

async fn handle_server_decoded_packet(
    udp_socket: &UdpSocket,
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
            Frame::Ping => {
                saw_switchworthy_traffic = true;
            }
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

fn handle_server_path_loss(
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

fn expire_server_session(
    sessions: &mut HashMap<SessionId, ServerSessionState>,
    path_to_session: &mut HashMap<PathHandle, SessionId>,
    sessions_by_client_ip: &mut HashMap<Ipv4Addr, SessionId>,
    session_id: SessionId,
) {
    if let Some(session) = sessions.remove(&session_id) {
        path_to_session.remove(&session.primary_path.handle);
        if let Some(standby) = session.standby_path {
            path_to_session.remove(&standby.handle);
        }
        sessions_by_client_ip.remove(&session.assigned_ipv4);
    }
}

fn try_match_server_session(
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

fn client_session_request(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    preferred_carrier: CarrierBinding,
    supported_carriers: &[CarrierBinding],
    resume_ticket: Option<SealedEnvelope>,
    now: u64,
) -> ClientSessionRequest {
    let mut request = ClientSessionRequest::conservative(config.endpoint_id.clone(), now);
    request.preferred_carrier = preferred_carrier;
    request.supported_carriers = supported_carriers.to_vec();
    request.policy_mode = config.session_policy.initial_mode;
    request.policy_flags.allow_speed_first = config.session_policy.allow_speed_first;
    request.policy_flags.allow_hybrid_pq = config.session_policy.allow_hybrid_pq;
    request.path_profile = admission_path_profile(
        persistent_state
            .network_profile
            .as_ref()
            .map(|profile| &profile.normality),
    );
    request.resume_ticket = resume_ticket;
    request
}

fn client_credential(config: &ResolvedClientConfig) -> ClientCredential {
    ClientCredential {
        auth_profile: AuthProfile::SharedDeployment,
        user_id: config.client_identity.clone(),
        client_static_private: Some(config.client_static_private_key),
        admission_key: config.admission_key,
        server_static_public: config.server_static_public_key,
        enable_lookup_hint: false,
    }
}

fn client_carrier_attempt_order(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
) -> Vec<CarrierBinding> {
    let mut available = vec![CarrierBinding::D1DatagramUdp];
    if config.enable_s1_fallback && config.stream_server_addr.is_some() {
        available.push(CarrierBinding::S1EncryptedStream);
    }
    let remembered = config
        .preferred_carrier
        .binding()
        .or(persistent_state.last_successful_carrier)
        .or_else(|| {
            persistent_state
                .network_profile
                .as_ref()
                .and_then(|profile| profile.remembered_profile.as_ref())
                .map(|profile| profile.preferred_carrier)
        });
    let mut order = Vec::new();
    if let Some(binding) = remembered {
        if available.contains(&binding) {
            order.push(binding);
        }
    }
    for binding in [
        CarrierBinding::D1DatagramUdp,
        CarrierBinding::S1EncryptedStream,
    ] {
        if available.contains(&binding) && !order.contains(&binding) {
            order.push(binding);
        }
    }
    order
}

fn next_standby_candidate(
    config: &ResolvedClientConfig,
    adaptive: &AdaptiveDatapath,
    paths: &HashMap<u64, ClientPathState>,
    active_path_id: u64,
) -> Option<CarrierBinding> {
    let active_binding = paths.get(&active_path_id)?.binding;
    adaptive
        .fallback_order()
        .into_iter()
        .filter(|binding| {
            matches!(
                binding,
                CarrierBinding::D1DatagramUdp | CarrierBinding::S1EncryptedStream
            )
        })
        .find(|binding| {
            *binding != active_binding
                && (*binding != CarrierBinding::S1EncryptedStream
                    || (config.enable_s1_fallback && config.stream_server_addr.is_some()))
                && !paths.values().any(|path| path.binding == *binding)
        })
}

fn schedule_next_standby_probe(now: u64, override_secs: u64, adaptive: &AdaptiveDatapath) -> u64 {
    let base = if override_secs > 0 {
        override_secs
    } else {
        adaptive.standby_health_check_secs()
    }
    .max(10);
    now.saturating_add(jittered_interval_secs(base))
}

fn jittered_interval_secs(base: u64) -> u64 {
    let jitter = rand::random::<u8>() % 41;
    let percent = 80 + u64::from(jitter);
    base.saturating_mul(percent) / 100
}

async fn open_client_standby_path(
    path_id: u64,
    binding: CarrierBinding,
    config: &ResolvedClientConfig,
    carriers: &RuntimeCarriers,
    event_tx: mpsc::UnboundedSender<ClientTransportEvent>,
) -> Result<ClientPathState, RuntimeError> {
    match binding {
        CarrierBinding::D1DatagramUdp => {
            let socket = build_udp_socket(
                config.bind,
                config.udp_recv_buffer_bytes,
                config.udp_send_buffer_bytes,
            )?;
            socket.connect(config.server_addr).await?;
            spawn_client_transport_path(
                path_id,
                binding,
                HandshakeTransport::Datagram(socket),
                event_tx,
                carriers,
            )
        }
        CarrierBinding::S1EncryptedStream => {
            let Some(addr) = config.stream_server_addr else {
                return Err(RuntimeError::InvalidConfig(
                    "stream_server_addr is not configured".to_string(),
                ));
            };
            let stream = TcpStream::connect(addr).await?;
            let _ = stream.set_nodelay(true);
            spawn_client_transport_path(
                path_id,
                binding,
                HandshakeTransport::Stream(stream),
                event_tx,
                carriers,
            )
        }
        _ => Err(RuntimeError::InvalidConfig(
            "unsupported standby carrier".to_string(),
        )),
    }
}

fn spawn_client_transport_path(
    path_id: u64,
    binding: CarrierBinding,
    transport: HandshakeTransport,
    event_tx: mpsc::UnboundedSender<ClientTransportEvent>,
    carriers: &RuntimeCarriers,
) -> Result<ClientPathState, RuntimeError> {
    match transport {
        HandshakeTransport::Datagram(socket) => {
            let socket = Arc::new(socket);
            let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let reader_socket = socket.clone();
            let writer_socket = socket.clone();
            let event_tx_reader = event_tx.clone();
            tokio::spawn(async move {
                let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
                loop {
                    match reader_socket.recv(&mut recv_buf).await {
                        Ok(len) => {
                            if event_tx_reader
                                .send(ClientTransportEvent::Inbound {
                                    path_id,
                                    bytes: recv_buf[..len].to_vec(),
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = event_tx_reader.send(ClientTransportEvent::Closed {
                                path_id,
                                reason: "udp closed",
                            });
                            break;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(bytes) = send_rx.recv().await {
                    if writer_socket.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
            Ok(ClientPathState {
                id: path_id,
                binding,
                sender: PathSender::Datagram(send_tx),
                validated: true,
                pending_probe_challenge: None,
                last_send_secs: now_secs(),
                last_recv_secs: now_secs(),
            })
        }
        HandshakeTransport::Stream(stream) => {
            let (mut reader, mut writer) = stream.into_split();
            let (send_tx, mut send_rx) = mpsc::unbounded_channel();
            let event_tx_reader = event_tx.clone();
            let carrier = *carriers.s1();
            tokio::spawn(async move {
                loop {
                    match read_s1_payload(&mut reader, &carrier).await {
                        Ok(bytes) => {
                            if event_tx_reader
                                .send(ClientTransportEvent::Inbound { path_id, bytes })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = event_tx_reader.send(ClientTransportEvent::Closed {
                                path_id,
                                reason: "stream closed",
                            });
                            break;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some(write) = send_rx.recv().await {
                    let result = match write {
                        StreamWrite::CarrierPayload(payload) => {
                            write_s1_payload(&mut writer, &carrier, &payload).await
                        }
                        StreamWrite::Raw(bytes) => {
                            writer.write_all(&bytes).await.map_err(RuntimeError::from)
                        }
                    };
                    if result.is_err() {
                        break;
                    }
                }
                let _ = writer.shutdown().await;
            });
            Ok(ClientPathState {
                id: path_id,
                binding,
                sender: PathSender::Stream(send_tx),
                validated: true,
                pending_probe_challenge: None,
                last_send_secs: now_secs(),
                last_recv_secs: now_secs(),
            })
        }
    }
}

fn spawn_server_udp_receiver(
    socket: Arc<UdpSocket>,
    tx: mpsc::UnboundedSender<ServerTransportEvent>,
) {
    tokio::spawn(async move {
        let mut recv_buf = vec![0_u8; DATAGRAM_BUFFER_SIZE];
        loop {
            match socket.recv_from(&mut recv_buf).await {
                Ok((len, peer_addr)) => {
                    if tx
                        .send(ServerTransportEvent::Datagram {
                            peer_addr,
                            bytes: recv_buf[..len].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    warn!(error = %error, "udp receiver stopped");
                    break;
                }
            }
        }
    });
}

fn spawn_server_tcp_listener(
    listener: TcpListener,
    tx: mpsc::UnboundedSender<ServerTransportEvent>,
    carrier: &S1Carrier,
) {
    let carrier = *carrier;
    tokio::spawn(async move {
        let mut next_conn_id = 1_u64;
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let conn_id = next_conn_id;
                    next_conn_id = next_conn_id.saturating_add(1);
                    let (send_tx, mut send_rx) = mpsc::unbounded_channel();
                    if tx
                        .send(ServerTransportEvent::StreamOpened {
                            conn_id,
                            peer_addr,
                            sender: send_tx.clone(),
                        })
                        .is_err()
                    {
                        break;
                    }
                    let (mut reader, mut writer) = stream.into_split();
                    let tx_reader = tx.clone();
                    tokio::spawn(async move {
                        loop {
                            match read_s1_payload(&mut reader, &carrier).await {
                                Ok(bytes) => {
                                    if tx_reader
                                        .send(ServerTransportEvent::StreamRecord { conn_id, bytes })
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(error) => {
                                    let malformed = error.kind() == io::ErrorKind::InvalidData;
                                    let _ = tx_reader.send(ServerTransportEvent::StreamClosed {
                                        conn_id,
                                        malformed,
                                    });
                                    break;
                                }
                            }
                        }
                    });
                    tokio::spawn(async move {
                        while let Some(write) = send_rx.recv().await {
                            let result = match write {
                                StreamWrite::CarrierPayload(payload) => {
                                    write_s1_payload(&mut writer, &carrier, &payload).await
                                }
                                StreamWrite::Raw(bytes) => {
                                    writer.write_all(&bytes).await.map_err(RuntimeError::from)
                                }
                            };
                            if result.is_err() {
                                break;
                            }
                        }
                        let _ = writer.shutdown().await;
                    });
                }
                Err(error) => {
                    warn!(error = %error, "tcp listener stopped");
                    break;
                }
            }
        }
    });
}

fn send_invalid_stream_response(
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    conn_id: u64,
    decoy_surface: bool,
) -> Result<(), RuntimeError> {
    let Some(peer) = stream_peers.get(&conn_id) else {
        return Ok(());
    };
    peer.sender
        .send(StreamWrite::Raw(if decoy_surface {
            decoy_http_response().into_bytes()
        } else {
            generic_http_failure().as_bytes().to_vec()
        }))
        .map_err(|_| RuntimeError::InvalidConfig("stream response channel closed".to_string()))
}

async fn send_frames_on_client_path(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    path: &ClientPathState,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    let outer = encode_client_tunnel_packet(
        carriers,
        endpoint_id,
        outer_keys,
        path.binding,
        &encoded.bytes,
    )?;
    queue_path_payload(&path.sender, outer)
}

async fn send_frames_to_server_path(
    udp_socket: &UdpSocket,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    session: &mut ServerSessionState,
    path: PathHandle,
    binding: CarrierBinding,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    send_frames_to_path_handle(
        udp_socket,
        stream_peers,
        carriers,
        endpoint_id,
        &session.outer_keys,
        &path,
        binding,
        &mut session.tunnel,
        frames,
        now,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_frames_to_path_handle(
    udp_socket: &UdpSocket,
    stream_peers: &HashMap<u64, ServerStreamPeer>,
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    path: &PathHandle,
    binding: CarrierBinding,
    tunnel: &mut TunnelSession,
    frames: &[Frame],
    now: u64,
) -> Result<(), RuntimeError> {
    let encoded = tunnel.encode_packet(frames, now)?;
    let outer =
        encode_server_tunnel_packet(carriers, endpoint_id, outer_keys, binding, &encoded.bytes)?;
    match path {
        PathHandle::Datagram(peer_addr) => {
            udp_socket.send_to(&outer, peer_addr).await?;
        }
        PathHandle::Stream(conn_id) => {
            let Some(peer) = stream_peers.get(conn_id) else {
                return Err(RuntimeError::InvalidConfig(
                    "missing stream peer sender".to_string(),
                ));
            };
            queue_path_payload(&PathSender::Stream(peer.sender.clone()), outer)?;
        }
    }
    Ok(())
}

fn queue_path_payload(sender: &PathSender, payload: Vec<u8>) -> Result<(), RuntimeError> {
    match sender {
        PathSender::Datagram(tx) => tx
            .send(payload)
            .map_err(|_| RuntimeError::InvalidConfig("datagram path closed".to_string())),
        PathSender::Stream(tx) => tx
            .send(StreamWrite::CarrierPayload(payload))
            .map_err(|_| RuntimeError::InvalidConfig("stream path closed".to_string())),
    }
}

fn encode_client_tunnel_packet(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    binding: CarrierBinding,
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    encode_server_tunnel_packet(carriers, endpoint_id, outer_keys, binding, packet_bytes)
}

fn encode_server_tunnel_packet(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    binding: CarrierBinding,
    packet_bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    match binding {
        CarrierBinding::D1DatagramUdp => encode_tunnel_datagram(
            carriers.d1(),
            endpoint_id,
            outer_keys.send_for(binding)?,
            packet_bytes,
        ),
        CarrierBinding::S1EncryptedStream => {
            encode_tunnel_stream_payload(endpoint_id, outer_keys.send_for(binding)?, packet_bytes)
        }
        _ => Err(RuntimeError::InvalidConfig(
            "unsupported runtime carrier".to_string(),
        )),
    }
}

fn decode_client_tunnel_packet(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    binding: CarrierBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    decode_server_tunnel_packet_direct(endpoint_id, outer_keys, binding, bytes).map_err(|error| {
        debug!(error = %error, carrier = %binding.as_str(), "failed to decode client tunnel packet");
        error
    }).and_then(|tunnel_bytes| {
        let _ = carriers;
        Ok(tunnel_bytes)
    })
}

fn decode_server_tunnel_packet(
    carriers: &RuntimeCarriers,
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    binding: CarrierBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    let _ = carriers;
    decode_server_tunnel_packet_direct(endpoint_id, outer_keys, binding, bytes)
}

fn decode_server_tunnel_packet_direct(
    endpoint_id: &apt_types::EndpointId,
    outer_keys: &RuntimeOuterKeys,
    binding: CarrierBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    match binding {
        CarrierBinding::D1DatagramUdp => decode_tunnel_datagram(
            &runtime_d1_carrier(1_380),
            endpoint_id,
            outer_keys.recv_for(binding)?,
            bytes,
        ),
        CarrierBinding::S1EncryptedStream => {
            decode_tunnel_stream_payload(endpoint_id, outer_keys.recv_for(binding)?, bytes)
        }
        _ => Err(RuntimeError::InvalidConfig(
            "unsupported runtime carrier".to_string(),
        )),
    }
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

fn decode_client_stream_admission_packet(
    config: &ResolvedClientConfig,
    payload: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_s1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_stream_payload(&config.endpoint_id, &outer_key, payload).ok()
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

fn decode_server_stream_admission_packet(
    config: &ResolvedServerConfig,
    payload: &[u8],
    now_secs: u64,
) -> Option<AdmissionPacket> {
    candidate_epoch_slots(now_secs)
        .into_iter()
        .find_map(|epoch_slot| {
            let outer_key =
                derive_s1_admission_outer_key(&config.admission_key, epoch_slot).ok()?;
            decode_admission_stream_payload(&config.endpoint_id, &outer_key, payload).ok()
        })
}

fn admission_config(config: &ResolvedServerConfig, carriers: &RuntimeCarriers) -> AdmissionConfig {
    let mut admission = AdmissionConfig::conservative(config.endpoint_id.clone());
    admission.allowed_carriers = vec![
        CarrierBinding::D1DatagramUdp,
        CarrierBinding::S1EncryptedStream,
    ];
    admission.default_policy = config.session_policy.initial_mode;
    admission.max_record_size = carriers.d1().max_record_size();
    admission.tunnel_mtu = config.tunnel_mtu;
    admission.allowed_suites = vec![CipherSuite::NoiseXxPsk2X25519ChaChaPolyBlake2s];
    admission
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

fn client_route_exempt_endpoints(config: &ResolvedClientConfig) -> Vec<SocketAddr> {
    let mut endpoints = vec![config.server_addr];
    if let Some(stream_addr) = config.stream_server_addr {
        if !endpoints.contains(&stream_addr) {
            endpoints.push(stream_addr);
        }
    }
    endpoints
}

fn runtime_d1_carrier(tunnel_mtu: u16) -> D1Carrier {
    D1Carrier::new(1_472, tunnel_mtu)
}

fn runtime_s1_carrier(tunnel_mtu: u16, decoy_surface: bool) -> S1Carrier {
    S1Carrier::new(16_384, tunnel_mtu, decoy_surface)
}

#[derive(Clone, Copy, Debug)]
struct RuntimeCarriers {
    d1: D1Carrier,
    s1: S1Carrier,
}

impl RuntimeCarriers {
    fn new(tunnel_mtu: u16, decoy_surface: bool) -> Self {
        Self {
            d1: runtime_d1_carrier(tunnel_mtu),
            s1: runtime_s1_carrier(tunnel_mtu, decoy_surface),
        }
    }

    fn d1(&self) -> &D1Carrier {
        &self.d1
    }

    fn s1(&self) -> &S1Carrier {
        &self.s1
    }
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

async fn write_s1_payload<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    carrier: &S1Carrier,
    payload: &[u8],
) -> Result<(), RuntimeError> {
    let mut records = carrier.encode_records(payload)?;
    let record = records
        .drain(..)
        .next()
        .ok_or(RuntimeError::Carrier(CarrierError::MalformedRecord))?;
    writer.write_all(&record).await?;
    Ok(())
}

async fn read_s1_payload<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    carrier: &S1Carrier,
) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await?;
    let len = u16::from_be_bytes(header) as usize;
    if len == 0 || len > usize::from(carrier.max_record_size()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed stream record",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

fn generic_http_failure() -> &'static str {
    "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
}

fn decoy_http_response() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        STREAM_DECOY_BODY.len(),
        STREAM_DECOY_BODY,
    )
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

fn candidate_epoch_slots(now_secs: u64) -> [u64; 3] {
    let slot = now_secs / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
    [slot.saturating_sub(1), slot, slot.saturating_add(1)]
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

    #[test]
    fn standby_probe_schedule_is_jittered() {
        let first = jittered_interval_secs(20);
        assert!((16..=24).contains(&first));
    }
}
