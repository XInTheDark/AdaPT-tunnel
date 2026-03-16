use super::super::*;
use super::{helpers::disconnected_client_status, wait_for_shutdown_signal};
use apt_client_control::ClientRuntimeEvent;
use apt_surface_h2::ApiSyncResponse;
use apt_tunnel::{DecodedPacket, Frame, RekeyStatus};

pub(super) async fn run_client_h2_session_loop(
    config: &ResolvedClientConfig,
    tun: TunHandle,
    mut session: ApiSyncH2ClientSession,
    backend: ApiSyncH2HyperClient,
    transport: SessionTransportParameters,
    persistent_state: &mut ClientPersistentState,
    _telemetry: &mut TelemetrySnapshot,
    _observability: &ObservabilityConfig,
    hooks: &ClientRuntimeHooks,
) -> Result<ClientStatus, RuntimeError> {
    let mut adaptive = AdaptiveDatapath::new_client(
        CarrierBinding::S1EncryptedStream,
        session.established().secrets.persona_seed,
        persistent_state
            .active_network_profile()
            .map(|profile| profile.context.clone())
            .unwrap_or_else(|| {
                build_client_network_context(
                    config.endpoint_id.as_str(),
                    &config.surface_plan.endpoint,
                )
            }),
        persistent_state
            .active_network_profile()
            .map(|profile| profile.normality.clone()),
        persistent_state
            .active_network_profile()
            .and_then(|profile| profile.remembered_profile.clone()),
        AdaptiveRuntimeConfig {
            negotiated_mode: session.established().mode,
            persisted_mode: persistent_state
                .active_network_profile()
                .map(|profile| profile.last_mode),
            keepalive_base_interval_secs: config.keepalive_secs,
        },
        admission_path_profile(
            persistent_state
                .active_network_profile()
                .map(|profile| &profile.normality),
        ),
        persistent_state
            .active_network_profile()
            .map(|profile| profile.keepalive_learning.clone()),
        now_secs(),
    );
    adaptive.note_successful_session();
    persist_client_learning(persistent_state, &adaptive);
    persistent_state.last_successful_carrier = Some(CarrierBinding::S1EncryptedStream);
    persistent_state.store(&config.state_path)?;

    let _session_id = session.established().session_id;
    let mut maintenance_tick = interval(Duration::from_secs(1));
    let mut tun_rx = tun.inbound_rx;
    let tun_tx = tun.outbound_tx.clone();
    let mut pending_frames = Vec::new();
    let mut pending_downlink = Some(spawn_downlink_round_trip(&session, backend.clone())?);
    let mut last_send_secs = now_secs();
    let mut last_recv_secs = now_secs();
    let mut shutdown_rx = hooks.shutdown_rx.clone();

    loop {
        tokio::select! {
            packet = tun_rx.recv() => {
                match packet {
                    Some(packet) => {
                        let shaping_started_millis = now_millis();
                        let (mut frames, payload_bytes, burst_len) = collect_outbound_tun_frames(
                            packet,
                            &mut tun_rx,
                            &mut adaptive,
                            CarrierBinding::S1EncryptedStream,
                            shaping_started_millis,
                        );
                        prepend_pending_frames(&mut pending_frames, &mut frames);
                        let decoded = session
                            .exchange_tunnel_frames_with_hyper_client(&backend, &frames, now_secs())
                            .await?;
                        last_send_secs = now_secs();
                        adaptive.record_outbound(
                            payload_bytes.saturating_add(approximate_frame_bytes(&frames)),
                            burst_len,
                            now_millis(),
                        );
                        adaptive.note_activity(last_send_secs);
                        if process_decoded_packet(
                            &mut session,
                            decoded,
                            &tun_tx,
                            &mut pending_frames,
                            &mut adaptive,
                            &mut last_recv_secs,
                        ).await? {
                            persist_client_learning(persistent_state, &adaptive);
                            persistent_state.last_status = Some(RuntimeStatus::Disconnected);
                            persistent_state.store(&config.state_path)?;
                            hooks.emit(ClientRuntimeEvent::SessionEnded {
                                reason: Some("remote close".to_string()),
                            });
                            return Ok(disconnected_client_status(
                                config,
                                &transport,
                                &tun.interface_name,
                                Some(CarrierBinding::S1EncryptedStream),
                                None,
                                adaptive.current_mode(),
                            ));
                        }
                        if flush_pending_frames_if_any(
                            &mut session,
                            &backend,
                            &tun_tx,
                            &mut pending_frames,
                            &mut adaptive,
                            &mut last_send_secs,
                            &mut last_recv_secs,
                        )
                        .await?
                        {
                            persist_client_learning(persistent_state, &adaptive);
                            persistent_state.last_status = Some(RuntimeStatus::Disconnected);
                            persistent_state.store(&config.state_path)?;
                            hooks.emit(ClientRuntimeEvent::SessionEnded {
                                reason: Some("remote close".to_string()),
                            });
                            return Ok(disconnected_client_status(
                                config,
                                &transport,
                                &tun.interface_name,
                                Some(CarrierBinding::S1EncryptedStream),
                                None,
                                adaptive.current_mode(),
                            ));
                        }
                    }
                    None => break,
                }
            }
            _ = maintenance_tick.tick() => {
                let now = now_secs();
                if let Some(mode) = adaptive.maybe_observe_stability(now) {
                    hooks.emit(ClientRuntimeEvent::ModeChanged { mode: mode.value() });
                }
                if let Some(mode) = adaptive.maybe_observe_quiet_impairment(now, last_send_secs, last_recv_secs) {
                    hooks.emit(ClientRuntimeEvent::ModeChanged { mode: mode.value() });
                }
                if now.saturating_sub(last_recv_secs) > config.session_idle_timeout_secs {
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                    return Err(RuntimeError::Timeout("H2 session idle timeout reached"));
                }
                let mut frames = std::mem::take(&mut pending_frames);
                frames.extend(session.collect_due_control_frames(now));
                if adaptive.keepalive_due(now) {
                    frames.extend(adaptive.build_keepalive_frames(64, now.saturating_mul(1_000)));
                }
                match session.rekey_status(now) {
                    RekeyStatus::SoftLimitReached => frames.push(session.initiate_rekey(now)?),
                    RekeyStatus::HardLimitReached => {
                        persist_client_learning(persistent_state, &adaptive);
                        persistent_state.store(&config.state_path)?;
                        return Err(RuntimeError::Timeout("rekey hard limit reached"));
                    }
                    RekeyStatus::Healthy => {}
                }
                pending_frames.extend(frames);
                if flush_pending_frames_if_any(
                    &mut session,
                    &backend,
                    &tun_tx,
                    &mut pending_frames,
                    &mut adaptive,
                    &mut last_send_secs,
                    &mut last_recv_secs,
                )
                .await?
                {
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.last_status = Some(RuntimeStatus::Disconnected);
                    persistent_state.store(&config.state_path)?;
                    hooks.emit(ClientRuntimeEvent::SessionEnded {
                        reason: Some("remote close".to_string()),
                    });
                    return Ok(disconnected_client_status(
                        config,
                        &transport,
                        &tun.interface_name,
                        Some(CarrierBinding::S1EncryptedStream),
                        None,
                        adaptive.current_mode(),
                    ));
                }
                let stats = adaptive.session_stats();
                hooks.emit(ClientRuntimeEvent::StatsTick {
                    tx_bytes: stats.tx_bytes,
                    rx_bytes: stats.rx_bytes,
                });
            }
            downlink = await_optional_downlink(&mut pending_downlink), if pending_downlink.is_some() => {
                let response = downlink??;
                let decoded = session.handle_tunnel_response(&response, now_secs())?;
                pending_downlink = Some(spawn_downlink_round_trip(&session, backend.clone())?);
                if process_decoded_packet(
                    &mut session,
                    decoded,
                    &tun_tx,
                    &mut pending_frames,
                    &mut adaptive,
                    &mut last_recv_secs,
                ).await? {
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.last_status = Some(RuntimeStatus::Disconnected);
                    persistent_state.store(&config.state_path)?;
                    hooks.emit(ClientRuntimeEvent::SessionEnded {
                        reason: Some("remote close".to_string()),
                    });
                    return Ok(disconnected_client_status(
                        config,
                        &transport,
                        &tun.interface_name,
                        Some(CarrierBinding::S1EncryptedStream),
                        None,
                        adaptive.current_mode(),
                    ));
                }
                if flush_pending_frames_if_any(
                    &mut session,
                    &backend,
                    &tun_tx,
                    &mut pending_frames,
                    &mut adaptive,
                    &mut last_send_secs,
                    &mut last_recv_secs,
                )
                .await?
                {
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.last_status = Some(RuntimeStatus::Disconnected);
                    persistent_state.store(&config.state_path)?;
                    hooks.emit(ClientRuntimeEvent::SessionEnded {
                        reason: Some("remote close".to_string()),
                    });
                    return Ok(disconnected_client_status(
                        config,
                        &transport,
                        &tun.interface_name,
                        Some(CarrierBinding::S1EncryptedStream),
                        None,
                        adaptive.current_mode(),
                    ));
                }
            }
            _ = wait_for_optional_shutdown_signal(&mut shutdown_rx) => {
                break;
            }
        }
    }

    if let Some(handle) = pending_downlink.take() {
        handle.abort();
    }

    persist_client_learning(persistent_state, &adaptive);
    let status = disconnected_client_status(
        config,
        &transport,
        &tun.interface_name,
        Some(CarrierBinding::S1EncryptedStream),
        None,
        adaptive.current_mode(),
    );
    hooks.emit(ClientRuntimeEvent::SessionEnded {
        reason: Some("shutdown".to_string()),
    });
    persistent_state.last_status = Some(status.status.clone());
    Ok(status)
}

fn spawn_downlink_round_trip(
    session: &ApiSyncH2ClientSession,
    backend: ApiSyncH2HyperClient,
) -> Result<tokio::task::JoinHandle<Result<ApiSyncResponse, RuntimeError>>, RuntimeError> {
    let request = session.prepare_tunnel_poll_request()?;
    let surface = session.surface().clone();
    Ok(tokio::spawn(async move {
        backend.round_trip(&surface, request).await
    }))
}

fn prepend_pending_frames(pending_frames: &mut Vec<Frame>, frames: &mut Vec<Frame>) {
    if pending_frames.is_empty() {
        return;
    }
    let mut combined = std::mem::take(pending_frames);
    combined.append(frames);
    *frames = combined;
}

async fn process_decoded_packet(
    session: &mut ApiSyncH2ClientSession,
    decoded: Option<DecodedPacket>,
    tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    pending_frames: &mut Vec<Frame>,
    adaptive: &mut AdaptiveDatapath,
    last_recv_secs: &mut u64,
) -> Result<bool, RuntimeError> {
    let Some(decoded) = decoded else {
        return Ok(false);
    };
    *last_recv_secs = now_secs();
    adaptive.record_inbound(decoded_payload_bytes(&decoded), now_millis());
    adaptive.note_activity(*last_recv_secs);
    pending_frames.extend(decoded.ack_suggestions.clone());
    for frame in decoded.frames {
        match frame {
            Frame::IpData(packet) => {
                let _ = tun_tx.send(packet).await;
            }
            Frame::PathChallenge { challenge, .. } => {
                let control_id = session.next_control_id();
                pending_frames.push(Frame::PathResponse {
                    control_id,
                    challenge,
                });
            }
            Frame::Close { .. } => return Ok(true),
            Frame::CtrlAck { .. }
            | Frame::PathResponse { .. }
            | Frame::SessionUpdate { .. }
            | Frame::Ping
            | Frame::Padding(_) => {}
        }
    }
    Ok(false)
}

fn decoded_payload_bytes(decoded: &DecodedPacket) -> usize {
    approximate_frame_bytes(&decoded.frames)
        .saturating_add(approximate_frame_bytes(&decoded.ack_suggestions))
}

async fn flush_pending_frames_if_any(
    session: &mut ApiSyncH2ClientSession,
    backend: &ApiSyncH2HyperClient,
    tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    pending_frames: &mut Vec<Frame>,
    adaptive: &mut AdaptiveDatapath,
    last_send_secs: &mut u64,
    last_recv_secs: &mut u64,
) -> Result<bool, RuntimeError> {
    if pending_frames.is_empty() {
        return Ok(false);
    }
    let now = now_secs();
    let sent_millis = now_millis();
    let frames = std::mem::take(pending_frames);
    let decoded = session
        .exchange_tunnel_frames_with_hyper_client(backend, &frames, now)
        .await?;
    *last_send_secs = now;
    adaptive.record_outbound(
        approximate_frame_bytes(&frames),
        frames
            .iter()
            .filter(|frame| matches!(frame, Frame::IpData(_)))
            .count()
            .max(1),
        sent_millis,
    );
    if frames.iter().any(|frame| matches!(frame, Frame::Ping)) {
        adaptive.note_keepalive_sent(now);
    } else {
        adaptive.note_activity(now);
    }
    process_decoded_packet(
        session,
        decoded,
        tun_tx,
        pending_frames,
        adaptive,
        last_recv_secs,
    )
    .await
}

async fn wait_for_optional_shutdown_signal(
    shutdown_rx: &mut Option<tokio::sync::watch::Receiver<bool>>,
) {
    let Some(shutdown_rx) = shutdown_rx.as_mut() else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    wait_for_shutdown_signal(shutdown_rx).await;
}

async fn await_optional_downlink(
    pending_downlink: &mut Option<tokio::task::JoinHandle<Result<ApiSyncResponse, RuntimeError>>>,
) -> Result<Result<ApiSyncResponse, RuntimeError>, RuntimeError> {
    let handle = pending_downlink
        .as_mut()
        .expect("downlink await helper is only polled when a task exists");
    let result = handle
        .await
        .map_err(|error| RuntimeError::Http(format!("h2 downlink task failed: {error}")));
    pending_downlink.take();
    result
}
