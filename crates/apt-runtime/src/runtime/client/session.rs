use super::*;

pub(super) async fn run_client_session_loop(
    config: &ResolvedClientConfig,
    tun: TunHandle,
    handshake: HandshakeSuccess,
    transport: SessionTransportParameters,
    persistent_state: &mut ClientPersistentState,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    carriers: &RuntimeCarriers,
) -> Result<ClientStatus, RuntimeError> {
    let outer_keys = RuntimeOuterKeys::new(
        &config.endpoint_id,
        derive_d1_tunnel_outer_keys(&handshake.established.secrets)?,
        derive_d2_tunnel_outer_keys(&handshake.established.secrets)?,
        derive_s1_tunnel_outer_keys(&handshake.established.secrets)?,
    )?;
    let mut adaptive = AdaptiveDatapath::new_client(
        handshake.established.chosen_carrier,
        handshake.established.secrets.persona_seed,
        persistent_state
            .active_network_profile()
            .map(|profile| profile.context.clone())
            .unwrap_or_else(|| {
                build_client_network_context(
                    config.endpoint_id.as_str(),
                    &config.server_addr.to_string(),
                )
            }),
        persistent_state
            .active_network_profile()
            .map(|profile| profile.normality.clone()),
        persistent_state
            .active_network_profile()
            .and_then(|profile| profile.remembered_profile.clone()),
        AdaptiveRuntimeConfig {
            initial_mode: config.session_policy.initial_mode,
            operator_mode: config.mode,
            allow_speed_first_by_policy: config.session_policy.allow_speed_first,
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
    persistent_state.last_successful_carrier = Some(handshake.binding);
    persistent_state.store(&config.state_path)?;

    let session_id = handshake.established.session_id;
    let encapsulation = TunnelEncapsulation::for_policy(handshake.established.policy_mode);
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
                        let tunnel_bytes = decode_client_tunnel_packet_owned(
                            carriers,
                            &config.endpoint_id,
                            &outer_keys,
                            encapsulation,
                            path.binding,
                            bytes,
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
                                        tunnel_addresses(&transport),
                                        Some(tun.interface_name.clone()),
                                        Some(paths.get(&active_path_id).map(|state| state.binding).unwrap_or(handshake.binding)),
                                        standby_path_id.and_then(|id| paths.get(&id).map(|state| state.binding)),
                                        Some(adaptive.current_mode().into()),
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
                                encapsulation,
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
                                    &AptEvent::ModeChanged {
                                        session_id,
                                        mode: mode.into(),
                                    },
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
                        let (frames, payload_bytes, burst_len) = collect_outbound_tun_frames(
                            packet,
                            &mut tun_rx,
                            &adaptive,
                            active_path.binding,
                        );
                        send_frames_on_client_path(
                            carriers,
                            &config.endpoint_id,
                            &outer_keys,
                            encapsulation,
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
                        &AptEvent::ModeChanged {
                            session_id,
                            mode: mode.into(),
                        },
                        None,
                        observability,
                    );
                    persist_client_learning(persistent_state, &adaptive);
                    persistent_state.store(&config.state_path)?;
                }
                if let Some(mode) = adaptive.maybe_observe_quiet_impairment(
                    now,
                    paths.get(&active_path_id).map_or(now, |path| path.last_send_secs),
                    paths.get(&active_path_id).map_or(now, |path| path.last_recv_secs),
                ) {
                    migration_pressure = migration_pressure.saturating_add(1);
                    record_event(
                        telemetry,
                        &AptEvent::ModeChanged {
                            session_id,
                            mode: mode.into(),
                        },
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
                let should_attempt_standby_probe =
                    config.allow_session_migration
                        && standby_path_id.is_none()
                        && now >= next_standby_probe_secs
                        && (migration_pressure > 0 || config.standby_health_check_secs > 0);
                if should_attempt_standby_probe {
                    if let Some(binding) = next_standby_candidate(config, &adaptive, &paths, active_path_id) {
                        match open_client_standby_path(
                            next_path_id,
                            binding,
                            config,
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
                                    encapsulation,
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
                                        &AptEvent::ModeChanged {
                                            session_id,
                                            mode: mode.into(),
                                        },
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
                if paths.contains_key(&active_path_id) && adaptive.keepalive_due(now) {
                    frames.extend(adaptive.build_keepalive_frames(64));
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
                        encapsulation,
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
                    if frames.iter().any(|frame| matches!(frame, Frame::Ping)) {
                        adaptive.note_keepalive_sent(now);
                    } else {
                        adaptive.note_activity(now);
                    }
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
        tunnel_addresses(&transport),
        Some(tun.interface_name),
        paths.get(&active_path_id).map(|state| state.binding),
        standby_path_id.and_then(|id| paths.get(&id).map(|state| state.binding)),
        Some(adaptive.current_mode().into()),
    );
    persistent_state.last_status = Some(status.status.clone());
    Ok(status)
}
