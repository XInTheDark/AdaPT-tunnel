use super::*;

pub(super) fn record_mode_change(
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    session_id: SessionId,
    mode: Mode,
) {
    record_event(
        telemetry,
        &AptEvent::ModeChanged { session_id, mode },
        None,
        observability,
    );
}

pub(super) fn promote_client_path(
    active_path_id: &mut u64,
    path_id: u64,
    binding: CarrierBinding,
    from: Option<CarrierBinding>,
    adaptive: &mut AdaptiveDatapath,
    persistent_state: &mut ClientPersistentState,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    session_id: SessionId,
) {
    *active_path_id = path_id;
    adaptive.set_active_carrier(binding);
    persistent_state.last_successful_carrier = Some(binding);
    record_event(
        telemetry,
        &AptEvent::CarrierMigrated {
            session_id,
            from,
            to: binding,
        },
        None,
        observability,
    );
}

pub(super) fn promote_standby_if_available(
    standby_path_id: Option<u64>,
    paths: &HashMap<u64, ClientPathState>,
    from: Option<CarrierBinding>,
    active_path_id: &mut u64,
    adaptive: &mut AdaptiveDatapath,
    persistent_state: &mut ClientPersistentState,
    telemetry: &mut TelemetrySnapshot,
    observability: &ObservabilityConfig,
    session_id: SessionId,
) -> bool {
    let Some(standby_id) = standby_path_id else {
        return false;
    };
    let Some(standby) = paths.get(&standby_id) else {
        return false;
    };
    promote_client_path(
        active_path_id,
        standby.id,
        standby.binding,
        from,
        adaptive,
        persistent_state,
        telemetry,
        observability,
        session_id,
    );
    true
}

pub(super) fn disconnected_client_status(
    config: &ResolvedClientConfig,
    transport: &SessionTransportParameters,
    interface_name: &str,
    active_binding: Option<CarrierBinding>,
    standby_binding: Option<CarrierBinding>,
    mode: Mode,
) -> ClientStatus {
    ClientStatus::new(
        RuntimeStatus::Disconnected,
        config.server_addr.to_string(),
        Some(IpAddr::V4(transport.client_ipv4)),
        tunnel_addresses(transport),
        Some(interface_name.to_string()),
        active_binding,
        standby_binding,
        Some(mode),
    )
}
