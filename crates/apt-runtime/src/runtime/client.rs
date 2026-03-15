use super::*;
use crate::dns::{configure_client_dns, DnsGuard};
use crate::route::RouteGuard;
use apt_client_control::ClientRuntimeEvent;

mod helpers;
mod session;

use helpers::{runtime_carrier, session_info};
use session::run_client_session_loop;

pub(super) async fn run_client(
    config: ResolvedClientConfig,
    hooks: ClientRuntimeHooks,
) -> Result<ClientRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-client");
    let carriers = RuntimeCarriers::new(1_380, false, config.d2.is_some());
    hooks.emit(ClientRuntimeEvent::Starting {
        server: config.server_addr.to_string(),
        requested_mode: config.mode.value(),
        preferred_carrier: runtime_carrier(config.preferred_carrier),
    });

    let mut persistent_state = ClientPersistentState::load(&config.state_path)?;
    let network_context = discover_client_network_context(&config);
    persistent_state.activate_network_profile(network_context, now_secs(), config.mode);
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
    let encapsulation = TunnelEncapsulation::for_mode(handshake.established.mode);
    let transport = extract_tunnel_parameters(&handshake.established)?;
    let tun = spawn_tun_worker(TunInterfaceConfig {
        name: config.interface_name.clone(),
        local_ipv4: transport.client_ipv4,
        peer_ipv4: transport.server_ipv4,
        netmask: transport.netmask,
        local_ipv6: transport.client_ipv6,
        ipv6_prefix_len: transport.ipv6_prefix_len,
        mtu: transport.mtu,
    })
    .await?;

    let effective_routes = if config.use_server_pushed_routes && !transport.routes.is_empty() {
        transport.routes.clone()
    } else {
        config.routes.clone()
    };
    let mut dns_guard = match configure_client_dns(&tun.interface_name, &transport.dns_servers) {
        Ok(guard) => guard,
        Err(error) => {
            warn!(
                error = %error,
                interface = %tun.interface_name,
                dns_servers = ?transport.dns_servers,
                "failed to apply pushed DNS settings automatically"
            );
            DnsGuard::default()
        }
    };
    let exempt_endpoints = client_route_exempt_endpoints(&config);
    let mut route_guard = configure_client_network_for_endpoints(
        &tun.interface_name,
        &exempt_endpoints,
        &effective_routes,
    )?;

    info!(
        server = %config.server_addr,
        tunnel_ipv4 = %transport.client_ipv4,
        tunnel_ipv6 = ?transport.client_ipv6,
        server_tunnel_ip = %transport.server_ipv4,
        server_tunnel_ipv6 = ?transport.server_ipv6,
        interface = %tun.interface_name,
        routes = ?effective_routes,
        carrier = %handshake.binding.as_str(),
        encapsulation = encapsulation.as_str(),
        requested_mode = config.mode.value(),
        negotiated_mode = handshake.established.mode.value(),
        "client session established"
    );
    if handshake.established.mode != config.mode {
        info!(
            requested_mode = config.mode.value(),
            negotiated_mode = handshake.established.mode.value(),
            "server negotiated a different numeric mode than the client requested"
        );
    }
    hooks.emit(ClientRuntimeEvent::SessionEstablished {
        session: session_info(
            &config,
            &transport,
            &tun.interface_name,
            handshake.binding,
            handshake.established.mode,
            &effective_routes,
        ),
    });

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
            mode: config.mode,
        },
        None,
        &observability,
    );

    let session_result = run_client_session_loop(
        &config,
        tun,
        handshake,
        transport,
        &mut persistent_state,
        &mut telemetry,
        &observability,
        &hooks,
        &carriers,
    )
    .await;

    if let Ok(status) = &session_result {
        persistent_state.last_status = Some(status.status.clone());
        persistent_state.store(&config.state_path)?;
    }
    log_cleanup_warnings(&mut route_guard, &mut dns_guard);

    let status = session_result?;
    Ok(ClientRuntimeResult { status, telemetry })
}

fn log_cleanup_warnings(route_guard: &mut RouteGuard, dns_guard: &mut DnsGuard) {
    for error in route_guard.cleanup_errors() {
        warn!(error = %error, "client route teardown reported a cleanup failure");
    }
    for error in dns_guard.cleanup_errors() {
        warn!(error = %error, "client dns teardown reported a cleanup failure");
    }
}
