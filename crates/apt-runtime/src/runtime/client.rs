use super::*;
use crate::dns::{configure_client_dns, DnsGuard};
use crate::route::RouteGuard;
use apt_client_control::ClientRuntimeEvent;
use apt_surface_h2::ApiSyncSurface;
use std::future::Future;
use tokio::sync::watch;

mod h2_session;
mod helpers;

use h2_session::run_client_h2_session_loop;
use helpers::session_info;

pub(super) async fn run_client(
    config: ResolvedClientConfig,
    hooks: ClientRuntimeHooks,
) -> Result<ClientRuntimeResult, RuntimeError> {
    let observability = ObservabilityConfig::default();
    let mut telemetry = TelemetrySnapshot::new("apt-client");
    hooks.emit(ClientRuntimeEvent::Starting {
        server: config.surface_plan.endpoint.clone(),
        requested_mode: config.mode.value(),
    });

    let mut persistent_state = ClientPersistentState::load(&config.state_path)?;
    let network_context = discover_client_network_context(&config);
    persistent_state.activate_network_profile(network_context, now_secs(), config.mode);
    persistent_state.last_status = Some(RuntimeStatus::Starting);
    persistent_state.store(&config.state_path)?;

    let startup_shutdown_rx = hooks.shutdown_rx.clone();
    let backend = run_startup_step(
        &startup_shutdown_rx,
        "client h2 connect",
        ApiSyncH2HyperClient::connect_tls_with_surface_plan(&config.surface_plan),
    )
    .await?;
    let surface = ApiSyncSurface::new(config.surface_plan.profile.clone())?;
    let driver = ApiSyncH2ClientDriver::new(surface);
    let h2_session = run_startup_step(
        &startup_shutdown_rx,
        "client handshake",
        driver.establish_tunnel_session_with_hyper_client(
            &config,
            &persistent_state,
            &backend,
            now_secs(),
        ),
    )
    .await?;
    let transport = extract_tunnel_parameters(h2_session.established())?;
    let tun = run_startup_step(
        &startup_shutdown_rx,
        "client tunnel setup",
        spawn_tun_worker(TunInterfaceConfig {
            name: config.interface_name.clone(),
            local_ipv4: transport.client_ipv4,
            peer_ipv4: transport.server_ipv4,
            netmask: transport.netmask,
            local_ipv6: transport.client_ipv6,
            ipv6_prefix_len: transport.ipv6_prefix_len,
            mtu: transport.mtu,
        }),
    )
    .await?;
    ensure_startup_not_canceled(&startup_shutdown_rx, "client startup")?;

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
    ensure_startup_not_canceled(&startup_shutdown_rx, "client startup")?;

    let established = h2_session.established().clone();
    info!(
        server = %config.surface_plan.endpoint,
        authority = %config.surface_plan.authority,
        tunnel_ipv4 = %transport.client_ipv4,
        tunnel_ipv6 = ?transport.client_ipv6,
        server_tunnel_ip = %transport.server_ipv4,
        server_tunnel_ipv6 = ?transport.server_ipv6,
        interface = %tun.interface_name,
        routes = ?effective_routes,
        carrier = "h2",
        requested_mode = config.mode.value(),
        negotiated_mode = established.mode.value(),
        "client session established"
    );
    if established.mode != config.mode {
        info!(
            requested_mode = config.mode.value(),
            negotiated_mode = established.mode.value(),
            "server negotiated a different numeric mode than the client requested"
        );
    }
    hooks.emit(ClientRuntimeEvent::SessionEstablished {
        session: session_info(
            &config,
            &transport,
            &tun.interface_name,
            established.chosen_carrier,
            established.mode,
            &effective_routes,
        ),
    });

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
            mode: config.mode,
        },
        None,
        &observability,
    );

    let session_result = run_client_h2_session_loop(
        &config,
        tun,
        h2_session,
        backend,
        transport,
        &mut persistent_state,
        &mut telemetry,
        &observability,
        &hooks,
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

async fn run_startup_step<T, F>(
    shutdown_rx: &Option<watch::Receiver<bool>>,
    context: &'static str,
    future: F,
) -> Result<T, RuntimeError>
where
    F: Future<Output = Result<T, RuntimeError>>,
{
    let Some(mut shutdown_rx) = shutdown_rx.clone() else {
        return future.await;
    };
    if *shutdown_rx.borrow() {
        return Err(RuntimeError::Canceled(context));
    }
    tokio::select! {
        result = future => result,
        _ = wait_for_shutdown_signal(&mut shutdown_rx) => Err(RuntimeError::Canceled(context)),
    }
}

fn ensure_startup_not_canceled(
    shutdown_rx: &Option<watch::Receiver<bool>>,
    context: &'static str,
) -> Result<(), RuntimeError> {
    if shutdown_rx
        .as_ref()
        .is_some_and(|shutdown_rx| *shutdown_rx.borrow())
    {
        return Err(RuntimeError::Canceled(context));
    }
    Ok(())
}

async fn wait_for_shutdown_signal(shutdown_rx: &mut watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    loop {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
        if *shutdown_rx.borrow() {
            return;
        }
    }
}
