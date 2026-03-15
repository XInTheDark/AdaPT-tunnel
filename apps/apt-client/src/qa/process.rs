use crate::{
    cli::ClientLaunchArgs,
    daemon_client::{send_request, subscribe},
};
use apt_client_control::{
    ClientDaemonEvent, ClientDaemonLifecycle, ClientDaemonRequest, ClientDaemonResponse,
    ClientDaemonSnapshot, ClientLaunchOptions, ClientSessionInfo,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub(super) struct EstablishedSession {
    pub server: String,
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_ipv6: Option<Ipv6Addr>,
    pub server_tunnel_ipv4: Ipv4Addr,
    pub server_tunnel_ipv6: Option<Ipv6Addr>,
    pub interface_name: String,
    pub routes: Vec<String>,
    pub carrier: String,
    pub negotiated_mode: u8,
    pub daemon_pid: u32,
}

impl EstablishedSession {
    pub(super) fn has_default_route(&self) -> bool {
        self.routes
            .iter()
            .any(|route| route == "0.0.0.0/0" || route == "::/0")
    }
}

pub(super) async fn connect_and_wait_for_established(
    launch: &ClientLaunchArgs,
    bundle_path: std::path::PathBuf,
    timeout_secs: u64,
) -> Result<EstablishedSession, Box<dyn std::error::Error + Send + Sync>> {
    let response = send_request(ClientDaemonRequest::Connect {
        options: ClientLaunchOptions {
            bundle_path: Some(bundle_path),
            ..launch.to_launch_options(None)
        },
    })
    .await?;
    if let ClientDaemonResponse::Error { message } = response {
        return Err(message.into());
    }

    let mut subscription = subscribe().await?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut latest_snapshot = subscription.initial_snapshot.clone();
    if let Some(session) = established_session_from_snapshot(&latest_snapshot) {
        return Ok(session);
    }

    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for tunnel establishment after {timeout_secs}s"
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(
            remaining.min(Duration::from_millis(250)),
            subscription.next_event(),
        )
        .await
        {
            Ok(Ok(Some(event))) => {
                if let Some(session) = handle_event(&event, &mut latest_snapshot)? {
                    return Ok(session);
                }
            }
            Ok(Ok(None)) => {
                return Err("daemon subscription ended before tunnel establishment".into())
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {}
        }
    }
}

pub(super) async fn disconnect_session() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match send_request(ClientDaemonRequest::Disconnect).await? {
        ClientDaemonResponse::Error { message } => Err(message.into()),
        _ => Ok(()),
    }
}

fn handle_event(
    event: &ClientDaemonEvent,
    latest_snapshot: &mut ClientDaemonSnapshot,
) -> Result<Option<EstablishedSession>, Box<dyn std::error::Error + Send + Sync>> {
    match event {
        ClientDaemonEvent::Snapshot(snapshot) => {
            *latest_snapshot = snapshot.clone();
            Ok(established_session_from_snapshot(latest_snapshot))
        }
        ClientDaemonEvent::Log { level, message } => {
            println!("[daemon][{level:?}] {message}");
            Ok(None)
        }
        ClientDaemonEvent::SessionEstablished { session } => Ok(Some(
            established_session_from_parts(latest_snapshot, session)?,
        )),
        ClientDaemonEvent::ReconnectScheduled {
            attempt,
            in_secs,
            reason,
        } => {
            println!("[daemon] reconnect attempt #{attempt} scheduled in {in_secs}s: {reason}");
            Ok(None)
        }
        ClientDaemonEvent::Error { message, fatal } => {
            if *fatal {
                Err(message.clone().into())
            } else {
                println!("[daemon][warn] {message}");
                Ok(None)
            }
        }
        ClientDaemonEvent::CarrierChanged { to, .. } => {
            println!("[daemon] carrier changed to {to}");
            Ok(None)
        }
        ClientDaemonEvent::ModeChanged { mode } => {
            println!("[daemon] adaptive mode changed to {mode}");
            Ok(None)
        }
        ClientDaemonEvent::StatsTick { .. } => Ok(None),
    }
}

fn established_session_from_snapshot(
    snapshot: &ClientDaemonSnapshot,
) -> Option<EstablishedSession> {
    if !matches!(snapshot.lifecycle, ClientDaemonLifecycle::Connected) {
        return None;
    }
    let session = ClientSessionInfo {
        server: snapshot.server.clone()?,
        interface_name: snapshot.interface_name.clone()?,
        carrier: snapshot.active_carrier.clone()?,
        negotiated_mode: snapshot.negotiated_mode?,
        tunnel_ipv4: snapshot
            .tunnel_addresses
            .iter()
            .find_map(|address| match address {
                std::net::IpAddr::V4(ip) => Some(*ip),
                std::net::IpAddr::V6(_) => None,
            }),
        tunnel_ipv6: snapshot
            .tunnel_addresses
            .iter()
            .find_map(|address| match address {
                std::net::IpAddr::V4(_) => None,
                std::net::IpAddr::V6(ip) => Some(*ip),
            }),
        server_tunnel_ipv4: snapshot.server_tunnel_ipv4,
        server_tunnel_ipv6: snapshot.server_tunnel_ipv6,
        tunnel_addresses: snapshot.tunnel_addresses.clone(),
        routes: snapshot.routes.clone(),
    };
    established_session_from_parts(snapshot, &session).ok()
}

fn established_session_from_parts(
    snapshot: &ClientDaemonSnapshot,
    session: &ClientSessionInfo,
) -> Result<EstablishedSession, Box<dyn std::error::Error + Send + Sync>> {
    Ok(EstablishedSession {
        server: session.server.clone(),
        tunnel_ipv4: session
            .tunnel_ipv4
            .ok_or("missing tunnel IPv4 in daemon snapshot")?,
        tunnel_ipv6: session.tunnel_ipv6,
        server_tunnel_ipv4: session
            .server_tunnel_ipv4
            .ok_or("missing server tunnel IPv4 in daemon snapshot")?,
        server_tunnel_ipv6: session.server_tunnel_ipv6,
        interface_name: session.interface_name.clone(),
        routes: session.routes.clone(),
        carrier: session.carrier.clone(),
        negotiated_mode: session.negotiated_mode,
        daemon_pid: snapshot.daemon_pid.unwrap_or_default(),
    })
}
