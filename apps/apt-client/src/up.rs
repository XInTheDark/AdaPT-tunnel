use crate::{
    cli::ClientLaunchArgs,
    daemon_client::{send_request, subscribe},
    paths::{ensure_user_owned_override, resolve_client_bundle_path},
};
use apt_client_control::{
    ClientDaemonEvent, ClientDaemonLifecycle, ClientDaemonRequest, ClientDaemonResponse,
    ClientDaemonSnapshot,
};

pub(super) async fn start_client(
    launch: ClientLaunchArgs,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bundle_path = resolve_client_bundle_path(launch.bundle.clone())?;
    let _ = ensure_user_owned_override(&bundle_path)?;
    println!("Using client bundle: {}", bundle_path.display());
    println!("Connecting through the local client daemon... Press Ctrl-C to disconnect.\n");

    match send_request(ClientDaemonRequest::Connect {
        options: launch.to_launch_options(Some(bundle_path)),
    })
    .await?
    {
        ClientDaemonResponse::Ack { message, snapshot } => {
            println!("{message}");
            attach_to_session(snapshot).await
        }
        ClientDaemonResponse::Error { message } => Err(message.into()),
        other => Err(format!("unexpected daemon response: {other:?}").into()),
    }
}

async fn attach_to_session(
    initial_snapshot: ClientDaemonSnapshot,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut subscription = subscribe().await?;
    let mut last_lifecycle = None;
    let mut seen_connected = false;
    render_snapshot(
        &subscription.initial_snapshot,
        &mut last_lifecycle,
        &mut seen_connected,
    )?;
    render_snapshot(&initial_snapshot, &mut last_lifecycle, &mut seen_connected)?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = send_request(ClientDaemonRequest::Disconnect).await;
                println!("\nDisconnect requested.");
            }
            maybe_event = subscription.next_event() => {
                match maybe_event? {
                    Some(event) => match event {
                        ClientDaemonEvent::Snapshot(snapshot) => {
                            if let Some(done) = render_snapshot(&snapshot, &mut last_lifecycle, &mut seen_connected)? {
                                return done;
                            }
                        }
                        ClientDaemonEvent::Log { level, message } => {
                            println!("[{level:?}] {message}");
                        }
                        ClientDaemonEvent::SessionEstablished { session } => {
                            seen_connected = true;
                            println!("connected: server={} carrier={} mode={} iface={}", session.server, session.carrier, session.negotiated_mode, session.interface_name);
                        }
                        ClientDaemonEvent::CarrierChanged { from, to } => {
                            println!("carrier changed: {} -> {}", from.unwrap_or_else(|| "unknown".to_string()), to);
                        }
                        ClientDaemonEvent::ModeChanged { mode } => {
                            println!("adaptive mode changed to {mode}");
                        }
                        ClientDaemonEvent::StatsTick { .. } => {}
                        ClientDaemonEvent::ReconnectScheduled { attempt, in_secs, reason } => {
                            println!("reconnect #{attempt} in {in_secs}s: {reason}");
                        }
                        ClientDaemonEvent::Error { message, fatal } => {
                            if fatal {
                                return Err(message.into());
                            }
                            eprintln!("warning: {message}");
                        }
                    },
                    None => return Ok(()),
                }
            }
        }
    }
}

fn render_snapshot(
    snapshot: &ClientDaemonSnapshot,
    last_lifecycle: &mut Option<ClientDaemonLifecycle>,
    seen_connected: &mut bool,
) -> Result<
    Option<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    if last_lifecycle.as_ref() != Some(&snapshot.lifecycle) {
        println!("status: {:?}", snapshot.lifecycle);
        *last_lifecycle = Some(snapshot.lifecycle.clone());
    }
    match snapshot.lifecycle {
        ClientDaemonLifecycle::Connected => {
            *seen_connected = true;
            Ok(None)
        }
        ClientDaemonLifecycle::Error => {
            let message = snapshot
                .last_error
                .clone()
                .unwrap_or_else(|| "client daemon reported a fatal error".to_string());
            Ok(Some(Err(message.into())))
        }
        ClientDaemonLifecycle::Idle if *seen_connected => Ok(Some(Ok(()))),
        _ => Ok(None),
    }
}
