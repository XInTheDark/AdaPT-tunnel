use crate::latency::measure_tunnel_rtt_ms;
use apt_bundle::{apply_optional_client_override, client_bundle_state_path, load_client_bundle};
use apt_client_control::{
    default_client_bundle_path_in, list_bundle_paths_in, ClientDaemonEvent, ClientDaemonLifecycle,
    ClientDaemonRequest, ClientDaemonResponse, ClientDaemonSnapshot, ClientLaunchOptions,
    ClientLogLevel, ClientRuntimeEvent,
};
use apt_runtime::{
    run_client_with_hooks, ClientRuntimeHooks, ClientRuntimeResult, Mode, RuntimeError,
};
use parking_lot::Mutex;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
    time::sleep,
};
use tracing::{error, info, warn};

#[derive(Clone)]
pub(crate) struct DaemonHandle {
    root_dir: PathBuf,
    snapshot: Arc<Mutex<ClientDaemonSnapshot>>,
    event_tx: broadcast::Sender<ClientDaemonEvent>,
    signal_tx: mpsc::UnboundedSender<SupervisorSignal>,
}

impl DaemonHandle {
    pub(crate) fn new(root_dir: PathBuf) -> Self {
        let snapshot = Arc::new(Mutex::new(ClientDaemonSnapshot {
            selected_bundle_path: Some(default_client_bundle_path_in(&root_dir)),
            daemon_pid: Some(std::process::id()),
            ..ClientDaemonSnapshot::default()
        }));
        let (event_tx, _) = broadcast::channel(512);
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let handle = Self {
            root_dir: root_dir.clone(),
            snapshot: Arc::clone(&snapshot),
            event_tx: event_tx.clone(),
            signal_tx: signal_tx.clone(),
        };
        tokio::spawn(run_supervisor(
            SupervisorState::new(root_dir, snapshot, event_tx, signal_tx),
            signal_rx,
        ));
        handle
    }

    pub(crate) fn snapshot(&self) -> ClientDaemonSnapshot {
        self.snapshot.lock().clone()
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<ClientDaemonEvent> {
        self.event_tx.subscribe()
    }
    pub(crate) async fn dispatch(&self, request: ClientDaemonRequest) -> ClientDaemonResponse {
        match request {
            ClientDaemonRequest::GetSnapshot => ClientDaemonResponse::Snapshot(self.snapshot()),
            ClientDaemonRequest::ListBundles => ClientDaemonResponse::BundleList {
                bundles: list_bundle_paths_in(&self.root_dir).unwrap_or_default(),
                selected: self.snapshot().selected_bundle_path,
            },
            ClientDaemonRequest::Subscribe => ClientDaemonResponse::Subscribed {
                snapshot: self.snapshot(),
            },
            other => self.dispatch_command(other).await,
        }
    }

    async fn dispatch_command(&self, request: ClientDaemonRequest) -> ClientDaemonResponse {
        let (reply_tx, reply_rx) = oneshot::channel();
        let signal = match request {
            ClientDaemonRequest::Connect { options } => {
                SupervisorSignal::Command(SupervisorCommand::Connect { options, reply_tx })
            }
            ClientDaemonRequest::Disconnect => {
                SupervisorSignal::Command(SupervisorCommand::Disconnect { reply_tx })
            }
            ClientDaemonRequest::ReconnectNow => {
                SupervisorSignal::Command(SupervisorCommand::ReconnectNow { reply_tx })
            }
            ClientDaemonRequest::SetMode { mode } => {
                SupervisorSignal::Command(SupervisorCommand::SetMode { mode, reply_tx })
            }
            ClientDaemonRequest::SetBundle { bundle_path } => {
                SupervisorSignal::Command(SupervisorCommand::SetBundle {
                    bundle_path,
                    reply_tx,
                })
            }
            ClientDaemonRequest::GetSnapshot
            | ClientDaemonRequest::Subscribe
            | ClientDaemonRequest::ListBundles => unreachable!("handled above"),
        };
        if self.signal_tx.send(signal).is_err() {
            return ClientDaemonResponse::Error {
                message: "client daemon supervisor is not running".to_string(),
            };
        }
        reply_rx
            .await
            .unwrap_or_else(|_| ClientDaemonResponse::Error {
                message: "client daemon supervisor stopped before replying".to_string(),
            })
    }
}

#[derive(Debug)]
enum SupervisorCommand {
    Connect {
        options: ClientLaunchOptions,
        reply_tx: oneshot::Sender<ClientDaemonResponse>,
    },
    Disconnect {
        reply_tx: oneshot::Sender<ClientDaemonResponse>,
    },
    ReconnectNow {
        reply_tx: oneshot::Sender<ClientDaemonResponse>,
    },
    SetMode {
        mode: u8,
        reply_tx: oneshot::Sender<ClientDaemonResponse>,
    },
    SetBundle {
        bundle_path: PathBuf,
        reply_tx: oneshot::Sender<ClientDaemonResponse>,
    },
}

#[derive(Debug)]
enum SupervisorSignal {
    Command(SupervisorCommand),
    RuntimeEvent {
        generation: u64,
        event: ClientRuntimeEvent,
    },
    SessionFinished {
        generation: u64,
        result: Result<ClientRuntimeResult, RuntimeError>,
    },
    ReconnectTick {
        token: u64,
        remaining_secs: u64,
    },
    ReconnectReady {
        token: u64,
    },
    LatencyMeasured {
        generation: u64,
        rtt_ms: Option<f64>,
    },
}

#[derive(Clone, Debug)]
struct DesiredState {
    bundle_path: PathBuf,
    mode: Option<u8>,
}

#[derive(Debug)]
struct SessionControl {
    generation: u64,
    shutdown_tx: watch::Sender<bool>,
    established: bool,
    _task: JoinHandle<()>,
}

struct SupervisorState {
    snapshot: Arc<Mutex<ClientDaemonSnapshot>>,
    event_tx: broadcast::Sender<ClientDaemonEvent>,
    signal_tx: mpsc::UnboundedSender<SupervisorSignal>,
    desired: DesiredState,
    should_run: bool,
    pending_connect: bool,
    reconnect_armed: bool,
    session: Option<SessionControl>,
    reconnect_token: u64,
    reconnect_attempt: u32,
    next_generation: u64,
    latency_task: Option<JoinHandle<()>>,
}

impl SupervisorState {
    fn new(
        root_dir: PathBuf,
        snapshot: Arc<Mutex<ClientDaemonSnapshot>>,
        event_tx: broadcast::Sender<ClientDaemonEvent>,
        signal_tx: mpsc::UnboundedSender<SupervisorSignal>,
    ) -> Self {
        Self {
            desired: DesiredState {
                bundle_path: default_client_bundle_path_in(&root_dir),
                mode: Some(Mode::STEALTH.value()),
            },
            snapshot,
            event_tx,
            signal_tx,
            should_run: false,
            pending_connect: false,
            reconnect_armed: false,
            session: None,
            reconnect_token: 0,
            reconnect_attempt: 0,
            next_generation: 1,
            latency_task: None,
        }
    }

    fn snapshot(&self) -> ClientDaemonSnapshot {
        self.snapshot.lock().clone()
    }

    fn update_snapshot(
        &self,
        update: impl FnOnce(&mut ClientDaemonSnapshot),
    ) -> ClientDaemonSnapshot {
        let mut snapshot = self.snapshot.lock();
        update(&mut snapshot);
        snapshot.clone()
    }

    fn publish_snapshot(&self) {
        let _ = self
            .event_tx
            .send(ClientDaemonEvent::Snapshot(self.snapshot()));
    }

    fn publish_log(&self, level: ClientLogLevel, message: impl Into<String>) {
        let message = message.into();
        match level {
            ClientLogLevel::Info => info!(message = %message),
            ClientLogLevel::Warn => warn!(message = %message),
            ClientLogLevel::Error => error!(message = %message),
        }
        let _ = self
            .event_tx
            .send(ClientDaemonEvent::Log { level, message });
    }

    fn publish_error(&self, message: impl Into<String>, fatal: bool) {
        let message = message.into();
        self.update_snapshot(|snapshot| {
            snapshot.lifecycle = if fatal {
                ClientDaemonLifecycle::Error
            } else {
                ClientDaemonLifecycle::Reconnecting
            };
            snapshot.last_error = Some(message.clone());
        });
        let _ = self.event_tx.send(ClientDaemonEvent::Error {
            message: message.clone(),
            fatal,
        });
        self.publish_log(
            if fatal {
                ClientLogLevel::Error
            } else {
                ClientLogLevel::Warn
            },
            message,
        );
        self.publish_snapshot();
    }

    fn clear_runtime_details(&self) {
        self.update_snapshot(|snapshot| {
            snapshot.active_carrier = None;
            snapshot.negotiated_mode = None;
            snapshot.interface_name = None;
            snapshot.tunnel_addresses.clear();
            snapshot.server_tunnel_ipv4 = None;
            snapshot.server_tunnel_ipv6 = None;
            snapshot.routes.clear();
            snapshot.tx_bytes = 0;
            snapshot.rx_bytes = 0;
            snapshot.reconnect_in_secs = None;
            snapshot.last_rtt_ms = None;
        });
    }

    fn cancel_latency_task(&mut self) {
        if let Some(task) = self.latency_task.take() {
            task.abort();
        }
    }

    fn current_snapshot_ack(&self, message: impl Into<String>) -> ClientDaemonResponse {
        ClientDaemonResponse::Ack {
            message: message.into(),
            snapshot: self.snapshot(),
        }
    }

    fn apply_connect_options(&mut self, options: ClientLaunchOptions) {
        if let Some(bundle_path) = options.bundle_path {
            self.desired.bundle_path = bundle_path;
        }
        if let Some(mode) = options.mode {
            self.desired.mode = Some(mode);
        }
        self.update_snapshot(|snapshot| {
            snapshot.selected_bundle_path = Some(self.desired.bundle_path.clone());
            snapshot.desired_mode = self.desired.mode;
            snapshot.last_error = None;
            snapshot.reconnect_attempt = 0;
            snapshot.reconnect_in_secs = None;
        });
        self.publish_snapshot();
    }

    fn request_session_shutdown(&mut self, disconnecting: bool) {
        self.reconnect_token = self.reconnect_token.saturating_add(1);
        self.cancel_latency_task();
        if disconnecting {
            self.update_snapshot(|snapshot| {
                snapshot.lifecycle = ClientDaemonLifecycle::Disconnecting;
                snapshot.reconnect_in_secs = None;
            });
            self.publish_snapshot();
        }
        if let Some(session) = self.session.as_ref() {
            let _ = session.shutdown_tx.send(true);
        }
    }

    fn start_session(&mut self, reconnecting: bool) -> Result<(), RuntimeError> {
        let bundle_path = self.desired.bundle_path.clone();
        let (resolved, bundle_server, effective_mode) =
            resolve_client_launch(&bundle_path, self.desired.mode)?;
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let hooks = ClientRuntimeHooks {
            shutdown_rx: Some(shutdown_rx),
            event_tx: Some(event_tx),
        };
        let signal_tx = self.signal_tx.clone();
        let task = tokio::spawn(async move {
            let runtime = tokio::spawn(run_client_with_hooks(resolved, hooks));
            tokio::pin!(runtime);
            loop {
                tokio::select! {
                    maybe_event = event_rx.recv() => {
                        let Some(event) = maybe_event else { continue; };
                        if signal_tx.send(SupervisorSignal::RuntimeEvent { generation, event }).is_err() {
                            break;
                        }
                    }
                    result = &mut runtime => {
                        let runtime_result = match result {
                            Ok(result) => result,
                            Err(join_error) => Err(RuntimeError::InvalidConfig(join_error.to_string())),
                        };
                        let _ = signal_tx.send(SupervisorSignal::SessionFinished { generation, result: runtime_result });
                        break;
                    }
                }
            }
        });
        self.session = Some(SessionControl {
            generation,
            shutdown_tx,
            established: false,
            _task: task,
        });
        self.reconnect_token = self.reconnect_token.saturating_add(1);
        self.update_snapshot(|snapshot| {
            snapshot.lifecycle = if reconnecting {
                ClientDaemonLifecycle::Reconnecting
            } else {
                ClientDaemonLifecycle::Connecting
            };
            snapshot.selected_bundle_path = Some(bundle_path.clone());
            snapshot.server = Some(bundle_server);
            snapshot.desired_mode = Some(effective_mode);
            snapshot.last_error = None;
            snapshot.active_carrier = None;
            snapshot.negotiated_mode = None;
            snapshot.interface_name = None;
            snapshot.tunnel_addresses.clear();
            snapshot.server_tunnel_ipv4 = None;
            snapshot.server_tunnel_ipv6 = None;
            snapshot.routes.clear();
            snapshot.tx_bytes = 0;
            snapshot.rx_bytes = 0;
            snapshot.last_rtt_ms = None;
            snapshot.reconnect_in_secs = None;
            snapshot.reconnect_attempt = self.reconnect_attempt;
        });
        self.publish_log(
            ClientLogLevel::Info,
            format!("starting client session with {}", bundle_path.display()),
        );
        self.publish_snapshot();
        Ok(())
    }

    fn spawn_reconnect_timer(&mut self, reason: String) {
        let delay_secs = reconnect_delay_secs(self.reconnect_attempt);
        self.reconnect_token = self.reconnect_token.saturating_add(1);
        let token = self.reconnect_token;
        self.update_snapshot(|snapshot| {
            snapshot.lifecycle = ClientDaemonLifecycle::Reconnecting;
            snapshot.reconnect_in_secs = Some(delay_secs);
            snapshot.reconnect_attempt = self.reconnect_attempt;
            snapshot.last_error = Some(reason.clone());
        });
        let _ = self.event_tx.send(ClientDaemonEvent::ReconnectScheduled {
            attempt: self.reconnect_attempt,
            in_secs: delay_secs,
            reason: reason.clone(),
        });
        self.publish_log(
            ClientLogLevel::Warn,
            format!("reconnecting in {delay_secs}s: {reason}"),
        );
        self.publish_snapshot();
        let signal_tx = self.signal_tx.clone();
        tokio::spawn(async move {
            let mut remaining = delay_secs;
            while remaining > 0 {
                sleep(Duration::from_secs(1)).await;
                remaining = remaining.saturating_sub(1);
                let _ = signal_tx.send(SupervisorSignal::ReconnectTick {
                    token,
                    remaining_secs: remaining,
                });
            }
            let _ = signal_tx.send(SupervisorSignal::ReconnectReady { token });
        });
    }

    fn start_latency_task(&mut self, generation: u64, target: std::net::Ipv4Addr) {
        self.cancel_latency_task();
        let signal_tx = self.signal_tx.clone();
        self.latency_task = Some(tokio::spawn(async move {
            loop {
                let rtt_ms = measure_tunnel_rtt_ms(target).await.unwrap_or(None);
                if signal_tx
                    .send(SupervisorSignal::LatencyMeasured { generation, rtt_ms })
                    .is_err()
                {
                    break;
                }
                sleep(Duration::from_secs(10)).await;
            }
        }));
    }
}

async fn run_supervisor(
    mut state: SupervisorState,
    mut signal_rx: mpsc::UnboundedReceiver<SupervisorSignal>,
) {
    while let Some(signal) = signal_rx.recv().await {
        match signal {
            SupervisorSignal::Command(command) => match command {
                SupervisorCommand::Connect { options, reply_tx } => {
                    state.apply_connect_options(options);
                    state.should_run = true;
                    state.pending_connect = true;
                    state.reconnect_armed = false;
                    let response = if state.session.is_some() {
                        state.request_session_shutdown(true);
                        state.current_snapshot_ack("restarting client session")
                    } else {
                        match state.start_session(false) {
                            Ok(()) => {
                                state.pending_connect = false;
                                state.current_snapshot_ack("starting client session")
                            }
                            Err(error) => {
                                state.pending_connect = false;
                                state.should_run = false;
                                state.publish_error(error.to_string(), true);
                                ClientDaemonResponse::Error {
                                    message: error.to_string(),
                                }
                            }
                        }
                    };
                    let _ = reply_tx.send(response);
                }
                SupervisorCommand::Disconnect { reply_tx } => {
                    state.should_run = false;
                    state.pending_connect = false;
                    state.reconnect_armed = false;
                    state.reconnect_attempt = 0;
                    state.request_session_shutdown(true);
                    if state.session.is_none() {
                        state.clear_runtime_details();
                        state.update_snapshot(|snapshot| {
                            snapshot.lifecycle = ClientDaemonLifecycle::Idle;
                            snapshot.last_error = None;
                        });
                        state.publish_snapshot();
                    }
                    let _ = reply_tx.send(state.current_snapshot_ack("disconnect requested"));
                }
                SupervisorCommand::ReconnectNow { reply_tx } => {
                    state.should_run = true;
                    state.pending_connect = true;
                    state.reconnect_armed = false;
                    state.reconnect_attempt = 0;
                    state.update_snapshot(|snapshot| {
                        snapshot.reconnect_attempt = 0;
                        snapshot.reconnect_in_secs = None;
                        snapshot.last_error = None;
                    });
                    let response = if state.session.is_some() {
                        state.request_session_shutdown(true);
                        state.current_snapshot_ack("reconnect requested")
                    } else {
                        match state.start_session(true) {
                            Ok(()) => {
                                state.pending_connect = false;
                                state.current_snapshot_ack("reconnect requested")
                            }
                            Err(error) => {
                                state.pending_connect = false;
                                state.should_run = false;
                                state.publish_error(error.to_string(), true);
                                ClientDaemonResponse::Error {
                                    message: error.to_string(),
                                }
                            }
                        }
                    };
                    let _ = reply_tx.send(response);
                }
                SupervisorCommand::SetMode { mode, reply_tx } => {
                    state.desired.mode = Some(mode);
                    state.reconnect_armed = false;
                    state.update_snapshot(|snapshot| snapshot.desired_mode = Some(mode));
                    state.publish_log(
                        ClientLogLevel::Info,
                        format!("set requested mode to {mode}"),
                    );
                    state.publish_snapshot();
                    if state.should_run {
                        state.pending_connect = true;
                        if state.session.is_some() {
                            state.request_session_shutdown(true);
                        } else if let Err(error) = state.start_session(false) {
                            state.pending_connect = false;
                            state.should_run = false;
                            state.publish_error(error.to_string(), true);
                            let _ = reply_tx.send(ClientDaemonResponse::Error {
                                message: error.to_string(),
                            });
                            continue;
                        } else {
                            state.pending_connect = false;
                        }
                    }
                    let _ = reply_tx.send(state.current_snapshot_ack("updated requested mode"));
                }
                SupervisorCommand::SetBundle {
                    bundle_path,
                    reply_tx,
                } => {
                    state.desired.bundle_path = bundle_path.clone();
                    state.reconnect_armed = false;
                    state.update_snapshot(|snapshot| {
                        snapshot.selected_bundle_path = Some(bundle_path.clone())
                    });
                    state.publish_log(
                        ClientLogLevel::Info,
                        format!("selected client bundle {}", bundle_path.display()),
                    );
                    state.publish_snapshot();
                    if state.should_run {
                        state.pending_connect = true;
                        if state.session.is_some() {
                            state.request_session_shutdown(true);
                        } else if let Err(error) = state.start_session(false) {
                            state.pending_connect = false;
                            state.should_run = false;
                            state.publish_error(error.to_string(), true);
                            let _ = reply_tx.send(ClientDaemonResponse::Error {
                                message: error.to_string(),
                            });
                            continue;
                        } else {
                            state.pending_connect = false;
                        }
                    }
                    let _ = reply_tx.send(state.current_snapshot_ack("updated selected bundle"));
                }
            },
            SupervisorSignal::RuntimeEvent { generation, event } => {
                if state
                    .session
                    .as_ref()
                    .map(|session| session.generation != generation)
                    .unwrap_or(true)
                {
                    continue;
                }
                match event {
                    ClientRuntimeEvent::Starting {
                        server,
                        requested_mode,
                    } => {
                        state.update_snapshot(|snapshot| {
                            snapshot.lifecycle = ClientDaemonLifecycle::Connecting;
                            snapshot.server = Some(server.clone());
                            snapshot.desired_mode = Some(requested_mode);
                        });
                        state.publish_snapshot();
                    }
                    ClientRuntimeEvent::SessionEstablished { session } => {
                        if let Some(active_session) = state.session.as_mut() {
                            active_session.established = true;
                        }
                        state.reconnect_armed = true;
                        state.update_snapshot(|snapshot| {
                            snapshot.lifecycle = ClientDaemonLifecycle::Connected;
                            snapshot.server = Some(session.server.clone());
                            snapshot.active_carrier = Some(session.carrier.clone());
                            snapshot.negotiated_mode = Some(session.negotiated_mode);
                            snapshot.interface_name = Some(session.interface_name.clone());
                            snapshot.tunnel_addresses = session.tunnel_addresses.clone();
                            snapshot.server_tunnel_ipv4 = session.server_tunnel_ipv4;
                            snapshot.server_tunnel_ipv6 = session.server_tunnel_ipv6;
                            snapshot.routes = session.routes.clone();
                            snapshot.reconnect_attempt = 0;
                            snapshot.reconnect_in_secs = None;
                            snapshot.last_error = None;
                        });
                        state.publish_log(
                            ClientLogLevel::Info,
                            format!(
                                "session established via {} at mode {}",
                                session.carrier, session.negotiated_mode
                            ),
                        );
                        let _ = state.event_tx.send(ClientDaemonEvent::SessionEstablished {
                            session: session.clone(),
                        });
                        state.publish_snapshot();
                        state.reconnect_attempt = 0;
                        if let Some(target) = session.server_tunnel_ipv4 {
                            state.start_latency_task(generation, target);
                        }
                    }
                    ClientRuntimeEvent::ModeChanged { mode } => {
                        state.update_snapshot(|snapshot| snapshot.negotiated_mode = Some(mode));
                        let _ = state.event_tx.send(ClientDaemonEvent::ModeChanged { mode });
                        state.publish_log(
                            ClientLogLevel::Info,
                            format!("adaptive mode changed to {mode}"),
                        );
                        state.publish_snapshot();
                    }
                    ClientRuntimeEvent::StatsTick { tx_bytes, rx_bytes } => {
                        state.update_snapshot(|snapshot| {
                            snapshot.tx_bytes = tx_bytes;
                            snapshot.rx_bytes = rx_bytes;
                        });
                        let snapshot = state.snapshot();
                        let _ = state.event_tx.send(ClientDaemonEvent::StatsTick {
                            tx_bytes,
                            rx_bytes,
                            last_rtt_ms: snapshot.last_rtt_ms,
                        });
                    }
                    ClientRuntimeEvent::SessionEnded { reason } => {
                        state.publish_log(
                            ClientLogLevel::Warn,
                            format!(
                                "session ended{}",
                                reason
                                    .as_deref()
                                    .map(|detail| format!(": {detail}"))
                                    .unwrap_or_default()
                            ),
                        );
                    }
                }
            }
            SupervisorSignal::SessionFinished { generation, result } => {
                let had_established = state
                    .session
                    .as_ref()
                    .map(|session| session.established)
                    .unwrap_or(false);
                if state
                    .session
                    .as_ref()
                    .map(|session| session.generation != generation)
                    .unwrap_or(true)
                {
                    continue;
                }
                state.session = None;
                state.cancel_latency_task();
                if state.pending_connect {
                    state.pending_connect = false;
                    if let Err(error) = state.start_session(true) {
                        state.should_run = false;
                        state.publish_error(error.to_string(), true);
                    }
                    continue;
                }
                if !state.should_run {
                    state.clear_runtime_details();
                    state.update_snapshot(|snapshot| {
                        snapshot.lifecycle = ClientDaemonLifecycle::Idle;
                        snapshot.last_error = None;
                        snapshot.reconnect_attempt = 0;
                        snapshot.reconnect_in_secs = None;
                    });
                    state.publish_log(ClientLogLevel::Info, "client session stopped");
                    state.publish_snapshot();
                    continue;
                }
                match result {
                    Ok(_)
                        if should_schedule_reconnect(
                            None,
                            state.reconnect_armed,
                            had_established,
                        ) =>
                    {
                        state.reconnect_attempt = state.reconnect_attempt.saturating_add(1);
                        state.clear_runtime_details();
                        state.spawn_reconnect_timer("client session disconnected".to_string());
                    }
                    Ok(_) => {
                        state.should_run = false;
                        state.clear_runtime_details();
                        state.publish_error(
                            "client session ended before an active connection was established"
                                .to_string(),
                            true,
                        );
                    }
                    Err(error)
                        if should_schedule_reconnect(
                            Some(&error),
                            state.reconnect_armed,
                            had_established,
                        ) =>
                    {
                        state.reconnect_attempt = state.reconnect_attempt.saturating_add(1);
                        state.clear_runtime_details();
                        state.spawn_reconnect_timer(error.to_string());
                    }
                    Err(error) => {
                        state.should_run = false;
                        state.clear_runtime_details();
                        state.publish_error(error.to_string(), true);
                    }
                }
            }
            SupervisorSignal::ReconnectTick {
                token,
                remaining_secs,
            } => {
                if token != state.reconnect_token || !state.should_run {
                    continue;
                }
                state.update_snapshot(|snapshot| snapshot.reconnect_in_secs = Some(remaining_secs));
                state.publish_snapshot();
            }
            SupervisorSignal::ReconnectReady { token } => {
                if token != state.reconnect_token || !state.should_run || state.session.is_some() {
                    continue;
                }
                if let Err(error) = state.start_session(true) {
                    state.should_run = false;
                    state.publish_error(error.to_string(), true);
                }
            }
            SupervisorSignal::LatencyMeasured { generation, rtt_ms } => {
                if state
                    .session
                    .as_ref()
                    .map(|session| session.generation != generation)
                    .unwrap_or(true)
                {
                    continue;
                }
                state.update_snapshot(|snapshot| snapshot.last_rtt_ms = rtt_ms);
                let snapshot = state.snapshot();
                let _ = state.event_tx.send(ClientDaemonEvent::StatsTick {
                    tx_bytes: snapshot.tx_bytes,
                    rx_bytes: snapshot.rx_bytes,
                    last_rtt_ms: snapshot.last_rtt_ms,
                });
            }
        }
    }
}

fn resolve_client_launch(
    bundle_path: &Path,
    mode_override: Option<u8>,
) -> Result<(apt_runtime::ResolvedClientConfig, String, u8), RuntimeError> {
    let mut bundle = load_client_bundle(bundle_path)
        .map_err(|error| RuntimeError::InvalidConfig(error.to_string()))?;
    bundle.config.state_path = client_bundle_state_path(bundle_path);
    let _ = apply_optional_client_override(&mut bundle.config, bundle_path)
        .map_err(|error| RuntimeError::InvalidConfig(error.to_string()))?;
    if let Some(mode) = mode_override {
        bundle.config.mode =
            Mode::try_from(mode).map_err(|error| RuntimeError::InvalidConfig(error.to_string()))?;
    }
    let resolved = bundle.config.resolve()?;
    Ok((
        resolved,
        bundle.config.server_addr,
        bundle.config.mode.value(),
    ))
}

fn reconnect_delay_secs(attempt: u32) -> u64 {
    match attempt {
        0 | 1 => 1,
        2 => 2,
        3 => 5,
        4 => 10,
        _ => 30,
    }
}

fn should_schedule_reconnect(
    error: Option<&RuntimeError>,
    reconnect_armed: bool,
    had_established: bool,
) -> bool {
    if !reconnect_armed && !had_established {
        return false;
    }
    match error {
        None => true,
        Some(error) => is_retriable_error(error),
    }
}

fn is_retriable_error(error: &RuntimeError) -> bool {
    matches!(
        error,
        RuntimeError::Io(_)
            | RuntimeError::Carrier(_)
            | RuntimeError::Crypto(_)
            | RuntimeError::Tunnel(_)
            | RuntimeError::Quic(_)
            | RuntimeError::Timeout(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_delay_schedule_matches_expected_backoff() {
        assert_eq!(reconnect_delay_secs(0), 1);
        assert_eq!(reconnect_delay_secs(1), 1);
        assert_eq!(reconnect_delay_secs(2), 2);
        assert_eq!(reconnect_delay_secs(3), 5);
        assert_eq!(reconnect_delay_secs(4), 10);
        assert_eq!(reconnect_delay_secs(5), 30);
        assert_eq!(reconnect_delay_secs(12), 30);
    }

    #[test]
    fn retriable_error_classification_matches_supervisor_policy() {
        assert!(is_retriable_error(&RuntimeError::Io(
            std::io::Error::other("temporary io failure")
        )));
        assert!(is_retriable_error(&RuntimeError::Quic(
            "temporary quic failure".to_string()
        )));
        assert!(is_retriable_error(&RuntimeError::Timeout("handshake")));

        assert!(!is_retriable_error(&RuntimeError::InvalidConfig(
            "bad bundle".to_string()
        )));
        assert!(!is_retriable_error(&RuntimeError::UnauthorizedPeer));
        assert!(!is_retriable_error(&RuntimeError::UnsupportedPlatform(
            "dns automation"
        )));
        assert!(!is_retriable_error(&RuntimeError::Canceled("shutdown")));
    }

    #[test]
    fn reconnect_only_arms_after_a_real_established_session() {
        assert!(!should_schedule_reconnect(
            Some(&RuntimeError::Timeout("handshake")),
            false,
            false,
        ));
        assert!(!should_schedule_reconnect(None, false, false));

        assert!(should_schedule_reconnect(
            Some(&RuntimeError::Timeout("live session")),
            true,
            true,
        ));
        assert!(should_schedule_reconnect(None, true, true));
        assert!(!should_schedule_reconnect(
            Some(&RuntimeError::InvalidConfig("bad bundle".to_string())),
            true,
            true,
        ));
    }
}
