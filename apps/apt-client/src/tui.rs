use crate::{
    cli::TuiOptions,
    daemon_client::{send_request, subscribe},
    paths::ensure_user_owned_override,
};
use apt_client_control::{
    ClientCarrier, ClientDaemonEvent, ClientDaemonLifecycle, ClientDaemonRequest,
    ClientDaemonResponse, ClientDaemonSnapshot,
};
use crossterm::{
    event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Terminal,
};
use std::{
    collections::VecDeque,
    io::{self, Stdout},
    path::PathBuf,
    time::Duration,
};
use tokio::{sync::mpsc, time::sleep};

const MAX_LOG_LINES: usize = 200;

pub(super) async fn run_tui(
    options: TuiOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut subscription = subscribe().await?;
    let mut app = App::new(subscription.initial_snapshot.clone());
    refresh_known_bundles(&mut app).await?;
    apply_initial_options(&mut app, options).await?;

    let mut terminal = setup_terminal()?;
    let (term_tx, mut term_rx) = mpsc::unbounded_channel();
    spawn_terminal_input(term_tx);

    let run_result = async {
        loop {
            terminal.draw(|frame| draw(frame, &app))?;
            tokio::select! {
                maybe_input = term_rx.recv() => {
                    let Some(input) = maybe_input else { break; };
                    if handle_input(&mut app, input).await? {
                        break;
                    }
                }
                maybe_event = subscription.next_event() => {
                    match maybe_event? {
                        Some(event) => app.apply_event(event),
                        None => {
                            app.push_log("daemon event stream ended".to_string());
                            break;
                        }
                    }
                }
                _ = sleep(Duration::from_millis(100)) => {}
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let restore_result = restore_terminal(terminal);
    match (run_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(run_error), Err(restore_error)) => Err(format!(
            "{run_error}; additionally failed to restore terminal: {restore_error}"
        )
        .into()),
    }
}

struct App {
    snapshot: ClientDaemonSnapshot,
    logs: VecDeque<String>,
    known_bundles: Vec<PathBuf>,
    bundle_input: String,
    editing_bundle: bool,
}

impl App {
    fn new(snapshot: ClientDaemonSnapshot) -> Self {
        Self {
            bundle_input: snapshot
                .selected_bundle_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            snapshot,
            logs: VecDeque::new(),
            known_bundles: Vec::new(),
            editing_bundle: false,
        }
    }

    fn apply_event(&mut self, event: ClientDaemonEvent) {
        match event {
            ClientDaemonEvent::Snapshot(snapshot) => {
                self.snapshot = snapshot;
                if !self.editing_bundle {
                    self.bundle_input = self
                        .snapshot
                        .selected_bundle_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default();
                }
            }
            ClientDaemonEvent::Log { level, message } => {
                self.push_log(format!("[{level:?}] {message}"));
            }
            ClientDaemonEvent::SessionEstablished { session } => {
                self.push_log(format!(
                    "connected via {} at mode {} on {}",
                    session.carrier, session.negotiated_mode, session.interface_name
                ));
            }
            ClientDaemonEvent::CarrierChanged { from, to } => {
                self.push_log(format!(
                    "carrier changed: {} -> {}",
                    from.unwrap_or_else(|| "unknown".to_string()),
                    to
                ));
            }
            ClientDaemonEvent::ModeChanged { mode } => {
                self.push_log(format!("adaptive mode changed to {mode}"));
            }
            ClientDaemonEvent::StatsTick { .. } => {}
            ClientDaemonEvent::ReconnectScheduled {
                attempt,
                in_secs,
                reason,
            } => {
                self.push_log(format!("reconnect #{attempt} in {in_secs}s: {reason}"));
            }
            ClientDaemonEvent::Error { message, fatal } => {
                if fatal {
                    self.push_log(format!("[ERROR] {message}"));
                } else {
                    self.push_log(format!("[WARN] {message}"));
                }
            }
        }
    }

    fn push_log(&mut self, message: String) {
        self.logs.push_back(message);
        while self.logs.len() > MAX_LOG_LINES {
            self.logs.pop_front();
        }
    }
}

async fn apply_initial_options(
    app: &mut App,
    options: TuiOptions,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(bundle) = options.launch.bundle {
        let _ = ensure_user_owned_override(&bundle)?;
        apply_response(
            app,
            send_request(ClientDaemonRequest::SetBundle {
                bundle_path: bundle,
            })
            .await?,
        );
    }
    if let Some(mode) = options.launch.mode {
        apply_response(
            app,
            send_request(ClientDaemonRequest::SetMode { mode }).await?,
        );
    }
    if let Some(carrier) = options.launch.carrier {
        apply_response(
            app,
            send_request(ClientDaemonRequest::SetCarrier {
                carrier: carrier.into(),
            })
            .await?,
        );
    }
    refresh_known_bundles(app).await?;
    Ok(())
}

async fn refresh_known_bundles(
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match send_request(ClientDaemonRequest::ListBundles).await? {
        ClientDaemonResponse::BundleList { bundles, selected } => {
            app.known_bundles = bundles;
            if let Some(selected) = selected {
                app.snapshot.selected_bundle_path = Some(selected.clone());
                if !app.editing_bundle {
                    app.bundle_input = selected.display().to_string();
                }
            }
        }
        ClientDaemonResponse::Error { message } => app.push_log(format!("[ERROR] {message}")),
        other => app.push_log(format!("unexpected bundle-list response: {other:?}")),
    }
    Ok(())
}

async fn handle_input(
    app: &mut App,
    input: CEvent,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let CEvent::Key(key) = input else {
        return Ok(false);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }
    if app.editing_bundle {
        return handle_bundle_input(app, key.code).await;
    }
    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Char('c') => {
            if matches!(
                app.snapshot.lifecycle,
                ClientDaemonLifecycle::Connected
                    | ClientDaemonLifecycle::Connecting
                    | ClientDaemonLifecycle::Reconnecting
                    | ClientDaemonLifecycle::Disconnecting
            ) {
                apply_response(app, send_request(ClientDaemonRequest::Disconnect).await?);
            } else {
                let bundle_path = current_bundle_path(app)?;
                let _ = ensure_user_owned_override(&bundle_path)?;
                apply_response(
                    app,
                    send_request(ClientDaemonRequest::Connect {
                        options: apt_client_control::ClientLaunchOptions {
                            bundle_path: Some(bundle_path),
                            mode: app.snapshot.desired_mode,
                            carrier: Some(app.snapshot.desired_carrier),
                        },
                    })
                    .await?,
                );
            }
        }
        KeyCode::Char('r') => {
            apply_response(app, send_request(ClientDaemonRequest::ReconnectNow).await?);
        }
        KeyCode::Char('k') => {
            let next = next_carrier(app.snapshot.desired_carrier);
            apply_response(
                app,
                send_request(ClientDaemonRequest::SetCarrier { carrier: next }).await?,
            );
        }
        KeyCode::Char('b') => {
            if app.known_bundles.is_empty() {
                app.push_log("no bundles were found under ~/.adapt-tunnel".to_string());
            } else {
                let next = next_bundle(app)?;
                let _ = ensure_user_owned_override(&next)?;
                apply_response(
                    app,
                    send_request(ClientDaemonRequest::SetBundle { bundle_path: next }).await?,
                );
            }
        }
        KeyCode::Char('e') => {
            app.editing_bundle = true;
            app.bundle_input = app
                .snapshot
                .selected_bundle_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            let next = app
                .snapshot
                .desired_mode
                .unwrap_or(100)
                .saturating_add(5)
                .min(100);
            apply_response(
                app,
                send_request(ClientDaemonRequest::SetMode { mode: next }).await?,
            );
        }
        KeyCode::Char('-') => {
            let next = app.snapshot.desired_mode.unwrap_or(100).saturating_sub(5);
            apply_response(
                app,
                send_request(ClientDaemonRequest::SetMode { mode: next }).await?,
            );
        }
        KeyCode::Esc if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(true),
        _ => {}
    }
    Ok(false)
}

async fn handle_bundle_input(
    app: &mut App,
    code: KeyCode,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    match code {
        KeyCode::Esc => {
            app.editing_bundle = false;
        }
        KeyCode::Enter => {
            let bundle = PathBuf::from(app.bundle_input.trim());
            if !app.bundle_input.trim().is_empty() {
                let _ = ensure_user_owned_override(&bundle)?;
                apply_response(
                    app,
                    send_request(ClientDaemonRequest::SetBundle {
                        bundle_path: bundle,
                    })
                    .await?,
                );
                refresh_known_bundles(app).await?;
            }
            app.editing_bundle = false;
        }
        KeyCode::Backspace => {
            app.bundle_input.pop();
        }
        KeyCode::Char(ch) => {
            app.bundle_input.push(ch);
        }
        _ => {}
    }
    Ok(false)
}

fn apply_response(app: &mut App, response: ClientDaemonResponse) {
    match response {
        ClientDaemonResponse::Ack { message, snapshot } => {
            app.push_log(message);
            app.snapshot = snapshot;
        }
        ClientDaemonResponse::Snapshot(snapshot) => {
            app.snapshot = snapshot;
        }
        ClientDaemonResponse::Error { message } => {
            app.push_log(format!("[ERROR] {message}"));
        }
        ClientDaemonResponse::BundleList { bundles, selected } => {
            app.known_bundles = bundles;
            app.snapshot.selected_bundle_path = selected;
        }
        ClientDaemonResponse::Subscribed { snapshot } => {
            app.snapshot = snapshot;
        }
    }
}

fn next_carrier(current: ClientCarrier) -> ClientCarrier {
    match current {
        ClientCarrier::Auto => ClientCarrier::D1,
        ClientCarrier::D1 => ClientCarrier::D2,
        ClientCarrier::D2 => ClientCarrier::S1,
        ClientCarrier::S1 => ClientCarrier::Auto,
    }
}

fn next_bundle(app: &App) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let current = app.snapshot.selected_bundle_path.as_ref();
    let next_index = current
        .and_then(|current| {
            app.known_bundles
                .iter()
                .position(|bundle| bundle == current)
        })
        .map_or(0, |index| (index + 1) % app.known_bundles.len());
    Ok(app.known_bundles[next_index].clone())
}

fn current_bundle_path(app: &App) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    app.snapshot
        .selected_bundle_path
        .clone()
        .or_else(|| {
            if app.bundle_input.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(app.bundle_input.trim()))
            }
        })
        .ok_or_else(|| "no bundle is currently selected".into())
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &App) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(frame.size());

    frame.render_widget(summary_widget(app), areas[0]);
    frame.render_widget(stats_widget(app), areas[1]);
    frame.render_widget(logs_widget(app), areas[2]);
    frame.render_widget(actions_widget(app), areas[3]);

    if app.editing_bundle {
        let popup = centered_rect(80, 5, frame.size());
        frame.render_widget(Clear, popup);
        let block = Block::default()
            .title("Edit bundle path (Enter to apply, Esc to cancel)")
            .borders(Borders::ALL);
        let widget = Paragraph::new(app.bundle_input.clone())
            .block(block)
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, popup);
    }
}

fn summary_widget(app: &App) -> Paragraph<'static> {
    let bundle = app
        .snapshot
        .selected_bundle_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string());
    let server = app
        .snapshot
        .server
        .clone()
        .unwrap_or_else(|| "-".to_string());
    let interface = app
        .snapshot
        .interface_name
        .clone()
        .unwrap_or_else(|| "-".to_string());
    let carrier = app
        .snapshot
        .active_carrier
        .clone()
        .unwrap_or_else(|| app.snapshot.desired_carrier.as_str().to_string());
    let mode = app
        .snapshot
        .negotiated_mode
        .or(app.snapshot.desired_mode)
        .map_or_else(|| "-".to_string(), |mode| mode.to_string());
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("{:?}", app.snapshot.lifecycle)),
            Span::raw("    "),
            Span::styled("Server: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(server),
        ]),
        Line::from(vec![
            Span::styled("Carrier: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(carrier),
            Span::raw("    "),
            Span::styled("Mode: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(mode),
            Span::raw("    "),
            Span::styled("Iface: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(interface),
        ]),
        Line::from(vec![
            Span::styled("Bundle: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(bundle),
        ]),
    ])
    .block(Block::default().title("Session").borders(Borders::ALL))
    .wrap(Wrap { trim: false })
}

fn stats_widget(app: &App) -> Paragraph<'static> {
    let rtt = app
        .snapshot
        .last_rtt_ms
        .map_or_else(|| "-".to_string(), |value| format!("{value:.2} ms"));
    let reconnect = app
        .snapshot
        .reconnect_in_secs
        .map_or_else(|| "-".to_string(), |secs| format!("{secs}s"));
    let tunnel_ips = if app.snapshot.tunnel_addresses.is_empty() {
        "-".to_string()
    } else {
        app.snapshot
            .tunnel_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    Paragraph::new(vec![
        Line::from(format!(
            "TX: {} bytes    RX: {} bytes    RTT: {}",
            app.snapshot.tx_bytes, app.snapshot.rx_bytes, rtt
        )),
        Line::from(format!(
            "Reconnect: {}    Attempt: {}",
            reconnect, app.snapshot.reconnect_attempt
        )),
        Line::from(format!("Tunnel IPs: {tunnel_ips}")),
    ])
    .block(Block::default().title("Live stats").borders(Borders::ALL))
    .wrap(Wrap { trim: false })
}

fn logs_widget(app: &App) -> Paragraph<'static> {
    let lines = app
        .logs
        .iter()
        .rev()
        .take(18)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(Line::from)
        .collect::<Vec<_>>();
    Paragraph::new(lines)
        .block(Block::default().title("Logs").borders(Borders::ALL))
        .wrap(Wrap { trim: false })
}

fn actions_widget(app: &App) -> Paragraph<'static> {
    let connect_label = if matches!(
        app.snapshot.lifecycle,
        ClientDaemonLifecycle::Connected
            | ClientDaemonLifecycle::Connecting
            | ClientDaemonLifecycle::Reconnecting
            | ClientDaemonLifecycle::Disconnecting
    ) {
        "c disconnect"
    } else {
        "c connect"
    };
    Paragraph::new(vec![Line::from(format!(
        "{}  •  r reconnect  •  +/- mode  •  k carrier  •  b cycle bundle  •  e edit bundle  •  q quit",
        connect_label
    ))])
    .block(Block::default().title("Actions").borders(Borders::ALL))
}

fn setup_terminal(
) -> Result<Terminal<CrosstermBackend<Stdout>>, Box<dyn std::error::Error + Send + Sync>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }
    let backend = CrosstermBackend::new(stdout);
    match Terminal::new(backend) {
        Ok(terminal) => Ok(terminal),
        Err(error) => {
            let mut stdout = io::stdout();
            let _ = execute!(stdout, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            Err(error.into())
        }
    }
}

fn restore_terminal(
    mut terminal: Terminal<CrosstermBackend<Stdout>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn spawn_terminal_input(term_tx: mpsc::UnboundedSender<CEvent>) {
    std::thread::spawn(move || loop {
        if event::poll(Duration::from_millis(100)).ok() != Some(true) {
            continue;
        }
        let Ok(event) = event::read() else {
            break;
        };
        if term_tx.send(event).is_err() {
            break;
        }
    });
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let popup_width = area.width.saturating_mul(percent_x).saturating_div(100);
    let popup_height = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + area.width.saturating_sub(popup_width).saturating_div(2),
        y: area.y + area.height.saturating_sub(popup_height).saturating_div(2),
        width: popup_width,
        height: popup_height,
    }
}
