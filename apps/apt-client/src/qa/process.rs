use super::EstablishedSession;
use crate::CliCarrier;
use std::{
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
    sync::mpsc,
    time::{sleep, timeout},
};

const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 10;
const MAX_READY_TAIL_LINES: usize = 12;

#[derive(Debug)]
pub(super) struct ManagedClientChild {
    pub child: Child,
    pub lines_rx: Option<mpsc::UnboundedReceiver<String>>,
    pub pid: u32,
}

pub(super) fn spawn_client_up_process(
    bundle_path: &Path,
    mode: Option<u8>,
    carrier: Option<CliCarrier>,
) -> Result<ManagedClientChild, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let mut command = Command::new(exe);
    command.arg("up").arg("--bundle").arg(bundle_path);
    if let Some(mode) = mode {
        command.arg("--mode").arg(mode.to_string());
    }
    if let Some(carrier) = carrier {
        command.arg("--carrier").arg(match carrier {
            CliCarrier::Auto => "auto",
            CliCarrier::D1 => "d1",
            CliCarrier::D2 => "d2",
            CliCarrier::S1 => "s1",
        });
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or("failed to determine child pid for test session")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("failed to capture child stdout")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("failed to capture child stderr")?;
    let (lines_tx, lines_rx) = mpsc::unbounded_channel();
    tokio::spawn(forward_child_stream(stdout, lines_tx.clone()));
    tokio::spawn(forward_child_stream(stderr, lines_tx));
    Ok(ManagedClientChild {
        child,
        lines_rx: Some(lines_rx),
        pid,
    })
}

pub(super) async fn wait_for_established_session(
    child: &mut ManagedClientChild,
    timeout_secs: u64,
) -> Result<EstablishedSession, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut last_lines = Vec::new();

    loop {
        if let Some(status) = child.child.try_wait()? {
            let tail = recent_tail(&last_lines);
            return Err(format!(
                "test session failed before tunnel establishment (status: {status}). Recent output:\n{tail}"
            )
            .into());
        }
        if Instant::now() >= deadline {
            let tail = recent_tail(&last_lines);
            return Err(format!(
                "timed out waiting for tunnel establishment after {timeout_secs}s. Recent output:\n{tail}"
            )
            .into());
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let Some(lines_rx) = child.lines_rx.as_mut() else {
            return Err("child output channel missing while waiting for readiness".into());
        };
        match timeout(remaining.min(Duration::from_millis(250)), lines_rx.recv()).await {
            Ok(Some(line)) => {
                println!("[client] {line}");
                push_recent_line(&mut last_lines, &line);
                if let Some(session) = parse_established_session(&line) {
                    return Ok(session);
                }
            }
            Ok(None) => sleep(Duration::from_millis(50)).await,
            Err(_) => {}
        }
    }
}

pub(super) async fn drain_client_output(mut lines_rx: mpsc::UnboundedReceiver<String>) {
    while let Some(line) = lines_rx.recv().await {
        println!("[client] {line}");
    }
}

pub(super) async fn shutdown_client_process(
    child: &mut ManagedClientChild,
) -> Result<(), Box<dyn std::error::Error>> {
    if child.child.try_wait()?.is_some() {
        return Ok(());
    }
    let status = Command::new("kill")
        .arg("-INT")
        .arg(child.pid.to_string())
        .status()
        .await?;
    if !status.success() {
        child.child.start_kill()?;
    }
    match timeout(
        Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS),
        child.child.wait(),
    )
    .await
    {
        Ok(wait_result) => {
            let _ = wait_result?;
            Ok(())
        }
        Err(_) => {
            child.child.start_kill()?;
            let _ = child.child.wait().await?;
            Ok(())
        }
    }
}

async fn forward_child_stream<R>(reader: R, lines_tx: mpsc::UnboundedSender<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut lines = BufReader::new(reader).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if lines_tx.send(line).is_err() {
                    break;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
}

fn push_recent_line(lines: &mut Vec<String>, line: &str) {
    lines.push(line.to_string());
    if lines.len() > MAX_READY_TAIL_LINES {
        let drain = lines.len() - MAX_READY_TAIL_LINES;
        lines.drain(..drain);
    }
}

fn recent_tail(lines: &[String]) -> String {
    if lines.is_empty() {
        String::from("no client output captured")
    } else {
        lines.join("\n")
    }
}

fn parse_established_session(line: &str) -> Option<EstablishedSession> {
    if !line.contains("client session established") {
        return None;
    }

    Some(EstablishedSession {
        server: extract_log_field(line, "server=", " tunnel_ipv4=")?,
        tunnel_ipv4: extract_log_field(line, "tunnel_ipv4=", " tunnel_ipv6=")
            .and_then(|value| value.parse().ok())?,
        tunnel_ipv6: parse_optional_ip(&extract_log_field(
            line,
            "tunnel_ipv6=",
            " server_tunnel_ip=",
        )?)?,
        server_tunnel_ipv4: extract_log_field(line, "server_tunnel_ip=", " server_tunnel_ipv6=")
            .and_then(|value| value.parse().ok())?,
        server_tunnel_ipv6: parse_optional_ip(&extract_log_field(
            line,
            "server_tunnel_ipv6=",
            " interface=",
        )?)?,
        interface_name: extract_log_field(line, "interface=", " routes=")?,
        routes: parse_route_list(&extract_log_field(line, "routes=", " carrier=")?),
        carrier: extract_log_field(line, "carrier=", " encapsulation=")?,
        negotiated_mode: extract_tail_field(line, "negotiated_mode=")?.parse().ok()?,
    })
}

fn extract_log_field(line: &str, key: &str, next_key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let end = line[start..]
        .find(next_key)
        .map(|index| start + index)
        .unwrap_or_else(|| line.len());
    Some(trim_log_value(&line[start..end]))
}

fn extract_tail_field(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    Some(trim_log_value(&line[start..]))
}

fn trim_log_value(value: &str) -> String {
    value.trim().trim_matches('"').trim().to_string()
}

fn parse_optional_ip<T>(value: &str) -> Option<Option<T>>
where
    T: std::str::FromStr,
{
    let trimmed = value.trim();
    if trimmed == "None" {
        return Some(None);
    }
    if let Some(inner) = trimmed
        .strip_prefix("Some(")
        .and_then(|inner| inner.strip_suffix(')'))
    {
        return inner.parse().ok().map(Some);
    }
    trimmed.parse().ok().map(Some)
}

fn parse_route_list(value: &str) -> Vec<String> {
    value
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(str::trim)
        .filter(|route| !route.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_established_session_log_line() {
        let line = "INFO client session established server=198.51.100.10:51820 tunnel_ipv4=10.77.0.2 tunnel_ipv6=Some(fd77:77::2) server_tunnel_ip=10.77.0.1 server_tunnel_ipv6=Some(fd77:77::1) interface=utun4 routes=[0.0.0.0/0, ::/0] carrier=D1 encapsulation=wrapped requested_mode=50 negotiated_mode=72";
        let parsed = parse_established_session(line).expect("log should parse");
        assert_eq!(parsed.server, "198.51.100.10:51820");
        assert_eq!(
            parsed.tunnel_ipv4,
            "10.77.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(
            parsed.server_tunnel_ipv4,
            "10.77.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(parsed.interface_name, "utun4");
        assert_eq!(parsed.carrier, "D1");
        assert_eq!(parsed.negotiated_mode, 72);
        assert_eq!(parsed.routes, vec!["0.0.0.0/0", "::/0"]);
        assert!(parsed.has_default_route());
    }
}
