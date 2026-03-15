use super::{fail_result, pass_result, QaCheckResult};
use reqwest::Url;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{
    process::Command,
    sync::watch,
    time::{sleep, timeout},
};

const DEFAULT_SPEEDTEST_BASE_URL: &str = "https://speed.cloudflare.com/__down";

#[derive(Debug)]
struct PingMetrics {
    transmitted: u32,
    received: u32,
    packet_loss_percent: f64,
    avg_rtt_ms: Option<f64>,
}

#[derive(Debug)]
struct DownloadMetrics {
    bytes: usize,
    elapsed: Duration,
    ttfb: Duration,
    throughput_mbps: f64,
}

#[derive(Debug, Clone, Copy)]
struct CpuMetrics {
    average_percent: f64,
    peak_percent: f64,
    samples: usize,
}

pub(super) async fn run_ping_check(name: &'static str, target: IpAddr, count: u8) -> QaCheckResult {
    match ping_target(target, count).await {
        Ok(metrics) => {
            let avg_rtt = metrics
                .avg_rtt_ms
                .map(|rtt| format!(", avg RTT {:.2} ms", rtt))
                .unwrap_or_default();
            pass_result(
                name,
                format!(
                    "{}/{} replies, {:.1}% loss{}",
                    metrics.received, metrics.transmitted, metrics.packet_loss_percent, avg_rtt
                ),
            )
        }
        Err(error) => fail_result(name, error.to_string()),
    }
}

pub(super) async fn run_dns_check(host: &str) -> QaCheckResult {
    match tokio::net::lookup_host((host, 443)).await {
        Ok(addresses) => {
            let resolved: Vec<String> = addresses.map(|address| address.ip().to_string()).collect();
            if resolved.is_empty() {
                fail_result("DNS resolution", format!("{host} resolved to no addresses"))
            } else {
                pass_result(
                    "DNS resolution",
                    format!("{host} -> {}", resolved.join(", ")),
                )
            }
        }
        Err(error) => fail_result(
            "DNS resolution",
            format!("failed to resolve {host}: {error}"),
        ),
    }
}

pub(super) async fn run_public_ip_check(url: &str) -> QaCheckResult {
    let client = match build_http_client(Duration::from_secs(10)) {
        Ok(client) => client,
        Err(error) => return fail_result("Public egress IP", error.to_string()),
    };
    match client.get(url).send().await {
        Ok(response) => match response.error_for_status() {
            Ok(response) => match response.text().await {
                Ok(body) => pass_result("Public egress IP", format!("{} -> {}", url, body.trim())),
                Err(error) => fail_result(
                    "Public egress IP",
                    format!("failed to read response body from {url}: {error}"),
                ),
            },
            Err(error) => fail_result("Public egress IP", format!("request failed: {error}")),
        },
        Err(error) => fail_result("Public egress IP", format!("request failed: {error}")),
    }
}

pub(super) async fn run_speedtest(
    override_url: Option<&str>,
    speedtest_bytes: usize,
    timeout_secs: u64,
    child_pid: u32,
) -> QaCheckResult {
    let speedtest_url = match build_speedtest_url(override_url, speedtest_bytes) {
        Ok(url) => url,
        Err(error) => return fail_result("Download throughput", error.to_string()),
    };
    let timeout_duration = Duration::from_secs(timeout_secs.max(1));
    let client = match build_http_client(timeout_duration) {
        Ok(client) => client,
        Err(error) => return fail_result("Download throughput", error.to_string()),
    };

    let (cpu_stop_tx, cpu_stop_rx) = watch::channel(false);
    let cpu_task = tokio::spawn(sample_process_cpu(child_pid, cpu_stop_rx));
    let speedtest_result = measure_download(&client, speedtest_url.clone(), timeout_duration).await;
    let _ = cpu_stop_tx.send(true);
    let cpu_metrics = cpu_task.await.ok().flatten();

    match speedtest_result {
        Ok(metrics) => {
            let cpu_note = cpu_metrics
                .map(|cpu| {
                    format!(
                        ", child CPU avg {:.1}% / peak {:.1}% ({} sample{})",
                        cpu.average_percent,
                        cpu.peak_percent,
                        cpu.samples,
                        if cpu.samples == 1 { "" } else { "s" }
                    )
                })
                .unwrap_or_default();
            pass_result(
                "Download throughput",
                format!(
                    "{} bytes in {:.2}s ({:.2} Mbps), TTFB {:.0} ms{} via {}",
                    metrics.bytes,
                    metrics.elapsed.as_secs_f64(),
                    metrics.throughput_mbps,
                    metrics.ttfb.as_secs_f64() * 1_000.0,
                    cpu_note,
                    speedtest_url,
                ),
            )
        }
        Err(error) => fail_result("Download throughput", error.to_string()),
    }
}

async fn ping_target(target: IpAddr, count: u8) -> Result<PingMetrics, Box<dyn std::error::Error>> {
    let mut command = if target.is_ipv6() && cfg!(target_os = "macos") {
        let mut command = Command::new("ping6");
        command.arg("-n");
        command
    } else {
        let mut command = Command::new("ping");
        if target.is_ipv6() {
            command.arg("-6");
        }
        command.arg("-n");
        command
    };
    command
        .arg("-c")
        .arg(count.to_string())
        .arg(target.to_string());
    let output = command.output().await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let detail = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            format!("{} {}", stdout.trim(), stderr.trim())
        };
        return Err(format!("ping failed: {detail}").into());
    }
    parse_ping_metrics(&stdout).ok_or_else(|| "unable to parse ping output".into())
}

fn parse_ping_metrics(output: &str) -> Option<PingMetrics> {
    let mut transmitted = None;
    let mut received = None;
    let mut packet_loss_percent = None;
    let mut avg_rtt_ms = None;

    for line in output.lines() {
        if line.contains("packet loss") {
            let parts: Vec<_> = line.split(',').map(str::trim).collect();
            if let Some(tx) = parts.first() {
                transmitted = tx.split_whitespace().next()?.parse().ok();
            }
            if let Some(rx) = parts.get(1) {
                received = rx.split_whitespace().next()?.parse().ok();
            }
            if let Some(loss_fragment) = parts.iter().find(|part| part.contains("packet loss")) {
                let loss = loss_fragment.split_whitespace().next()?;
                packet_loss_percent = loss.trim_end_matches('%').parse().ok();
            }
        }
        if line.contains("min/avg/max") && line.contains('=') {
            let stats = line.split('=').nth(1)?.trim();
            let first_token = stats.split_whitespace().next()?;
            let segments: Vec<_> = first_token.split('/').collect();
            avg_rtt_ms = segments.get(1).and_then(|value| value.parse().ok());
        }
    }

    Some(PingMetrics {
        transmitted: transmitted?,
        received: received?,
        packet_loss_percent: packet_loss_percent?,
        avg_rtt_ms,
    })
}

fn build_http_client(
    timeout_duration: Duration,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(timeout_duration)
        .build()?)
}

fn build_speedtest_url(
    override_url: Option<&str>,
    speedtest_bytes: usize,
) -> Result<Url, Box<dyn std::error::Error>> {
    if let Some(override_url) = override_url {
        return Ok(Url::parse(override_url)?);
    }
    let mut url = Url::parse(DEFAULT_SPEEDTEST_BASE_URL)?;
    url.query_pairs_mut()
        .append_pair("bytes", &speedtest_bytes.to_string());
    Ok(url)
}

async fn measure_download(
    client: &reqwest::Client,
    url: Url,
    timeout_duration: Duration,
) -> Result<DownloadMetrics, Box<dyn std::error::Error>> {
    let started = Instant::now();
    let response = timeout(timeout_duration, client.get(url).send()).await??;
    let response = response.error_for_status()?;
    let ttfb = started.elapsed();
    let mut response = response;
    let mut bytes = 0usize;
    while let Some(chunk) = timeout(timeout_duration, response.chunk()).await?? {
        bytes = bytes.saturating_add(chunk.len());
    }
    let elapsed = started.elapsed();
    let throughput_mbps = if elapsed.is_zero() {
        0.0
    } else {
        (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0
    };
    Ok(DownloadMetrics {
        bytes,
        elapsed,
        ttfb,
        throughput_mbps,
    })
}

async fn sample_process_cpu(pid: u32, mut stop_rx: watch::Receiver<bool>) -> Option<CpuMetrics> {
    let mut samples = Vec::new();
    loop {
        if *stop_rx.borrow() {
            break;
        }
        if let Some(sample) = read_process_cpu_percent(pid).await {
            samples.push(sample);
        }
        tokio::select! {
            _ = sleep(Duration::from_secs(1)) => {}
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
    if samples.is_empty() {
        return None;
    }
    let average_percent = samples.iter().sum::<f64>() / samples.len() as f64;
    let peak_percent = samples
        .iter()
        .copied()
        .fold(0.0_f64, |peak, sample| peak.max(sample));
    Some(CpuMetrics {
        average_percent,
        peak_percent,
        samples: samples.len(),
    })
}

async fn read_process_cpu_percent(pid: u32) -> Option<f64> {
    let output = Command::new("ps")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-o")
        .arg("%cpu=")
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_summary_formats() {
        let mac_output = r#"4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 11.295/12.175/13.238/0.756 ms
"#;
        let parsed = parse_ping_metrics(mac_output).expect("mac ping output should parse");
        assert_eq!(parsed.transmitted, 4);
        assert_eq!(parsed.received, 4);
        assert_eq!(parsed.packet_loss_percent, 0.0);
        assert_eq!(parsed.avg_rtt_ms, Some(12.175));

        let linux_output = r#"4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 11.295/12.175/13.238/0.756 ms
"#;
        let parsed = parse_ping_metrics(linux_output).expect("linux ping output should parse");
        assert_eq!(parsed.transmitted, 4);
        assert_eq!(parsed.received, 4);
        assert_eq!(parsed.packet_loss_percent, 0.0);
        assert_eq!(parsed.avg_rtt_ms, Some(12.175));
    }

    #[test]
    fn builds_default_speedtest_url_with_bytes_query() {
        let url = build_speedtest_url(None, 12_345).expect("default speedtest URL should build");
        assert_eq!(
            url.as_str(),
            "https://speed.cloudflare.com/__down?bytes=12345"
        );
    }
}
