use super::{find_client_bundle, prompt_bundle_path, CliCarrier};
use clap::Args;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

mod probes;
mod process;

use self::probes::{run_dns_check, run_ping_check, run_public_ip_check, run_speedtest};
use self::process::{
    drain_client_output, shutdown_client_process, spawn_client_up_process,
    wait_for_established_session,
};

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 20;
const DEFAULT_PING_COUNT: u8 = 4;
const DEFAULT_DNS_HOST: &str = "example.com";
const DEFAULT_PUBLIC_IP_URL: &str = "https://api.ipify.org";
const DEFAULT_SPEEDTEST_BYTES: usize = 25_000_000;
const DEFAULT_SPEEDTEST_TIMEOUT_SECS: u64 = 45;

#[derive(Debug, Clone, Args)]
pub(super) struct QaOptions {
    /// Path to the client bundle file. If omitted, common default locations are searched.
    #[arg(long)]
    pub bundle: Option<PathBuf>,
    /// Override the numeric mode for this test run only (0 = speed, 100 = stealth).
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub mode: Option<u8>,
    /// Override the preferred carrier for this test run only.
    #[arg(long, value_enum)]
    pub carrier: Option<CliCarrier>,
    /// Seconds to wait for `apt-client up` to establish the tunnel before failing.
    #[arg(long, default_value_t = DEFAULT_CONNECT_TIMEOUT_SECS)]
    pub connect_timeout_secs: u64,
    /// Number of ICMP echo requests to send for each tunnel ping probe.
    #[arg(long, default_value_t = DEFAULT_PING_COUNT)]
    pub ping_count: u8,
    /// Hostname to resolve during the DNS check.
    #[arg(long, default_value = DEFAULT_DNS_HOST)]
    pub dns_host: String,
    /// URL used for the public egress-IP check when full-tunnel routing is active.
    #[arg(long, default_value = DEFAULT_PUBLIC_IP_URL)]
    pub public_ip_url: String,
    /// Optional override URL for the throughput/speed test.
    #[arg(long)]
    pub speedtest_url: Option<String>,
    /// Byte target for the default download throughput test endpoint.
    #[arg(long, default_value_t = DEFAULT_SPEEDTEST_BYTES)]
    pub speedtest_bytes: usize,
    /// Timeout for the download throughput test.
    #[arg(long, default_value_t = DEFAULT_SPEEDTEST_TIMEOUT_SECS)]
    pub speedtest_timeout_secs: u64,
    /// Skip the DNS lookup test.
    #[arg(long, default_value_t = false)]
    pub skip_dns: bool,
    /// Skip the public egress-IP check.
    #[arg(long, default_value_t = false)]
    pub skip_public_ip: bool,
    /// Skip the download throughput test.
    #[arg(long, default_value_t = false)]
    pub skip_speedtest: bool,
}

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
}

impl EstablishedSession {
    pub(super) fn has_default_route(&self) -> bool {
        self.routes
            .iter()
            .any(|route| route == "0.0.0.0/0" || route == "::/0")
    }
}

#[derive(Debug, Clone)]
pub(super) struct QaCheckResult {
    pub name: &'static str,
    pub outcome: QaOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QaOutcome {
    Pass,
    Fail,
    Skip,
}

impl fmt::Display for QaOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Skip => write!(f, "SKIP"),
        }
    }
}

pub(super) fn pass_result(name: &'static str, detail: String) -> QaCheckResult {
    QaCheckResult {
        name,
        outcome: QaOutcome::Pass,
        detail,
    }
}

pub(super) fn fail_result(name: &'static str, detail: String) -> QaCheckResult {
    QaCheckResult {
        name,
        outcome: QaOutcome::Fail,
        detail,
    }
}

pub(super) fn skip_result(name: &'static str, detail: impl Into<String>) -> QaCheckResult {
    QaCheckResult {
        name,
        outcome: QaOutcome::Skip,
        detail: detail.into(),
    }
}

pub(super) async fn run_targeted_tests(
    options: QaOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = match options.bundle.clone() {
        Some(path) => path,
        None => find_client_bundle().unwrap_or(prompt_bundle_path()?),
    };
    println!("Using client bundle: {}", bundle_path.display());
    println!("Launching a temporary client session for QA...\n");

    let mut child = spawn_client_up_process(&bundle_path, options.mode, options.carrier)?;
    let ready = match wait_for_established_session(&mut child, options.connect_timeout_secs).await {
        Ok(ready) => ready,
        Err(error) => {
            shutdown_client_process(&mut child).await.ok();
            return Err(error);
        }
    };

    println!();
    print_session_summary(&ready);

    let line_forwarder = tokio::spawn(drain_client_output(
        child
            .lines_rx
            .take()
            .expect("child output receiver should exist after readiness"),
    ));
    let qa_result = execute_qa_suite(&ready, &options, child.pid).await;
    let shutdown_result = shutdown_client_process(&mut child).await;
    line_forwarder.await.ok();

    if let Err(error) = shutdown_result {
        eprintln!("warning: failed to shut down test client cleanly: {error}");
    }

    qa_result
}

fn print_session_summary(ready: &EstablishedSession) {
    println!("Session established for QA:");
    println!("  server: {}", ready.server);
    println!("  interface: {}", ready.interface_name);
    println!("  carrier: {}", ready.carrier);
    println!("  negotiated mode: {}", ready.negotiated_mode);
    println!("  client tunnel IPv4: {}", ready.tunnel_ipv4);
    println!("  server tunnel IPv4: {}", ready.server_tunnel_ipv4);
    if let Some(ipv6) = ready.tunnel_ipv6 {
        println!("  client tunnel IPv6: {ipv6}");
    }
    if let Some(ipv6) = ready.server_tunnel_ipv6 {
        println!("  server tunnel IPv6: {ipv6}");
    }
    if ready.routes.is_empty() {
        println!("  routes: []");
    } else {
        println!("  routes: {}", ready.routes.join(", "));
    }
    println!();
}

async fn execute_qa_suite(
    ready: &EstablishedSession,
    options: &QaOptions,
    child_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    results.push(
        run_ping_check(
            "Tunnel IPv4 ping",
            ready.server_tunnel_ipv4.into(),
            options.ping_count,
        )
        .await,
    );

    if let Some(server_tunnel_ipv6) = ready.server_tunnel_ipv6 {
        results.push(
            run_ping_check(
                "Tunnel IPv6 ping",
                server_tunnel_ipv6.into(),
                options.ping_count,
            )
            .await,
        );
    } else {
        results.push(skip_result(
            "Tunnel IPv6 ping",
            "server did not advertise an IPv6 tunnel address",
        ));
    }

    let can_run_public_checks = ready.has_default_route();
    if !options.skip_dns {
        if can_run_public_checks {
            results.push(run_dns_check(&options.dns_host).await);
        } else {
            results.push(skip_result(
                "DNS resolution",
                "no default tunnel route detected; skipping internet-facing DNS QA",
            ));
        }
    }

    if !options.skip_public_ip {
        if can_run_public_checks {
            results.push(run_public_ip_check(&options.public_ip_url).await);
        } else {
            results.push(skip_result(
                "Public egress IP",
                "no default tunnel route detected; skipping public egress-IP check",
            ));
        }
    }

    if !options.skip_speedtest {
        if can_run_public_checks || options.speedtest_url.is_some() {
            results.push(
                run_speedtest(
                    options.speedtest_url.as_deref(),
                    options.speedtest_bytes,
                    options.speedtest_timeout_secs,
                    child_pid,
                )
                .await,
            );
        } else {
            results.push(skip_result(
                "Download throughput",
                "no default tunnel route detected and no explicit --speedtest-url was provided",
            ));
        }
    }

    print_results(&results);
    let failed = results
        .iter()
        .filter(|result| matches!(result.outcome, QaOutcome::Fail))
        .count();
    if failed > 0 {
        return Err(format!("{} QA check(s) failed", failed).into());
    }
    Ok(())
}

fn print_results(results: &[QaCheckResult]) {
    println!("\nQA results:");
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    for result in results {
        match result.outcome {
            QaOutcome::Pass => passed += 1,
            QaOutcome::Fail => failed += 1,
            QaOutcome::Skip => skipped += 1,
        }
        println!("  [{}] {} — {}", result.outcome, result.name, result.detail);
    }
    println!("\nSummary: {passed} passed, {failed} failed, {skipped} skipped");
}
