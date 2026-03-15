use crate::{
    cli::QaOptions,
    paths::{ensure_user_owned_override, resolve_client_bundle_path},
};
use std::fmt;

mod probes;
mod process;

use self::probes::{run_dns_check, run_ping_check, run_public_ip_check, run_speedtest};
use self::process::{connect_and_wait_for_established, disconnect_session, EstablishedSession};

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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bundle_path = resolve_client_bundle_path(options.launch.bundle.clone())?;
    let _ = ensure_user_owned_override(&bundle_path)?;
    println!("Using client bundle: {}", bundle_path.display());
    println!("Launching a temporary daemon-managed client session for QA...\n");

    let ready = match connect_and_wait_for_established(
        &options.launch,
        bundle_path,
        options.connect_timeout_secs,
    )
    .await
    {
        Ok(ready) => ready,
        Err(error) => {
            let _ = disconnect_session().await;
            return Err(error);
        }
    };

    println!();
    print_session_summary(&ready);

    let qa_result = execute_qa_suite(&ready, &options).await;
    let shutdown_result = disconnect_session().await;

    if let Err(error) = shutdown_result {
        eprintln!("warning: failed to shut down the test session cleanly: {error}");
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            "no server tunnel IPv6 was negotiated",
        ));
    }

    if options.skip_dns {
        results.push(skip_result("DNS resolution", "skipped by flag"));
    } else if ready.has_default_route() {
        results.push(run_dns_check(&options.dns_host).await);
    } else {
        results.push(skip_result(
            "DNS resolution",
            "active routes do not include a default route",
        ));
    }

    if options.skip_public_ip {
        results.push(skip_result("Public egress IP", "skipped by flag"));
    } else if ready.has_default_route() {
        results.push(run_public_ip_check(&options.public_ip_url).await);
    } else {
        results.push(skip_result(
            "Public egress IP",
            "active routes do not include a default route",
        ));
    }

    if options.skip_speedtest {
        results.push(skip_result("Download throughput", "skipped by flag"));
    } else if ready.has_default_route() || options.speedtest_url.is_some() {
        results.push(
            run_speedtest(
                options.speedtest_url.as_deref(),
                options.speedtest_bytes,
                options.speedtest_timeout_secs,
                ready.daemon_pid,
            )
            .await,
        );
    } else {
        results.push(skip_result(
            "Download throughput",
            "no default route is active and no explicit speedtest URL was supplied",
        ));
    }

    print_results(&results);

    if results
        .iter()
        .any(|result| result.outcome == QaOutcome::Fail)
    {
        return Err("one or more QA checks failed".into());
    }
    Ok(())
}

fn print_results(results: &[QaCheckResult]) {
    println!("QA results:");
    for result in results {
        println!("  [{}] {} — {}", result.outcome, result.name, result.detail);
    }
}
