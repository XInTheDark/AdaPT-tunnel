use super::*;
use std::path::PathBuf;

fn browser_h2_baseline() -> PassiveCapture {
    PassiveCapture {
        label: "browser-h2-baseline".to_string(),
        family: TraceFamily::BrowserH2,
        alpn: "h2".to_string(),
        request_count: 4,
        response_count: 4,
        concurrency_peak: 2,
        total_bytes: 3_200,
        object_sizes: vec![120, 240, 900, 1_100],
        gap_ms: vec![12, 18, 25, 33],
        error_codes: vec![],
    }
}

fn browser_h2_trace() -> H2BackendTrace {
    H2BackendTrace {
        label: "browser-h2-trace".to_string(),
        family: TraceFamily::BrowserH2,
        transport_security: H2TransportSecurity::Tls,
        alpn: "h2".to_string(),
        exchanges: vec![
            H2Exchange {
                stream_id: 1,
                authority: "api.example.com".to_string(),
                method: "POST".to_string(),
                path: "/v1/devices/device-1/sync".to_string(),
                request_headers: vec![
                    H2HeaderField {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    },
                    H2HeaderField {
                        name: "x-client-version".to_string(),
                        value: "browser-2026.03".to_string(),
                    },
                ],
                response_headers: vec![
                    H2HeaderField {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    },
                    H2HeaderField {
                        name: "cache-control".to_string(),
                        value: "no-store".to_string(),
                    },
                ],
                status: 200,
                request_body_bytes: 192,
                response_body_bytes: 256,
                start_ms: 0,
                end_ms: 14,
            },
            H2Exchange {
                stream_id: 3,
                authority: "api.example.com".to_string(),
                method: "POST".to_string(),
                path: "/v1/devices/device-1/sync".to_string(),
                request_headers: vec![
                    H2HeaderField {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    },
                    H2HeaderField {
                        name: "x-client-version".to_string(),
                        value: "browser-2026.03".to_string(),
                    },
                ],
                response_headers: vec![
                    H2HeaderField {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    },
                    H2HeaderField {
                        name: "cache-control".to_string(),
                        value: "no-store".to_string(),
                    },
                ],
                status: 200,
                request_body_bytes: 208,
                response_body_bytes: 272,
                start_ms: 12,
                end_ms: 28,
            },
        ],
        error_codes: vec![],
    }
}

#[test]
fn passive_delta_flags_large_mismatch() {
    let baseline = browser_h2_baseline();
    let subject = PassiveCapture {
        label: "legacy-s1".to_string(),
        family: TraceFamily::AdaptLegacyS1,
        alpn: "tcp".to_string(),
        request_count: 1,
        response_count: 1,
        concurrency_peak: 1,
        total_bytes: 900,
        object_sizes: vec![16_384],
        gap_ms: vec![1],
        error_codes: vec![400],
    };
    let delta = compare_passive_capture(&subject, &baseline);
    assert!(!delta.is_close_to_baseline());
    assert!(!delta.alpn_match);
    assert_eq!(delta.error_mismatch_count, 1);
}

#[test]
fn h2_trace_summary_derives_passive_capture() {
    let trace = browser_h2_trace();
    let capture = trace.to_passive_capture();

    assert_eq!(capture.family, TraceFamily::BrowserH2);
    assert_eq!(capture.alpn, "h2");
    assert_eq!(capture.request_count, 2);
    assert_eq!(capture.response_count, 2);
    assert_eq!(capture.concurrency_peak, 2);
    assert_eq!(capture.object_sizes, vec![256, 272]);
    assert_eq!(capture.gap_ms, vec![12]);
    assert!(capture.total_bytes > 0);
}

#[test]
fn h2_semantic_delta_warns_on_cleartext_lab_shape() {
    let baseline = browser_h2_trace();
    let mut subject = baseline.clone();
    subject.label = "adapt-v2-h2c-trace".to_string();
    subject.family = TraceFamily::AdaptV2S1H2;
    subject.transport_security = H2TransportSecurity::Cleartext;

    let delta = compare_h2_backend_trace(&subject, &baseline);

    assert!(delta.is_close_to_baseline());
    assert!(delta.has_warning_signal());
    assert!(!delta.transport_security_match);
}

#[test]
fn retry_assessment_detects_deterministic_ladder() {
    let assessment = assess_retry_pattern(&RetryTrace {
        attempts: vec![
            RetryAttempt {
                family: TraceFamily::AdaptLegacyD1,
                delay_ms: 250,
                success: false,
            },
            RetryAttempt {
                family: TraceFamily::AdaptLegacyD2,
                delay_ms: 250,
                success: false,
            },
            RetryAttempt {
                family: TraceFamily::AdaptLegacyS1,
                delay_ms: 250,
                success: true,
            },
        ],
    });
    assert!(assessment.deterministic_pattern);
    assert_eq!(assessment.successful_attempt_index, Some(2));
}

#[test]
fn harness_report_passes_close_public_session() {
    let baseline = browser_h2_baseline();
    let subject = PassiveCapture {
        label: "adapt-v2-h2".to_string(),
        family: TraceFamily::AdaptV2S1H2,
        alpn: "h2".to_string(),
        request_count: 4,
        response_count: 4,
        concurrency_peak: 2,
        total_bytes: 3_000,
        object_sizes: vec![140, 260, 880, 1_080],
        gap_ms: vec![14, 20, 24, 35],
        error_codes: vec![],
    };
    let report = build_harness_report(
        compare_passive_capture(&subject, &baseline),
        &[ActiveProbeResult {
            probe_name: "semi-valid-upgrade".to_string(),
            expected: ProbeDisposition::HonestPublicSemantics,
            observed: ProbeDisposition::HonestPublicSemantics,
        }],
        assess_retry_pattern(&RetryTrace {
            attempts: vec![RetryAttempt {
                family: TraceFamily::AdaptV2S1H2,
                delay_ms: 350,
                success: true,
            }],
        }),
    );
    assert_eq!(report.verdict, HarnessVerdict::Pass);
    assert_eq!(report.probes.honest, 1);
    assert!(report.h2_semantics.is_none());
}

#[test]
fn harness_report_warns_on_cleartext_h2_lab_trace() {
    let baseline = browser_h2_trace();
    let mut subject = baseline.clone();
    subject.label = "adapt-v2-h2c-trace".to_string();
    subject.family = TraceFamily::AdaptV2S1H2;
    subject.transport_security = H2TransportSecurity::Cleartext;

    let report = build_h2_harness_report(
        compare_passive_capture(
            &subject.to_passive_capture(),
            &baseline.to_passive_capture(),
        ),
        Some(compare_h2_backend_trace(&subject, &baseline)),
        &[ActiveProbeResult {
            probe_name: "semi-valid-upgrade".to_string(),
            expected: ProbeDisposition::HonestPublicSemantics,
            observed: ProbeDisposition::HonestPublicSemantics,
        }],
        assess_retry_pattern(&RetryTrace {
            attempts: vec![RetryAttempt {
                family: TraceFamily::AdaptV2S1H2,
                delay_ms: 350,
                success: true,
            }],
        }),
    );

    assert_eq!(report.verdict, HarnessVerdict::Warn);
    assert!(report.h2_semantics.is_some());
}

#[test]
fn fixture_manifest_loads_and_evaluates_repo_samples() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("manifest.json");
    let manifest = load_fixture_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.entries.len(), 3);
    let evaluations = evaluate_fixture_manifest(&manifest_path).unwrap();
    assert_eq!(evaluations.len(), 3);
    assert_eq!(evaluations[0].name, "browser-h2-vs-adapt-v2-h2");
    assert_eq!(evaluations[0].report.verdict, HarnessVerdict::Pass);
    assert_eq!(evaluations[1].report.verdict, HarnessVerdict::Warn);
    assert_eq!(evaluations[2].report.verdict, HarnessVerdict::Pass);
    assert!(evaluations[1].report.h2_semantics.is_some());
    assert!(evaluations[2].report.h2_semantics.is_some());
}
