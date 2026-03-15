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
}

#[test]
fn fixture_manifest_loads_and_evaluates_repo_samples() {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("manifest.json");
    let manifest = load_fixture_manifest(&manifest_path).unwrap();
    assert_eq!(manifest.entries.len(), 1);
    let evaluations = evaluate_fixture_manifest(&manifest_path).unwrap();
    assert_eq!(evaluations.len(), 1);
    assert_eq!(evaluations[0].name, "browser-h2-vs-adapt-v2-h2");
    assert_eq!(evaluations[0].report.verdict, HarnessVerdict::Pass);
}
