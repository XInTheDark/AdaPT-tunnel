use crate::{
    compare::{H2SemanticDelta, PassiveDelta, RetryAssessment},
    trace::{ActiveProbeResult, ProbeDisposition},
};
use serde::{Deserialize, Serialize};

/// Coarse pass/warn/fail result used by the first harness version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessVerdict {
    Pass,
    Warn,
    Fail,
}

/// Probe rollup used in reports and tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub total: usize,
    pub honest: usize,
    pub silent: usize,
    pub distinctive: usize,
}

/// First-cut harness report joining passive/probe/retry assessments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessReport {
    pub passive: PassiveDelta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_semantics: Option<H2SemanticDelta>,
    pub probes: ProbeSummary,
    pub retry: RetryAssessment,
    pub verdict: HarnessVerdict,
}

/// Builds one harness report from passive/probe/retry assessments only.
#[must_use]
pub fn build_harness_report(
    passive: PassiveDelta,
    probes: &[ActiveProbeResult],
    retry: RetryAssessment,
) -> HarnessReport {
    build_h2_harness_report(passive, None, probes, retry)
}

/// Builds one harness report from passive/probe/retry assessments plus richer H2 semantics.
#[must_use]
pub fn build_h2_harness_report(
    passive: PassiveDelta,
    h2_semantics: Option<H2SemanticDelta>,
    probes: &[ActiveProbeResult],
    retry: RetryAssessment,
) -> HarnessReport {
    let probes = summarize_probes(probes);
    let semantics_fail = h2_semantics
        .as_ref()
        .is_some_and(|semantics| !semantics.is_close_to_baseline());
    let semantics_warn = h2_semantics
        .as_ref()
        .is_some_and(H2SemanticDelta::has_warning_signal);
    let verdict = if !passive.is_close_to_baseline() || semantics_fail || probes.distinctive > 0 {
        HarnessVerdict::Fail
    } else if retry.deterministic_pattern || probes.silent > 0 || semantics_warn {
        HarnessVerdict::Warn
    } else {
        HarnessVerdict::Pass
    };
    HarnessReport {
        passive,
        h2_semantics,
        probes,
        retry,
        verdict,
    }
}

fn summarize_probes(probes: &[ActiveProbeResult]) -> ProbeSummary {
    let honest = probes
        .iter()
        .filter(|probe| matches!(probe.observed, ProbeDisposition::HonestPublicSemantics))
        .count();
    let silent = probes
        .iter()
        .filter(|probe| matches!(probe.observed, ProbeDisposition::SilentDrop))
        .count();
    let distinctive = probes
        .iter()
        .filter(|probe| matches!(probe.observed, ProbeDisposition::DistinctiveFailure))
        .count();
    ProbeSummary {
        total: probes.len(),
        honest,
        silent,
        distinctive,
    }
}
