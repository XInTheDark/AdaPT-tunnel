use crate::{
    compare::{PassiveDelta, RetryAssessment},
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
    pub probes: ProbeSummary,
    pub retry: RetryAssessment,
    pub verdict: HarnessVerdict,
}

/// Builds one harness report from the three currently-supported comparison axes.
#[must_use]
pub fn build_harness_report(
    passive: PassiveDelta,
    probes: &[ActiveProbeResult],
    retry: RetryAssessment,
) -> HarnessReport {
    let probes = summarize_probes(probes);
    let verdict = if !passive.is_close_to_baseline() || probes.distinctive > 0 {
        HarnessVerdict::Fail
    } else if retry.deterministic_pattern || probes.silent > 0 {
        HarnessVerdict::Warn
    } else {
        HarnessVerdict::Pass
    };
    HarnessReport {
        passive,
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
