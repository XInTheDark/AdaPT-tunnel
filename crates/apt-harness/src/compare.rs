use crate::trace::{H2BackendTrace, PassiveCapture, RetryTrace, TraceFamily};
use serde::{Deserialize, Serialize};

/// Passive mismatch summary between a subject capture and its baseline family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveDelta {
    pub baseline_family: TraceFamily,
    pub subject_family: TraceFamily,
    pub alpn_match: bool,
    pub request_delta: i32,
    pub response_delta: i32,
    pub concurrency_delta: i32,
    pub size_overlap_percent: u8,
    pub gap_overlap_percent: u8,
    pub error_mismatch_count: u16,
}

impl PassiveDelta {
    /// Returns true when the subject remains inside a coarse acceptable envelope.
    #[must_use]
    pub fn is_close_to_baseline(&self) -> bool {
        self.alpn_match
            && self.request_delta.abs() <= 2
            && self.response_delta.abs() <= 2
            && self.concurrency_delta.abs() <= 2
            && self.size_overlap_percent >= 60
            && self.gap_overlap_percent >= 60
            && self.error_mismatch_count == 0
    }
}

/// Coarse H2 semantic mismatch summary derived from richer backend traces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2SemanticDelta {
    pub baseline_family: TraceFamily,
    pub subject_family: TraceFamily,
    pub transport_security_match: bool,
    pub authority_match_percent: u8,
    pub method_match_percent: u8,
    pub path_match_percent: u8,
    pub status_mismatch_count: u16,
    pub request_header_name_overlap_percent: u8,
    pub response_header_name_overlap_percent: u8,
}

impl H2SemanticDelta {
    /// Returns true when the subject keeps the same broad H2 semantics as the baseline.
    #[must_use]
    pub fn is_close_to_baseline(&self) -> bool {
        self.authority_match_percent >= 75
            && self.method_match_percent >= 75
            && self.path_match_percent >= 75
            && self.status_mismatch_count == 0
            && self.request_header_name_overlap_percent >= 60
            && self.response_header_name_overlap_percent >= 60
    }

    /// Returns true when the semantic delta should surface as a warning even if the rest is close.
    #[must_use]
    pub fn has_warning_signal(&self) -> bool {
        !self.transport_security_match
    }
}

/// Retry-pattern assessment focused on deterministic ladders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryAssessment {
    pub attempts: usize,
    pub distinct_families: usize,
    pub deterministic_pattern: bool,
    pub successful_attempt_index: Option<usize>,
}

/// Compares two passive summaries using intentionally coarse first-cut metrics.
#[must_use]
pub fn compare_passive_capture(
    subject: &PassiveCapture,
    baseline: &PassiveCapture,
) -> PassiveDelta {
    PassiveDelta {
        baseline_family: baseline.family.clone(),
        subject_family: subject.family.clone(),
        alpn_match: subject.alpn == baseline.alpn,
        request_delta: i32::from(subject.request_count) - i32::from(baseline.request_count),
        response_delta: i32::from(subject.response_count) - i32::from(baseline.response_count),
        concurrency_delta: i32::from(subject.concurrency_peak)
            - i32::from(baseline.concurrency_peak),
        size_overlap_percent: overlap_percent(&subject.object_sizes, &baseline.object_sizes),
        gap_overlap_percent: overlap_percent(&subject.gap_ms, &baseline.gap_ms),
        error_mismatch_count: symmetric_difference_len(&subject.error_codes, &baseline.error_codes),
    }
}

/// Compares richer H2 backend traces using coarse authority/path/header/states heuristics.
#[must_use]
pub fn compare_h2_backend_trace(
    subject: &H2BackendTrace,
    baseline: &H2BackendTrace,
) -> H2SemanticDelta {
    let pair_count = subject.exchanges.len().max(baseline.exchanges.len()).max(1);
    let zipped = subject
        .exchanges
        .iter()
        .zip(&baseline.exchanges)
        .collect::<Vec<_>>();
    let authority_matches = zipped
        .iter()
        .filter(|(left, right)| left.authority == right.authority)
        .count();
    let method_matches = zipped
        .iter()
        .filter(|(left, right)| left.method == right.method)
        .count();
    let path_matches = zipped
        .iter()
        .filter(|(left, right)| left.path == right.path)
        .count();
    let status_mismatch_count = zipped
        .iter()
        .filter(|(left, right)| left.status != right.status)
        .count() as u16
        + subject.exchanges.len().abs_diff(baseline.exchanges.len()) as u16;
    H2SemanticDelta {
        baseline_family: baseline.family.clone(),
        subject_family: subject.family.clone(),
        transport_security_match: subject.transport_security == baseline.transport_security,
        authority_match_percent: match_percent(authority_matches, pair_count),
        method_match_percent: match_percent(method_matches, pair_count),
        path_match_percent: match_percent(path_matches, pair_count),
        status_mismatch_count,
        request_header_name_overlap_percent: set_overlap_percent(
            &subject
                .request_header_names()
                .into_iter()
                .collect::<Vec<_>>(),
            &baseline
                .request_header_names()
                .into_iter()
                .collect::<Vec<_>>(),
        ),
        response_header_name_overlap_percent: set_overlap_percent(
            &subject
                .response_header_names()
                .into_iter()
                .collect::<Vec<_>>(),
            &baseline
                .response_header_names()
                .into_iter()
                .collect::<Vec<_>>(),
        ),
    }
}

/// Determines whether the retry ladder is deterministic enough to be suspicious.
#[must_use]
pub fn assess_retry_pattern(trace: &RetryTrace) -> RetryAssessment {
    let successful_attempt_index = trace.attempts.iter().position(|attempt| attempt.success);
    let distinct_families = trace
        .attempts
        .iter()
        .map(|attempt| attempt.family.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let deterministic_pattern = trace.attempts.len() >= 3
        && trace
            .attempts
            .windows(2)
            .all(|pair| pair[0].delay_ms == pair[1].delay_ms);
    RetryAssessment {
        attempts: trace.attempts.len(),
        distinct_families,
        deterministic_pattern,
        successful_attempt_index,
    }
}

fn match_percent(matches: usize, total: usize) -> u8 {
    ((matches.saturating_mul(100)) / total.max(1)).min(100) as u8
}

fn overlap_percent(left: &[u32], right: &[u32]) -> u8 {
    if left.is_empty() || right.is_empty() {
        return 100;
    }
    let left_range = range(left);
    let right_range = range(right);
    if left_range.0 == left_range.1 && right_range.0 == right_range.1 {
        return scalar_closeness_percent(left_range.0, right_range.0);
    }
    let overlap_start = left_range.0.max(right_range.0);
    let overlap_end = left_range.1.min(right_range.1);
    if overlap_end < overlap_start {
        return 0;
    }
    let overlap = overlap_end - overlap_start;
    let union = left_range.1.max(right_range.1) - left_range.0.min(right_range.0);
    if union == 0 {
        100
    } else {
        ((overlap.saturating_mul(100)) / union).min(100) as u8
    }
}

fn scalar_closeness_percent(left: u32, right: u32) -> u8 {
    let max = left.max(right);
    if max == 0 {
        return 100;
    }
    let diff = left.abs_diff(right);
    100_u8.saturating_sub(((diff.saturating_mul(100)) / max).min(100) as u8)
}

fn set_overlap_percent<T>(left: &[T], right: &[T]) -> u8
where
    T: Ord + Clone,
{
    if left.is_empty() || right.is_empty() {
        return 100;
    }
    let left = left
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let right = right
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let intersection = left.intersection(&right).count();
    let union = left.union(&right).count();
    ((intersection.saturating_mul(100)) / union.max(1)).min(100) as u8
}

fn range(values: &[u32]) -> (u32, u32) {
    let min = *values.iter().min().unwrap_or(&0);
    let max = *values.iter().max().unwrap_or(&0);
    (min, max)
}

fn symmetric_difference_len(left: &[u16], right: &[u16]) -> u16 {
    let left = left
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let right = right
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    left.symmetric_difference(&right).count() as u16
}
