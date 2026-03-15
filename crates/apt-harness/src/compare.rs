use crate::trace::{PassiveCapture, RetryTrace, TraceFamily};
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

fn overlap_percent(left: &[u32], right: &[u32]) -> u8 {
    if left.is_empty() || right.is_empty() {
        return 100;
    }
    let left_range = range(left);
    let right_range = range(right);
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
