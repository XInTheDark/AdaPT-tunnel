//! Empirical harness primitives for AdaPT passive/probe/retry regression work.
//!
//! The initial harness focuses on repository-local analysis helpers so future
//! carriers can be measured against browser/public-service baselines without
//! baking comparison logic into the runtime itself.
#![allow(missing_docs)]

mod compare;
mod report;
mod trace;

pub use compare::{assess_retry_pattern, compare_passive_capture, PassiveDelta, RetryAssessment};
pub use report::{build_harness_report, HarnessReport, HarnessVerdict, ProbeSummary};
pub use trace::{
    ActiveProbeResult, PassiveCapture, ProbeDisposition, RetryAttempt, RetryTrace, TraceFamily,
};

#[cfg(test)]
mod tests;
