//! Empirical harness primitives for AdaPT passive/probe/retry regression work.
//!
//! The initial harness focuses on repository-local analysis helpers so future
//! carriers can be measured against browser/public-service baselines without
//! baking comparison logic into the runtime itself.
#![allow(missing_docs)]

mod compare;
mod corpus;
mod report;
mod trace;

pub use compare::{
    assess_retry_pattern, compare_h2_backend_trace, compare_passive_capture, H2SemanticDelta,
    PassiveDelta, RetryAssessment,
};
pub use corpus::{
    evaluate_fixture_manifest, load_fixture_manifest, CaptureFormat, FixtureEntry,
    FixtureEvaluation, FixtureManifest, HarnessFixtureError,
};
pub use report::{
    build_h2_harness_report, build_harness_report, HarnessReport, HarnessVerdict, ProbeSummary,
};
pub use trace::{
    ActiveProbeResult, H2BackendTrace, H2Exchange, H2HeaderField, H2TransportSecurity,
    PassiveCapture, ProbeDisposition, RetryAttempt, RetryTrace, TraceFamily,
};

#[cfg(test)]
mod tests;
