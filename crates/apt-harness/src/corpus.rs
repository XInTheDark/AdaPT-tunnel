use crate::{
    assess_retry_pattern, build_h2_harness_report, build_harness_report, compare_h2_backend_trace,
    compare_passive_capture, ActiveProbeResult, H2BackendTrace, HarnessReport, PassiveCapture,
    RetryTrace,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Error returned when loading or evaluating harness fixture corpora.
#[derive(Debug, Error)]
pub enum HarnessFixtureError {
    #[error("failed to read harness fixture file `{path}`")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse harness fixture file `{path}`")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Supported on-disk capture formats for fixture corpora.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureFormat {
    #[default]
    PassiveSummary,
    H2BackendTrace,
}

/// One logical comparison row inside a fixture manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureEntry {
    pub name: String,
    pub baseline_capture: PathBuf,
    #[serde(default)]
    pub baseline_format: CaptureFormat,
    pub subject_capture: PathBuf,
    #[serde(default)]
    pub subject_format: CaptureFormat,
    pub probes: PathBuf,
    pub retry_trace: PathBuf,
}

/// A fixture manifest describing one or more harness comparison rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FixtureManifest {
    #[serde(default)]
    pub entries: Vec<FixtureEntry>,
}

/// Loaded + evaluated result for one fixture entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureEvaluation {
    pub name: String,
    pub report: HarnessReport,
}

/// Loads a JSON fixture manifest from disk.
pub fn load_fixture_manifest(
    path: impl AsRef<Path>,
) -> Result<FixtureManifest, HarnessFixtureError> {
    load_json_file(path.as_ref())
}

/// Evaluates every fixture entry in a manifest relative to the manifest's directory.
pub fn evaluate_fixture_manifest(
    manifest_path: impl AsRef<Path>,
) -> Result<Vec<FixtureEvaluation>, HarnessFixtureError> {
    let manifest_path = manifest_path.as_ref();
    let manifest = load_fixture_manifest(manifest_path)?;
    let root = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    manifest
        .entries
        .iter()
        .map(|entry| evaluate_fixture_entry(&root, entry))
        .collect()
}

fn evaluate_fixture_entry(
    root: &Path,
    entry: &FixtureEntry,
) -> Result<FixtureEvaluation, HarnessFixtureError> {
    let baseline = load_capture_file(&root.join(&entry.baseline_capture), entry.baseline_format)?;
    let subject = load_capture_file(&root.join(&entry.subject_capture), entry.subject_format)?;
    let probes: Vec<ActiveProbeResult> = load_json_file(&root.join(&entry.probes))?;
    let retry: RetryTrace = load_json_file(&root.join(&entry.retry_trace))?;
    let report = match (&baseline, &subject) {
        (LoadedCapture::H2Trace(baseline), LoadedCapture::H2Trace(subject)) => {
            let baseline_passive = baseline.to_passive_capture();
            let subject_passive = subject.to_passive_capture();
            build_h2_harness_report(
                compare_passive_capture(&subject_passive, &baseline_passive),
                Some(compare_h2_backend_trace(subject, baseline)),
                &probes,
                assess_retry_pattern(&retry),
            )
        }
        _ => build_harness_report(
            compare_passive_capture(
                &subject.to_passive_capture(),
                &baseline.to_passive_capture(),
            ),
            &probes,
            assess_retry_pattern(&retry),
        ),
    };
    Ok(FixtureEvaluation {
        name: entry.name.clone(),
        report,
    })
}

fn load_capture_file(
    path: &Path,
    format: CaptureFormat,
) -> Result<LoadedCapture, HarnessFixtureError> {
    match format {
        CaptureFormat::PassiveSummary => load_json_file(path).map(LoadedCapture::Passive),
        CaptureFormat::H2BackendTrace => load_json_file(path).map(LoadedCapture::H2Trace),
    }
}

fn load_json_file<T>(path: &Path) -> Result<T, HarnessFixtureError>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path).map_err(|source| HarnessFixtureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| HarnessFixtureError::Json {
        path: path.to_path_buf(),
        source,
    })
}

enum LoadedCapture {
    Passive(PassiveCapture),
    H2Trace(H2BackendTrace),
}

impl LoadedCapture {
    fn to_passive_capture(&self) -> PassiveCapture {
        match self {
            Self::Passive(capture) => capture.clone(),
            Self::H2Trace(trace) => trace.to_passive_capture(),
        }
    }
}
