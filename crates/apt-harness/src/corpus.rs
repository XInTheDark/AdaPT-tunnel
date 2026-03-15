use crate::{
    assess_retry_pattern, build_harness_report, compare_passive_capture, ActiveProbeResult,
    HarnessReport, PassiveCapture, RetryTrace,
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

/// One logical comparison row inside a fixture manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureEntry {
    pub name: String,
    pub baseline_capture: PathBuf,
    pub subject_capture: PathBuf,
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
    let baseline: PassiveCapture = load_json_file(&root.join(&entry.baseline_capture))?;
    let subject: PassiveCapture = load_json_file(&root.join(&entry.subject_capture))?;
    let probes: Vec<ActiveProbeResult> = load_json_file(&root.join(&entry.probes))?;
    let retry: RetryTrace = load_json_file(&root.join(&entry.retry_trace))?;
    Ok(FixtureEvaluation {
        name: entry.name.clone(),
        report: build_harness_report(
            compare_passive_capture(&subject, &baseline),
            &probes,
            assess_retry_pattern(&retry),
        ),
    })
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
