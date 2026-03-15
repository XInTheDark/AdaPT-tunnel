use serde::{Deserialize, Serialize};

/// Coarse baseline/subject family labels used by the first harness revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TraceFamily {
    BrowserH2,
    BrowserH3,
    AdaptLegacyD1,
    AdaptLegacyD2,
    AdaptLegacyS1,
    AdaptV2S1H2,
    AdaptV2D2H3,
}

impl TraceFamily {
    /// Returns a short stable identifier suitable for report rows.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BrowserH2 => "browser-h2",
            Self::BrowserH3 => "browser-h3",
            Self::AdaptLegacyD1 => "adapt-legacy-d1",
            Self::AdaptLegacyD2 => "adapt-legacy-d2",
            Self::AdaptLegacyS1 => "adapt-legacy-s1",
            Self::AdaptV2S1H2 => "adapt-v2-s1-h2",
            Self::AdaptV2D2H3 => "adapt-v2-d2-h3",
        }
    }
}

/// Passive wire-image summary distilled from a capture or qlog/pcap parser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveCapture {
    pub label: String,
    pub family: TraceFamily,
    pub alpn: String,
    pub request_count: u16,
    pub response_count: u16,
    pub concurrency_peak: u16,
    pub total_bytes: u64,
    #[serde(default)]
    pub object_sizes: Vec<u32>,
    #[serde(default)]
    pub gap_ms: Vec<u32>,
    #[serde(default)]
    pub error_codes: Vec<u16>,
}

/// Active-probe classification used by the regression harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProbeDisposition {
    HonestPublicSemantics,
    SilentDrop,
    DistinctiveFailure,
}

/// Result of one active probe class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveProbeResult {
    pub probe_name: String,
    pub expected: ProbeDisposition,
    pub observed: ProbeDisposition,
}

/// One retry attempt captured by the harness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryAttempt {
    pub family: TraceFamily,
    pub delay_ms: u32,
    pub success: bool,
}

/// Retry ladder trace for one session bootstrap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RetryTrace {
    #[serde(default)]
    pub attempts: Vec<RetryAttempt>,
}
