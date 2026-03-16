use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

/// Whether the observed H2 session was cleartext lab traffic or a TLS-backed origin-facing session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum H2TransportSecurity {
    Cleartext,
    Tls,
}

/// One observed request/response header field inside an H2 exchange trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2HeaderField {
    pub name: String,
    pub value: String,
}

/// One coarse request/response exchange summary from an H2 backend trace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2Exchange {
    pub stream_id: u32,
    pub authority: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub request_headers: Vec<H2HeaderField>,
    #[serde(default)]
    pub response_headers: Vec<H2HeaderField>,
    pub status: u16,
    pub request_body_bytes: u32,
    pub response_body_bytes: u32,
    pub start_ms: u32,
    pub end_ms: u32,
}

/// Richer H2 session trace suitable for deriving passive summaries and coarse browser-vs-AdaPT comparisons.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2BackendTrace {
    pub label: String,
    pub family: TraceFamily,
    pub transport_security: H2TransportSecurity,
    #[serde(default = "default_h2_alpn")]
    pub alpn: String,
    #[serde(default)]
    pub exchanges: Vec<H2Exchange>,
    #[serde(default)]
    pub error_codes: Vec<u16>,
}

impl H2BackendTrace {
    /// Derives a coarse passive summary from a richer H2 exchange trace.
    #[must_use]
    pub fn to_passive_capture(&self) -> PassiveCapture {
        let mut starts = self
            .exchanges
            .iter()
            .map(|exchange| exchange.start_ms)
            .collect::<Vec<_>>();
        starts.sort_unstable();
        let gap_ms = starts.windows(2).map(|pair| pair[1] - pair[0]).collect();
        PassiveCapture {
            label: self.label.clone(),
            family: self.family.clone(),
            alpn: self.alpn.clone(),
            request_count: self.exchanges.len() as u16,
            response_count: self.exchanges.len() as u16,
            concurrency_peak: concurrency_peak(&self.exchanges),
            total_bytes: self
                .exchanges
                .iter()
                .map(estimated_exchange_bytes)
                .sum::<u64>(),
            object_sizes: self
                .exchanges
                .iter()
                .map(|exchange| exchange.response_body_bytes)
                .collect(),
            gap_ms,
            error_codes: self.error_codes.clone(),
        }
    }

    /// Returns the flattened set of request header names observed in the trace.
    #[must_use]
    pub fn request_header_names(&self) -> BTreeSet<&str> {
        self.exchanges
            .iter()
            .flat_map(|exchange| {
                exchange
                    .request_headers
                    .iter()
                    .map(|header| header.name.as_str())
            })
            .collect()
    }

    /// Returns the flattened set of response header names observed in the trace.
    #[must_use]
    pub fn response_header_names(&self) -> BTreeSet<&str> {
        self.exchanges
            .iter()
            .flat_map(|exchange| {
                exchange
                    .response_headers
                    .iter()
                    .map(|header| header.name.as_str())
            })
            .collect()
    }
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

fn default_h2_alpn() -> String {
    "h2".to_string()
}

fn concurrency_peak(exchanges: &[H2Exchange]) -> u16 {
    let mut peak = 0_usize;
    for exchange in exchanges {
        let concurrent = exchanges
            .iter()
            .filter(|candidate| {
                candidate.start_ms <= exchange.start_ms && candidate.end_ms >= exchange.start_ms
            })
            .count();
        peak = peak.max(concurrent);
    }
    peak as u16
}

fn estimated_exchange_bytes(exchange: &H2Exchange) -> u64 {
    let request_headers = exchange
        .request_headers
        .iter()
        .map(|header| (header.name.len() + header.value.len()) as u64)
        .sum::<u64>();
    let response_headers = exchange
        .response_headers
        .iter()
        .map(|header| (header.name.len() + header.value.len()) as u64)
        .sum::<u64>();
    request_headers
        + response_headers
        + u64::from(exchange.request_body_bytes)
        + u64::from(exchange.response_body_bytes)
        + exchange.method.len() as u64
        + exchange.path.len() as u64
        + exchange.authority.len() as u64
}
