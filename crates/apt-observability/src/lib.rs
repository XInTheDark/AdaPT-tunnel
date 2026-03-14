//! Privacy-aware logging, metrics, and tracing helpers.
//!
//! The crate keeps observability coarse by default: enough to debug deployments,
//! but not enough to recreate a fingerprint of user traffic.

use apt_types::{CarrierBinding, CredentialIdentity, PathProfile, PolicyMode, SessionId};
use serde::{Deserialize, Serialize};
use tracing::{info, info_span};
use tracing_subscriber::{fmt, EnvFilter};

/// Coarse observability configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Logical service name used in tracing output.
    pub service_name: String,
    /// Whether debug output is allowed.
    pub debug: bool,
    /// Whether to include coarse path metadata.
    pub include_path_profile: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "adapt-tunnel".to_string(),
            debug: false,
            include_path_profile: true,
        }
    }
}

/// Privacy-safe structured events.
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AptEvent {
    /// Admission was accepted.
    AdmissionAccepted {
        session_id: SessionId,
        carrier: CarrierBinding,
        credential_identity: String,
    },
    /// Admission was rejected quietly.
    AdmissionRejected {
        carrier: CarrierBinding,
        reason: &'static str,
    },
    /// Tunnel session established.
    TunnelEstablished {
        session_id: SessionId,
        carrier: CarrierBinding,
        mode: PolicyMode,
    },
    /// Policy mode changed.
    PolicyModeChanged {
        session_id: SessionId,
        mode: PolicyMode,
    },
}

/// Minimal telemetry snapshot for UIs and CLIs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Service name.
    pub service_name: String,
    /// Count of accepted admissions.
    pub accepted_admissions: u64,
    /// Count of rejected admissions.
    pub rejected_admissions: u64,
    /// Count of established sessions.
    pub established_sessions: u64,
}

impl TelemetrySnapshot {
    /// Creates a new empty snapshot.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            accepted_admissions: 0,
            rejected_admissions: 0,
            established_sessions: 0,
        }
    }

    /// Applies a structured event.
    pub fn apply(&mut self, event: &AptEvent) {
        match event {
            AptEvent::AdmissionAccepted { .. } => self.accepted_admissions += 1,
            AptEvent::AdmissionRejected { .. } => self.rejected_admissions += 1,
            AptEvent::TunnelEstablished { .. } => self.established_sessions += 1,
            AptEvent::PolicyModeChanged { .. } => {}
        }
    }
}

/// Initializes tracing once for CLI/demo binaries.
pub fn init_tracing(config: &ObservabilityConfig) {
    let filter = if config.debug { "debug" } else { "info" };
    let _ = fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .compact()
        .try_init();
}

/// Logs one coarse event and updates the snapshot.
pub fn record_event(
    snapshot: &mut TelemetrySnapshot,
    event: &AptEvent,
    path_profile: Option<&PathProfile>,
    config: &ObservabilityConfig,
) {
    snapshot.apply(event);
    let _span = info_span!("apt_event", service = %config.service_name).entered();
    match event {
        AptEvent::AdmissionAccepted {
            session_id,
            carrier,
            credential_identity,
        } => {
            info!(session = %session_id, carrier = %carrier.as_str(), credential = %credential_identity, "admission accepted");
        }
        AptEvent::AdmissionRejected { carrier, reason } => {
            info!(carrier = %carrier.as_str(), reason = *reason, "admission rejected");
        }
        AptEvent::TunnelEstablished {
            session_id,
            carrier,
            mode,
        } => {
            if config.include_path_profile {
                info!(session = %session_id, carrier = %carrier.as_str(), mode = ?mode, path = ?path_profile, "tunnel established");
            } else {
                info!(session = %session_id, carrier = %carrier.as_str(), mode = ?mode, "tunnel established");
            }
        }
        AptEvent::PolicyModeChanged { session_id, mode } => {
            info!(session = %session_id, mode = ?mode, "policy mode changed");
        }
    }
}

/// Converts a credential identity into a privacy-safe label.
#[must_use]
pub fn redact_credential(identity: &CredentialIdentity) -> String {
    match identity {
        CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
        CredentialIdentity::User(user) => {
            format!("user:{}", &user.chars().take(6).collect::<String>())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_types::CredentialIdentity;

    #[test]
    fn snapshot_counts_events() {
        let mut snapshot = TelemetrySnapshot::new("svc");
        snapshot.apply(&AptEvent::AdmissionRejected {
            carrier: CarrierBinding::D1DatagramUdp,
            reason: "drop",
        });
        snapshot.apply(&AptEvent::TunnelEstablished {
            session_id: SessionId([1_u8; 16]),
            carrier: CarrierBinding::D1DatagramUdp,
            mode: PolicyMode::Balanced,
        });
        assert_eq!(snapshot.rejected_admissions, 1);
        assert_eq!(snapshot.established_sessions, 1);
    }

    #[test]
    fn credential_redaction_is_coarse() {
        assert_eq!(
            redact_credential(&CredentialIdentity::SharedDeployment),
            "shared-deployment"
        );
        assert_eq!(
            redact_credential(&CredentialIdentity::User("abcdefgh".to_string())),
            "user:abcdef"
        );
    }
}
