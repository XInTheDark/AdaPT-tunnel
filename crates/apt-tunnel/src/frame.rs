use crate::TunnelError;
use apt_types::CloseCode;
use serde::{Deserialize, Serialize};

/// High-level tunnel frames after decryption.
#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// A full IPv4 or IPv6 packet.
    IpData(Vec<u8>),
    /// Acknowledgement for a reliable control frame.
    CtrlAck { acked_control_id: u64 },
    /// Path ownership challenge.
    PathChallenge { control_id: u64, challenge: [u8; 8] },
    /// Path ownership response.
    PathResponse { control_id: u64, challenge: [u8; 8] },
    /// Rekey contribution.
    SessionUpdate {
        /// Reliable control identifier.
        control_id: u64,
        /// The phase to activate once the update is acknowledged.
        next_phase: u8,
        /// Fresh contribution mixed into the next phase derivation.
        contribution: [u8; 32],
        /// UNIX timestamp when the update was issued.
        issued_at_secs: u64,
    },
    /// Best-effort liveness probe.
    Ping,
    /// Encrypted close signal.
    Close {
        control_id: u64,
        code: CloseCode,
        reason: String,
    },
    /// Padding bytes to shape packet size.
    Padding(Vec<u8>),
}

impl Frame {
    /// Returns the control identifier if this frame is reliable.
    #[must_use]
    pub fn reliable_control_id(&self) -> Option<u64> {
        match self {
            Self::CtrlAck { .. } | Self::Ping => None,
            Self::PathChallenge { control_id, .. }
            | Self::PathResponse { control_id, .. }
            | Self::SessionUpdate { control_id, .. }
            | Self::Close { control_id, .. } => Some(*control_id),
            Self::IpData(_) | Self::Padding(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ControlFrame {
    CtrlAck {
        acked_control_id: u64,
    },
    PathChallenge {
        control_id: u64,
        challenge: [u8; 8],
    },
    PathResponse {
        control_id: u64,
        challenge: [u8; 8],
    },
    SessionUpdate {
        control_id: u64,
        next_phase: u8,
        contribution: [u8; 32],
        issued_at_secs: u64,
    },
    Ping,
    Close {
        control_id: u64,
        code: CloseCode,
        reason: String,
    },
}

impl From<ControlFrame> for Frame {
    fn from(value: ControlFrame) -> Self {
        match value {
            ControlFrame::CtrlAck { acked_control_id } => Self::CtrlAck { acked_control_id },
            ControlFrame::PathChallenge {
                control_id,
                challenge,
            } => Self::PathChallenge {
                control_id,
                challenge,
            },
            ControlFrame::PathResponse {
                control_id,
                challenge,
            } => Self::PathResponse {
                control_id,
                challenge,
            },
            ControlFrame::SessionUpdate {
                control_id,
                next_phase,
                contribution,
                issued_at_secs,
            } => Self::SessionUpdate {
                control_id,
                next_phase,
                contribution,
                issued_at_secs,
            },
            ControlFrame::Ping => Self::Ping,
            ControlFrame::Close {
                control_id,
                code,
                reason,
            } => Self::Close {
                control_id,
                code,
                reason,
            },
        }
    }
}

impl TryFrom<&Frame> for ControlFrame {
    type Error = TunnelError;

    fn try_from(value: &Frame) -> Result<Self, Self::Error> {
        match value {
            Frame::CtrlAck { acked_control_id } => Ok(Self::CtrlAck {
                acked_control_id: *acked_control_id,
            }),
            Frame::PathChallenge {
                control_id,
                challenge,
            } => Ok(Self::PathChallenge {
                control_id: *control_id,
                challenge: *challenge,
            }),
            Frame::PathResponse {
                control_id,
                challenge,
            } => Ok(Self::PathResponse {
                control_id: *control_id,
                challenge: *challenge,
            }),
            Frame::SessionUpdate {
                control_id,
                next_phase,
                contribution,
                issued_at_secs,
            } => Ok(Self::SessionUpdate {
                control_id: *control_id,
                next_phase: *next_phase,
                contribution: *contribution,
                issued_at_secs: *issued_at_secs,
            }),
            Frame::Ping => Ok(Self::Ping),
            Frame::Close {
                control_id,
                code,
                reason,
            } => Ok(Self::Close {
                control_id: *control_id,
                code: *code,
                reason: reason.clone(),
            }),
            Frame::IpData(_) | Frame::Padding(_) => {
                Err(TunnelError::InvalidState("frame is not a control frame"))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EncryptedControlFrame {
    pub(crate) sequence_number: u64,
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WireFrame {
    IpData(Vec<u8>),
    EncryptedControl(EncryptedControlFrame),
    Padding(Vec<u8>),
}
