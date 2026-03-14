//! Inner encrypted tunnel primitives for APT/1-core.
//!
//! The tunnel packet format is datagram-oriented and protects one or more frames
//! inside an AEAD-encrypted packet. Reliable control frames are retransmitted by
//! the session helper until acknowledged or expired.

use apt_crypto::{
    derive_rekey_phase, open_tunnel_payload, open_tunnel_payload_with_nonce, seal_tunnel_payload,
    seal_tunnel_payload_with_nonce, CryptoError, SessionSecretsForRole,
};
use apt_types::{CloseCode, RekeyLimits, SessionId, SessionRole};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use thiserror::Error;

const FLAG_HAS_CONTROL: u8 = 0x01;
const PACKET_NONCE_LEN: usize = 12;
const DEFAULT_RETRANSMIT_INTERVAL_SECS: u64 = 1;
const DEFAULT_CONTROL_LIFETIME_SECS: u64 = 10;

/// Errors returned by the tunnel layer.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Packet bytes were malformed.
    #[error("malformed tunnel packet")]
    MalformedPacket,
    /// Replay protection rejected a packet.
    #[error("replay detected")]
    Replay,
    /// Cryptographic processing failed.
    #[error("crypto failure: {0}")]
    Crypto(#[from] apt_crypto::CryptoError),
    /// Serialization failure.
    #[error("serialization failure: {0}")]
    Serialization(#[from] Box<bincode::ErrorKind>),
    /// Invalid state transition.
    #[error("invalid tunnel state: {0}")]
    InvalidState(&'static str),
}

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
enum ControlFrame {
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
struct EncryptedControlFrame {
    sequence_number: u64,
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum WireFrame {
    IpData(Vec<u8>),
    EncryptedControl(EncryptedControlFrame),
    Padding(Vec<u8>),
}

/// Fixed tunnel packet header authenticated as AEAD associated data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelPacketHeader {
    /// Packet flags.
    pub flags: u8,
    /// Key phase.
    pub key_phase: u8,
    /// Monotonic packet number.
    pub packet_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct WirePacketBody {
    header: TunnelPacketHeader,
    frames: Vec<WireFrame>,
}

/// Decoded tunnel packet plus any ack frames the caller may want to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPacket {
    /// Parsed header.
    pub header: TunnelPacketHeader,
    /// Decrypted frames.
    pub frames: Vec<Frame>,
    /// Ack frames suggested for reliable control frames.
    pub ack_suggestions: Vec<Frame>,
}

/// Encoded packet returned by `TunnelSession::encode_packet`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedPacket {
    /// Parsed header for the packet that was emitted.
    pub header: TunnelPacketHeader,
    /// Serialized bytes ready for a carrier record.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ReplayWindow {
    largest_seen: Option<u64>,
    seen: BTreeSet<u64>,
    window_size: u64,
}

impl ReplayWindow {
    fn new(window_size: u64) -> Self {
        Self {
            largest_seen: None,
            seen: BTreeSet::new(),
            window_size,
        }
    }

    fn check_and_insert(&mut self, packet_number: u64) -> Result<(), TunnelError> {
        if let Some(largest) = self.largest_seen {
            if packet_number + self.window_size < largest {
                return Err(TunnelError::Replay);
            }
            if self.seen.contains(&packet_number) {
                return Err(TunnelError::Replay);
            }
            if packet_number > largest {
                self.largest_seen = Some(packet_number);
            }
        } else {
            self.largest_seen = Some(packet_number);
        }
        self.seen.insert(packet_number);
        if let Some(largest) = self.largest_seen {
            let floor = largest.saturating_sub(self.window_size);
            self.seen.retain(|value| *value >= floor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PendingControl {
    frame: Frame,
    expires_at_secs: u64,
    last_sent_at_secs: Option<u64>,
    attempts: u8,
}

#[derive(Clone, Copy, Debug)]
struct PendingSendRekey {
    control_id: u64,
    next_phase: u8,
    next_send_data: [u8; 32],
    next_send_ctrl: [u8; 32],
    next_rekey: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct StagedRecvRekey {
    next_phase: u8,
    next_recv_data: [u8; 32],
    next_recv_ctrl: [u8; 32],
    next_rekey: [u8; 32],
}

/// Rekey limit state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RekeyStatus {
    /// Limits have not yet been crossed.
    Healthy,
    /// Soft limit reached: initiate rekey soon.
    SoftLimitReached,
    /// Hard limit reached: close the session rather than continue.
    HardLimitReached,
}

/// Live tunnel session state.
#[derive(Clone, Debug)]
pub struct TunnelSession {
    /// Session identifier.
    pub session_id: SessionId,
    role: SessionRole,
    send_data_key: [u8; 32],
    recv_data_key: [u8; 32],
    send_ctrl_key: [u8; 32],
    recv_ctrl_key: [u8; 32],
    rekey_secret: [u8; 32],
    send_key_phase: u8,
    recv_key_phase: u8,
    send_packet_number: u64,
    send_ctrl_sequence: u64,
    bytes_sent_under_phase: u64,
    phase_started_at_secs: u64,
    rekey_limits: RekeyLimits,
    replay_window: ReplayWindow,
    next_control_id: u64,
    pending_controls: HashMap<u64, PendingControl>,
    pending_send_rekey: Option<PendingSendRekey>,
    staged_recv_rekey: Option<StagedRecvRekey>,
}

impl TunnelSession {
    /// Creates a new tunnel session.
    #[must_use]
    pub fn new(
        session_id: SessionId,
        role: SessionRole,
        secrets: SessionSecretsForRole,
        rekey_limits: RekeyLimits,
        replay_window_size: u64,
        now_secs: u64,
    ) -> Self {
        Self {
            session_id,
            role,
            send_data_key: secrets.send_data,
            recv_data_key: secrets.recv_data,
            send_ctrl_key: secrets.send_ctrl,
            recv_ctrl_key: secrets.recv_ctrl,
            rekey_secret: secrets.rekey,
            send_key_phase: 0,
            recv_key_phase: 0,
            send_packet_number: 0,
            send_ctrl_sequence: 0,
            bytes_sent_under_phase: 0,
            phase_started_at_secs: now_secs,
            rekey_limits,
            replay_window: ReplayWindow::new(replay_window_size),
            next_control_id: 1,
            pending_controls: HashMap::new(),
            pending_send_rekey: None,
            staged_recv_rekey: None,
        }
    }

    /// Returns the current send key phase.
    #[must_use]
    pub const fn send_key_phase(&self) -> u8 {
        self.send_key_phase
    }

    /// Queues a reliable control frame for retransmission tracking.
    pub fn queue_reliable_control(
        &mut self,
        frame: Frame,
        now_secs: u64,
        lifetime_secs: Option<u64>,
    ) -> Result<u64, TunnelError> {
        let control_id = frame
            .reliable_control_id()
            .ok_or(TunnelError::InvalidState("frame is not reliable"))?;
        self.pending_controls.insert(
            control_id,
            PendingControl {
                frame,
                expires_at_secs: now_secs + lifetime_secs.unwrap_or(DEFAULT_CONTROL_LIFETIME_SECS),
                last_sent_at_secs: None,
                attempts: 0,
            },
        );
        Ok(control_id)
    }

    /// Returns any queued control frames that are due for initial send or retransmit.
    #[must_use]
    pub fn collect_due_control_frames(&mut self, now_secs: u64) -> Vec<Frame> {
        let mut due = Vec::new();
        let mut expired = Vec::new();
        for (control_id, pending) in &mut self.pending_controls {
            if pending.expires_at_secs <= now_secs {
                expired.push(*control_id);
                continue;
            }
            let should_send = match pending.last_sent_at_secs {
                None => true,
                Some(last_sent) => {
                    now_secs.saturating_sub(last_sent) >= DEFAULT_RETRANSMIT_INTERVAL_SECS
                }
            };
            if should_send {
                pending.last_sent_at_secs = Some(now_secs);
                pending.attempts = pending.attempts.saturating_add(1);
                due.push(pending.frame.clone());
            }
        }
        for control_id in expired {
            self.pending_controls.remove(&control_id);
        }
        due
    }

    /// Allocates the next reliable control identifier.
    pub fn next_control_id(&mut self) -> u64 {
        let value = self.next_control_id;
        self.next_control_id = self.next_control_id.saturating_add(1);
        value
    }

    /// Returns the current rekey status.
    #[must_use]
    pub fn rekey_status(&self, now_secs: u64) -> RekeyStatus {
        let age = now_secs.saturating_sub(self.phase_started_at_secs);
        if self.bytes_sent_under_phase >= self.rekey_limits.hard_bytes
            || age >= self.rekey_limits.hard_age_secs
        {
            RekeyStatus::HardLimitReached
        } else if self.bytes_sent_under_phase >= self.rekey_limits.soft_bytes
            || age >= self.rekey_limits.soft_age_secs
        {
            RekeyStatus::SoftLimitReached
        } else {
            RekeyStatus::Healthy
        }
    }

    /// Initiates a send-direction rekey by returning a `SESSION_UPDATE` frame.
    pub fn initiate_rekey(&mut self, now_secs: u64) -> Result<Frame, TunnelError> {
        if self.pending_send_rekey.is_some() {
            return Err(TunnelError::InvalidState("rekey already pending"));
        }
        let control_id = self.next_control_id();
        let contribution: [u8; 32] = rand::random();
        let next_phase = self.send_key_phase.wrapping_add(1);
        let phase = derive_rekey_phase(&self.rekey_secret, next_phase, &contribution)?;
        let (next_send_data, next_send_ctrl) = if self.role.is_initiator() {
            (
                phase.initiator_to_responder_data,
                phase.initiator_to_responder_ctrl,
            )
        } else {
            (
                phase.responder_to_initiator_data,
                phase.responder_to_initiator_ctrl,
            )
        };
        self.pending_send_rekey = Some(PendingSendRekey {
            control_id,
            next_phase,
            next_send_data,
            next_send_ctrl,
            next_rekey: phase.next_rekey,
        });
        let frame = Frame::SessionUpdate {
            control_id,
            next_phase,
            contribution,
            issued_at_secs: now_secs,
        };
        self.queue_reliable_control(frame.clone(), now_secs, None)?;
        Ok(frame)
    }

    /// Encodes frames into one encrypted tunnel packet.
    pub fn encode_packet(
        &mut self,
        frames: &[Frame],
        now_secs: u64,
    ) -> Result<EncodedPacket, TunnelError> {
        let mut has_control = false;
        let mut wire_frames = Vec::with_capacity(frames.len());
        for frame in frames {
            match frame {
                Frame::IpData(packet) => wire_frames.push(WireFrame::IpData(packet.clone())),
                Frame::Padding(bytes) => wire_frames.push(WireFrame::Padding(bytes.clone())),
                Frame::CtrlAck { .. }
                | Frame::PathChallenge { .. }
                | Frame::PathResponse { .. }
                | Frame::SessionUpdate { .. }
                | Frame::Ping
                | Frame::Close { .. } => {
                    has_control = true;
                    let control_plaintext = bincode::serialize(&ControlFrame::try_from(frame)?)?;
                    let sequence_number = self.send_ctrl_sequence;
                    self.send_ctrl_sequence = self.send_ctrl_sequence.saturating_add(1);
                    let ciphertext = seal_tunnel_payload(
                        &self.send_ctrl_key,
                        sequence_number,
                        b"apt ctrl",
                        &control_plaintext,
                    )?;
                    wire_frames.push(WireFrame::EncryptedControl(EncryptedControlFrame {
                        sequence_number,
                        ciphertext,
                    }));
                }
            }
        }

        let header = TunnelPacketHeader {
            flags: if has_control { FLAG_HAS_CONTROL } else { 0 },
            key_phase: self.send_key_phase,
            packet_number: self.send_packet_number,
        };
        let plaintext = bincode::serialize(&WirePacketBody {
            header,
            frames: wire_frames,
        })?;
        let nonce: [u8; PACKET_NONCE_LEN] = rand::random();
        let ciphertext = seal_tunnel_payload_with_nonce(
            &self.send_data_key,
            &nonce,
            &self.session_id.0,
            &plaintext,
        )?;
        let mut packet = Vec::with_capacity(nonce.len() + ciphertext.len());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);
        self.send_packet_number = self.send_packet_number.saturating_add(1);
        self.bytes_sent_under_phase = self
            .bytes_sent_under_phase
            .saturating_add(u64::try_from(packet.len()).unwrap_or(u64::MAX));
        let _ = now_secs;
        Ok(EncodedPacket {
            header,
            bytes: packet,
        })
    }

    fn apply_ack(&mut self, acked_control_id: u64, now_secs: u64) {
        self.pending_controls.remove(&acked_control_id);
        if let Some(pending) = self.pending_send_rekey {
            if pending.control_id == acked_control_id {
                self.send_key_phase = pending.next_phase;
                self.send_data_key = pending.next_send_data;
                self.send_ctrl_key = pending.next_send_ctrl;
                self.rekey_secret = pending.next_rekey;
                self.bytes_sent_under_phase = 0;
                self.phase_started_at_secs = now_secs;
                self.pending_send_rekey = None;
            }
        }
    }

    fn stage_recv_rekey(
        &mut self,
        next_phase: u8,
        contribution: [u8; 32],
    ) -> Result<(), TunnelError> {
        let phase = derive_rekey_phase(&self.rekey_secret, next_phase, &contribution)?;
        let (next_recv_data, next_recv_ctrl) = if self.role.is_initiator() {
            (
                phase.responder_to_initiator_data,
                phase.responder_to_initiator_ctrl,
            )
        } else {
            (
                phase.initiator_to_responder_data,
                phase.initiator_to_responder_ctrl,
            )
        };
        self.staged_recv_rekey = Some(StagedRecvRekey {
            next_phase,
            next_recv_data,
            next_recv_ctrl,
            next_rekey: phase.next_rekey,
        });
        Ok(())
    }

    fn maybe_promote_recv_phase(&mut self, key_phase: u8, now_secs: u64) {
        if let Some(staged) = self.staged_recv_rekey {
            if staged.next_phase == key_phase {
                self.recv_key_phase = staged.next_phase;
                self.recv_data_key = staged.next_recv_data;
                self.recv_ctrl_key = staged.next_recv_ctrl;
                self.rekey_secret = staged.next_rekey;
                self.phase_started_at_secs = now_secs;
                self.staged_recv_rekey = None;
            }
        }
    }

    /// Decrypts and validates one tunnel packet.
    pub fn decode_packet(
        &mut self,
        bytes: &[u8],
        now_secs: u64,
    ) -> Result<DecodedPacket, TunnelError> {
        if bytes.len() <= PACKET_NONCE_LEN {
            return Err(TunnelError::MalformedPacket);
        }
        let nonce: [u8; PACKET_NONCE_LEN] = bytes[..PACKET_NONCE_LEN]
            .try_into()
            .map_err(|_| TunnelError::MalformedPacket)?;
        let ciphertext = &bytes[PACKET_NONCE_LEN..];
        let session_aad = &self.session_id.0;

        let try_decrypt = |key: &[u8; 32]| -> Result<Option<WirePacketBody>, TunnelError> {
            match open_tunnel_payload_with_nonce(key, &nonce, session_aad, ciphertext) {
                Ok(plaintext) => {
                    let body = bincode::deserialize(&plaintext)?;
                    Ok(Some(body))
                }
                Err(CryptoError::Aead) => Ok(None),
                Err(error) => Err(TunnelError::Crypto(error)),
            }
        };

        let (header, wire_frames) = if let Some(body) = try_decrypt(&self.recv_data_key)? {
            if body.header.key_phase != self.recv_key_phase {
                return Err(TunnelError::InvalidState("unexpected receive key phase"));
            }
            (body.header, body.frames)
        } else if let Some(staged) = self.staged_recv_rekey {
            if let Some(body) = try_decrypt(&staged.next_recv_data)? {
                if body.header.key_phase != staged.next_phase {
                    return Err(TunnelError::InvalidState(
                        "unexpected staged receive key phase",
                    ));
                }
                (body.header, body.frames)
            } else {
                return Err(TunnelError::Crypto(CryptoError::Aead));
            }
        } else {
            return Err(TunnelError::Crypto(CryptoError::Aead));
        };
        self.replay_window.check_and_insert(header.packet_number)?;

        let ctrl_key = if header.key_phase == self.recv_key_phase {
            self.recv_ctrl_key
        } else if self
            .staged_recv_rekey
            .as_ref()
            .is_some_and(|staged| staged.next_phase == header.key_phase)
        {
            self.staged_recv_rekey.unwrap().next_recv_ctrl
        } else {
            return Err(TunnelError::InvalidState(
                "unknown receive control key phase",
            ));
        };

        let mut frames = Vec::new();
        let mut ack_suggestions = Vec::new();
        for wire_frame in wire_frames {
            match wire_frame {
                WireFrame::IpData(packet) => frames.push(Frame::IpData(packet)),
                WireFrame::Padding(bytes) => frames.push(Frame::Padding(bytes)),
                WireFrame::EncryptedControl(control) => {
                    let plaintext = open_tunnel_payload(
                        &ctrl_key,
                        control.sequence_number,
                        b"apt ctrl",
                        &control.ciphertext,
                    )?;
                    let control_frame: ControlFrame = bincode::deserialize(&plaintext)?;
                    let frame: Frame = control_frame.into();
                    match &frame {
                        Frame::CtrlAck { acked_control_id } => {
                            self.apply_ack(*acked_control_id, now_secs);
                        }
                        Frame::SessionUpdate {
                            control_id,
                            next_phase,
                            contribution,
                            ..
                        } => {
                            self.stage_recv_rekey(*next_phase, *contribution)?;
                            ack_suggestions.push(Frame::CtrlAck {
                                acked_control_id: *control_id,
                            });
                        }
                        Frame::PathChallenge { control_id, .. }
                        | Frame::PathResponse { control_id, .. }
                        | Frame::Close { control_id, .. } => {
                            ack_suggestions.push(Frame::CtrlAck {
                                acked_control_id: *control_id,
                            });
                        }
                        Frame::Ping | Frame::IpData(_) | Frame::Padding(_) => {}
                    }
                    frames.push(frame);
                }
            }
        }
        self.maybe_promote_recv_phase(header.key_phase, now_secs);
        Ok(DecodedPacket {
            header,
            frames,
            ack_suggestions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apt_crypto::tunnel_nonce_from_packet_number;
    use apt_types::RekeyLimits;

    fn test_session_pair() -> (TunnelSession, TunnelSession) {
        let session_id = SessionId([1_u8; 16]);
        let rekey_limits = RekeyLimits::recommended();
        let initiator = TunnelSession::new(
            session_id,
            SessionRole::Initiator,
            SessionSecretsForRole {
                send_data: [1_u8; 32],
                recv_data: [2_u8; 32],
                send_ctrl: [3_u8; 32],
                recv_ctrl: [4_u8; 32],
                rekey: [9_u8; 32],
                persona_seed: [7_u8; 32],
                resume_secret: [8_u8; 32],
            },
            rekey_limits,
            4_096,
            0,
        );
        let responder = TunnelSession::new(
            session_id,
            SessionRole::Responder,
            SessionSecretsForRole {
                send_data: [2_u8; 32],
                recv_data: [1_u8; 32],
                send_ctrl: [4_u8; 32],
                recv_ctrl: [3_u8; 32],
                rekey: [9_u8; 32],
                persona_seed: [7_u8; 32],
                resume_secret: [8_u8; 32],
            },
            rekey_limits,
            4_096,
            0,
        );
        (initiator, responder)
    }

    #[test]
    fn replay_window_rejects_duplicates() {
        let (mut initiator, mut responder) = test_session_pair();
        let packet = initiator
            .encode_packet(&[Frame::IpData(vec![0, 1, 2])], 0)
            .unwrap();
        let _ = responder.decode_packet(&packet.bytes, 0).unwrap();
        let err = responder.decode_packet(&packet.bytes, 0).unwrap_err();
        assert!(matches!(err, TunnelError::Replay));
    }

    #[test]
    fn mixed_frames_round_trip() {
        let (mut initiator, mut responder) = test_session_pair();
        let control_id = initiator.next_control_id();
        let frames = vec![
            Frame::IpData(vec![1, 2, 3]),
            Frame::PathChallenge {
                control_id,
                challenge: *b"12345678",
            },
            Frame::Padding(vec![0; 8]),
        ];
        let packet = initiator.encode_packet(&frames, 0).unwrap();
        let decoded = responder.decode_packet(&packet.bytes, 0).unwrap();
        assert_eq!(decoded.frames.len(), 3);
        assert_eq!(decoded.ack_suggestions.len(), 1);
    }

    #[test]
    fn reliable_control_retransmits_until_acked() {
        let (mut initiator, _) = test_session_pair();
        let control_id = initiator.next_control_id();
        let frame = Frame::PathChallenge {
            control_id,
            challenge: *b"abcdefgh",
        };
        initiator
            .queue_reliable_control(frame.clone(), 0, Some(3))
            .unwrap();
        assert_eq!(initiator.collect_due_control_frames(0), vec![frame.clone()]);
        assert!(initiator.collect_due_control_frames(0).is_empty());
        assert_eq!(initiator.collect_due_control_frames(1), vec![frame]);
        assert!(initiator.collect_due_control_frames(4).is_empty());
    }

    #[test]
    fn rekey_transitions_after_ack() {
        let (mut initiator, mut responder) = test_session_pair();
        let update = initiator.initiate_rekey(0).unwrap();
        let packet = initiator.encode_packet(&[update.clone()], 0).unwrap();
        let decoded = responder.decode_packet(&packet.bytes, 0).unwrap();
        assert!(decoded
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::SessionUpdate { .. })));
        let ack_packet = responder
            .encode_packet(&decoded.ack_suggestions, 1)
            .unwrap();
        let _ = initiator.decode_packet(&ack_packet.bytes, 1).unwrap();
        assert_eq!(initiator.send_key_phase(), 1);
    }

    #[test]
    fn hard_limit_is_detected() {
        let (mut initiator, _) = test_session_pair();
        initiator.bytes_sent_under_phase = initiator.rekey_limits.hard_bytes;
        assert_eq!(initiator.rekey_status(0), RekeyStatus::HardLimitReached);
    }

    #[test]
    fn tunnel_nonce_depends_on_sequence() {
        assert_ne!(
            tunnel_nonce_from_packet_number(1),
            tunnel_nonce_from_packet_number(2)
        );
    }
}
