use crate::{
    codec::{
        decode_packet_plaintext, encode_fast_path_single_ip_data, DecodedPlaintext,
        FLAG_HAS_CONTROL, PACKET_NONCE_LEN,
    },
    frame::{ControlFrame, EncryptedControlFrame, WireFrame},
    packet::{DecodedPacket, EncodedPacket, WirePacketBody},
    rekey::{PendingSendRekey, RekeyStatus, StagedRecvRekey},
    replay::ReplayWindow,
    Frame, TunnelError, TunnelPacketHeader,
};
use apt_crypto::{
    derive_rekey_phase, tunnel_nonce_from_packet_number, CryptoError, SessionSecretsForRole,
    TunnelAead,
};
use apt_types::{RekeyLimits, SessionId, SessionRole};
use std::collections::HashMap;

const DEFAULT_RETRANSMIT_INTERVAL_SECS: u64 = 1;
const DEFAULT_CONTROL_LIFETIME_SECS: u64 = 10;

#[derive(Clone, Debug)]
struct PendingControl {
    frame: Frame,
    expires_at_secs: u64,
    last_sent_at_secs: Option<u64>,
    attempts: u8,
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
    send_data_aead: TunnelAead,
    recv_data_aead: TunnelAead,
    send_ctrl_aead: TunnelAead,
    recv_ctrl_aead: TunnelAead,
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
        let send_data_aead =
            TunnelAead::new(&secrets.send_data).expect("session secrets are fixed length");
        let recv_data_aead =
            TunnelAead::new(&secrets.recv_data).expect("session secrets are fixed length");
        let send_ctrl_aead =
            TunnelAead::new(&secrets.send_ctrl).expect("session secrets are fixed length");
        let recv_ctrl_aead =
            TunnelAead::new(&secrets.recv_ctrl).expect("session secrets are fixed length");
        Self {
            session_id,
            role,
            send_data_key: secrets.send_data,
            recv_data_key: secrets.recv_data,
            send_ctrl_key: secrets.send_ctrl,
            recv_ctrl_key: secrets.recv_ctrl,
            send_data_aead,
            recv_data_aead,
            send_ctrl_aead,
            recv_ctrl_aead,
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
            next_send_data_aead: TunnelAead::new(&next_send_data)?,
            next_send_ctrl_aead: TunnelAead::new(&next_send_ctrl)?,
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
        let header = TunnelPacketHeader {
            flags: if frames
                .iter()
                .any(|frame| !matches!(frame, Frame::IpData(_) | Frame::Padding(_)))
            {
                FLAG_HAS_CONTROL
            } else {
                0
            },
            key_phase: self.send_key_phase,
            packet_number: self.send_packet_number,
        };
        let plaintext = if let [Frame::IpData(packet)] = frames {
            encode_fast_path_single_ip_data(header, packet)?
        } else {
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
                        let control_plaintext =
                            bincode::serialize(&ControlFrame::try_from(frame)?)?;
                        let sequence_number = self.send_ctrl_sequence;
                        self.send_ctrl_sequence = self.send_ctrl_sequence.saturating_add(1);
                        let ciphertext = self.send_ctrl_aead.seal(
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
            bincode::serialize(&WirePacketBody {
                header,
                frames: wire_frames,
            })?
        };
        let nonce = tunnel_nonce_from_packet_number(header.packet_number);
        let ciphertext =
            self.send_data_aead
                .seal_with_nonce(&nonce, &self.session_id.0, &plaintext)?;
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
        if let Some(pending) = self.pending_send_rekey.as_ref() {
            if pending.control_id == acked_control_id {
                self.send_key_phase = pending.next_phase;
                self.send_data_key = pending.next_send_data;
                self.send_ctrl_key = pending.next_send_ctrl;
                self.send_data_aead = pending.next_send_data_aead.clone();
                self.send_ctrl_aead = pending.next_send_ctrl_aead.clone();
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
            next_recv_data_aead: TunnelAead::new(&next_recv_data)?,
            next_recv_ctrl_aead: TunnelAead::new(&next_recv_ctrl)?,
            next_rekey: phase.next_rekey,
        });
        Ok(())
    }

    fn maybe_promote_recv_phase(&mut self, key_phase: u8, now_secs: u64) {
        if let Some(staged) = self.staged_recv_rekey.as_ref() {
            if staged.next_phase == key_phase {
                self.recv_key_phase = staged.next_phase;
                self.recv_data_key = staged.next_recv_data;
                self.recv_ctrl_key = staged.next_recv_ctrl;
                self.recv_data_aead = staged.next_recv_data_aead.clone();
                self.recv_ctrl_aead = staged.next_recv_ctrl_aead.clone();
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

        let try_decrypt = |aead: &TunnelAead| -> Result<Option<Vec<u8>>, TunnelError> {
            match aead.open_with_nonce(&nonce, session_aad, ciphertext) {
                Ok(plaintext) => Ok(Some(plaintext)),
                Err(CryptoError::Aead) => Ok(None),
                Err(error) => Err(TunnelError::Crypto(error)),
            }
        };

        let decoded_plaintext = if let Some(plaintext) = try_decrypt(&self.recv_data_aead)? {
            let decoded = decode_packet_plaintext(&plaintext)?;
            if decoded.header().key_phase != self.recv_key_phase {
                return Err(TunnelError::InvalidState("unexpected receive key phase"));
            }
            decoded
        } else if let Some(staged) = self.staged_recv_rekey.as_ref() {
            if let Some(plaintext) = try_decrypt(&staged.next_recv_data_aead)? {
                let decoded = decode_packet_plaintext(&plaintext)?;
                if decoded.header().key_phase != staged.next_phase {
                    return Err(TunnelError::InvalidState(
                        "unexpected staged receive key phase",
                    ));
                }
                decoded
            } else {
                return Err(TunnelError::Crypto(CryptoError::Aead));
            }
        } else {
            return Err(TunnelError::Crypto(CryptoError::Aead));
        };
        let header = decoded_plaintext.header();
        self.replay_window.check_and_insert(header.packet_number)?;

        if let DecodedPlaintext::FastPath { packet, .. } = decoded_plaintext {
            self.maybe_promote_recv_phase(header.key_phase, now_secs);
            return Ok(DecodedPacket {
                header,
                frames: vec![Frame::IpData(packet)],
                ack_suggestions: Vec::new(),
            });
        }
        let DecodedPlaintext::Standard(body) = decoded_plaintext else {
            unreachable!("fast-path case already returned")
        };

        let ctrl_aead = if header.key_phase == self.recv_key_phase {
            self.recv_ctrl_aead.clone()
        } else if self
            .staged_recv_rekey
            .as_ref()
            .is_some_and(|staged| staged.next_phase == header.key_phase)
        {
            self.staged_recv_rekey
                .as_ref()
                .expect("checked above")
                .next_recv_ctrl_aead
                .clone()
        } else {
            return Err(TunnelError::InvalidState(
                "unknown receive control key phase",
            ));
        };

        let mut frames = Vec::new();
        let mut ack_suggestions = Vec::new();
        for wire_frame in body.frames {
            match wire_frame {
                WireFrame::IpData(packet) => frames.push(Frame::IpData(packet)),
                WireFrame::Padding(bytes) => frames.push(Frame::Padding(bytes)),
                WireFrame::EncryptedControl(control) => {
                    let plaintext = ctrl_aead.open(
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
