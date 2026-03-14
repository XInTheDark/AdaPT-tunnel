use super::*;
use crate::codec::FAST_PATH_SINGLE_IP_DATA_TAG;
use apt_crypto::{
    open_tunnel_payload_with_nonce, tunnel_nonce_from_packet_number, SessionSecretsForRole,
};
use apt_types::{RekeyLimits, SessionId, SessionRole};

fn initiator_secrets() -> SessionSecretsForRole {
    SessionSecretsForRole {
        send_data: [1_u8; 32],
        recv_data: [2_u8; 32],
        send_ctrl: [3_u8; 32],
        recv_ctrl: [4_u8; 32],
        rekey: [9_u8; 32],
        persona_seed: [7_u8; 32],
        resume_secret: [8_u8; 32],
    }
}

fn responder_secrets() -> SessionSecretsForRole {
    SessionSecretsForRole {
        send_data: [2_u8; 32],
        recv_data: [1_u8; 32],
        send_ctrl: [4_u8; 32],
        recv_ctrl: [3_u8; 32],
        rekey: [9_u8; 32],
        persona_seed: [7_u8; 32],
        resume_secret: [8_u8; 32],
    }
}

fn test_session_id() -> SessionId {
    SessionId([1_u8; 16])
}

fn test_session_pair() -> (TunnelSession, TunnelSession) {
    let session_id = test_session_id();
    let rekey_limits = RekeyLimits::recommended();
    let initiator = TunnelSession::new(
        session_id,
        SessionRole::Initiator,
        initiator_secrets(),
        rekey_limits,
        4_096,
        0,
    );
    let responder = TunnelSession::new(
        session_id,
        SessionRole::Responder,
        responder_secrets(),
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
fn single_ip_frame_uses_fast_path_encoding() {
    let (mut initiator, mut responder) = test_session_pair();
    let packet = initiator
        .encode_packet(&[Frame::IpData(vec![0x5A; 512])], 0)
        .unwrap();
    let nonce = tunnel_nonce_from_packet_number(packet.header.packet_number);
    let plaintext = open_tunnel_payload_with_nonce(
        &initiator_secrets().send_data,
        &nonce,
        &test_session_id().0,
        &packet.bytes[nonce.len()..],
    )
    .unwrap();
    assert_eq!(
        plaintext.first().copied(),
        Some(FAST_PATH_SINGLE_IP_DATA_TAG)
    );

    let decoded = responder.decode_packet(&packet.bytes, 0).unwrap();
    assert_eq!(decoded.frames, vec![Frame::IpData(vec![0x5A; 512])]);
    assert!(decoded.ack_suggestions.is_empty());
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
    let mut initiator = TunnelSession::new(
        test_session_id(),
        SessionRole::Initiator,
        initiator_secrets(),
        RekeyLimits {
            soft_bytes: 1,
            hard_bytes: 1,
            soft_age_secs: u64::MAX,
            hard_age_secs: u64::MAX,
        },
        4_096,
        0,
    );
    let _ = initiator
        .encode_packet(&[Frame::IpData(vec![0, 1, 2, 3])], 0)
        .unwrap();
    assert_eq!(initiator.rekey_status(0), RekeyStatus::HardLimitReached);
}

#[test]
fn tunnel_nonce_depends_on_sequence() {
    assert_ne!(
        tunnel_nonce_from_packet_number(1),
        tunnel_nonce_from_packet_number(2)
    );
}
