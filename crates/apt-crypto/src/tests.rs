use super::*;
use apt_types::{CarrierBinding, PathProfile, SessionRole};
use serde::{Deserialize, Serialize};

#[test]
fn lookup_hint_rotates_by_epoch() {
    let key = [7_u8; 32];
    assert_ne!(derive_lookup_hint(&key, 1), derive_lookup_hint(&key, 2));
}

#[test]
fn sealed_envelopes_fail_with_wrong_aad() {
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct PayloadType {
        value: u32,
    }

    let key = [9_u8; 32];
    let sealed = SealedEnvelope::seal(&key, b"a", &PayloadType { value: 7 }).unwrap();
    let err = sealed.open::<PayloadType>(&key, b"b").unwrap_err();
    assert!(matches!(err, CryptoError::Aead));
}

#[test]
fn ticket_round_trip_and_integrity_failure() {
    let protector = TokenProtector::new([5_u8; 32]);
    let ticket = ResumeTicket {
        credential_label: "alice".to_string(),
        server_id: "edge-a".to_string(),
        expires_at_secs: 999,
        last_successful_carrier: CarrierBinding::D1DatagramUdp,
        last_path_profile: PathProfile::unknown(),
        resume_secret: [8_u8; 32],
    };
    let mut sealed = protector.seal(&ticket).unwrap();
    let opened: ResumeTicket = protector.open(&sealed).unwrap();
    assert_eq!(opened, ticket);

    sealed.ciphertext[0] ^= 0x01;
    let err = protector.open::<ResumeTicket>(&sealed).unwrap_err();
    assert!(matches!(err, CryptoError::Aead));
}

#[test]
fn opaque_payload_round_trip_and_integrity_failure() {
    let key = derive_runtime_key(&[4_u8; 32], b"d1 outer").unwrap();
    let sealed = seal_opaque_payload(&key, b"aad", b"hello opaque").unwrap();
    let opened = open_opaque_payload(&key, b"aad", &sealed).unwrap();
    assert_eq!(opened, b"hello opaque");

    let err = open_opaque_payload(&key, b"wrong", &sealed).unwrap_err();
    assert!(matches!(err, CryptoError::Aead));
}

#[test]
fn noise_session_derivation_round_trip() {
    let psk = [3_u8; 32];
    let responder_static = generate_static_keypair().unwrap();
    let prologue = b"apt-test".to_vec();
    let mut fixed_ephemeral = [5_u8; 32];
    fixed_ephemeral[0] &= 248;
    fixed_ephemeral[31] &= 127;
    fixed_ephemeral[31] |= 64;

    let mut initiator = NoiseHandshake::new(NoiseHandshakeConfig {
        role: SessionRole::Initiator,
        psk,
        prologue: prologue.clone(),
        local_static_private: None,
        remote_static_public: None,
        fixed_ephemeral_private: None,
    })
    .unwrap();
    let mut responder = NoiseHandshake::new(NoiseHandshakeConfig {
        role: SessionRole::Responder,
        psk,
        prologue,
        local_static_private: Some(responder_static.private),
        remote_static_public: None,
        fixed_ephemeral_private: Some(fixed_ephemeral),
    })
    .unwrap();

    let msg1 = initiator.write_message(&[]).unwrap();
    responder.read_message(&msg1).unwrap();
    let server_contrib = [11_u8; 32];
    let msg2 = responder.write_message(&server_contrib).unwrap();
    let server_payload = initiator.read_message(&msg2).unwrap();
    assert_eq!(server_payload, server_contrib);
    let client_contrib = [13_u8; 32];
    let msg3 = initiator.write_message(&client_contrib).unwrap();
    let client_payload = responder.read_message(&msg3).unwrap();
    assert_eq!(client_payload, client_contrib);

    let initiator_split = initiator.raw_split().unwrap();
    let responder_split = responder.raw_split().unwrap();
    assert_eq!(initiator_split, responder_split);

    let init_hash = initiator.handshake_hash();
    let resp_hash = responder.handshake_hash();
    assert_eq!(init_hash, resp_hash);

    let init_secrets = derive_session_secrets(
        initiator_split,
        &client_contrib,
        &server_contrib,
        &init_hash,
    )
    .unwrap();
    let resp_secrets = derive_session_secrets(
        responder_split,
        &client_contrib,
        &server_contrib,
        &resp_hash,
    )
    .unwrap();
    assert_eq!(
        init_secrets.initiator_to_responder_data,
        resp_secrets.initiator_to_responder_data
    );
    assert_eq!(
        init_secrets.responder_to_initiator_ctrl,
        resp_secrets.responder_to_initiator_ctrl
    );
}

#[test]
fn rekey_derivation_depends_on_phase_and_contribution() {
    let rekey = [17_u8; 32];
    let a = derive_rekey_phase(&rekey, 1, &[21_u8; 32]).unwrap();
    let b = derive_rekey_phase(&rekey, 2, &[21_u8; 32]).unwrap();
    let c = derive_rekey_phase(&rekey, 1, &[22_u8; 32]).unwrap();
    assert_ne!(a.initiator_to_responder_data, b.initiator_to_responder_data);
    assert_ne!(a.initiator_to_responder_data, c.initiator_to_responder_data);
}

#[test]
fn tunnel_nonce_is_packet_number_based() {
    let n1 = tunnel_nonce_from_packet_number(1);
    let n2 = tunnel_nonce_from_packet_number(2);
    assert_ne!(n1, n2);
    assert_eq!(u64::from_be_bytes(n1[4..].try_into().unwrap()), 1);
}
