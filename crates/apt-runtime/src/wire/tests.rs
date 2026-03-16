use super::*;
use apt_carriers::{D1Carrier, D2Carrier};
use apt_crypto::SealedEnvelope;
use apt_types::{EndpointId, SessionId};

#[test]
fn admission_datagram_round_trip() {
    let carrier = D1Carrier::conservative();
    let endpoint_id = EndpointId::new("edge-a");
    let key = derive_d1_admission_outer_key(&[3_u8; 32], 77).unwrap();
    let packet = AdmissionWirePacket {
        lookup_hint: Some([9_u8; 8]),
        envelope: SealedEnvelope {
            nonce: [7_u8; 24],
            ciphertext: b"admission".to_vec(),
        },
    };
    let encoded = encode_admission_datagram(&carrier, &endpoint_id, &key, &packet).unwrap();
    let decoded = decode_admission_datagram(&carrier, &endpoint_id, &key, &encoded).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn confirmation_datagram_round_trip() {
    let carrier = D1Carrier::conservative();
    let endpoint_id = EndpointId::new("edge-a");
    let key = derive_d1_confirmation_outer_key(&[5_u8; 32]).unwrap();
    let packet = ConfirmationWirePacket {
        envelope: SealedEnvelope {
            nonce: [1_u8; 24],
            ciphertext: b"confirmation".to_vec(),
        },
    };
    let encoded = encode_confirmation_datagram(&carrier, &endpoint_id, &key, &packet).unwrap();
    let decoded = decode_confirmation_datagram(&carrier, &endpoint_id, &key, &encoded).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn d2_admission_datagram_round_trip() {
    let carrier = D2Carrier::conservative();
    let endpoint_id = EndpointId::new("edge-a");
    let key = derive_d2_admission_outer_key(&[0x13_u8; 32], 77).unwrap();
    let packet = AdmissionWirePacket {
        lookup_hint: Some([0x19_u8; 8]),
        envelope: SealedEnvelope {
            nonce: [0x17_u8; 24],
            ciphertext: b"d2-admission".to_vec(),
        },
    };
    let encoded = encode_admission_d2_datagram(&carrier, &endpoint_id, &key, &packet).unwrap();
    let decoded = decode_admission_d2_datagram(&carrier, &endpoint_id, &key, &encoded).unwrap();
    assert_eq!(decoded, packet);
}

#[test]
fn tunnel_outer_keys_are_directional() {
    let keys = derive_d1_tunnel_outer_keys(&apt_crypto::SessionSecretsForRole {
        send_data: [1_u8; 32],
        recv_data: [2_u8; 32],
        send_ctrl: [3_u8; 32],
        recv_ctrl: [4_u8; 32],
        rekey: [5_u8; 32],
        persona_seed: [6_u8; 32],
        resume_secret: [7_u8; 32],
    })
    .unwrap();
    assert_ne!(keys.send, keys.recv);

    let carrier = D1Carrier::conservative();
    let endpoint_id = EndpointId::new("edge-a");
    let payload = SessionId([8_u8; 16]).0.to_vec();
    let encoded = encode_tunnel_datagram(&carrier, &endpoint_id, &keys.send, &payload).unwrap();
    let decoded = decode_tunnel_datagram(&carrier, &endpoint_id, &keys.send, &encoded).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn d2_tunnel_outer_keys_are_directional() {
    let keys = derive_d2_tunnel_outer_keys(&apt_crypto::SessionSecretsForRole {
        send_data: [1_u8; 32],
        recv_data: [2_u8; 32],
        send_ctrl: [3_u8; 32],
        recv_ctrl: [4_u8; 32],
        rekey: [5_u8; 32],
        persona_seed: [6_u8; 32],
        resume_secret: [7_u8; 32],
    })
    .unwrap();
    assert_ne!(keys.send, keys.recv);

    let carrier = D2Carrier::conservative();
    let endpoint_id = EndpointId::new("edge-a");
    let payload = SessionId([8_u8; 16]).0.to_vec();
    let encoded = encode_tunnel_d2_datagram(&carrier, &endpoint_id, &keys.send, &payload).unwrap();
    let decoded = decode_tunnel_d2_datagram(&carrier, &endpoint_id, &keys.send, &encoded).unwrap();
    assert_eq!(decoded, payload);
}
