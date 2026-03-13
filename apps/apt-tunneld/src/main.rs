//! Development CLI for the APT tunnel-node role.

use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionServer, AdmissionServerSecrets, ClientCredential,
    ClientSessionRequest, CredentialStore, ServerResponse,
};
use apt_carriers::D1Carrier;
use apt_observability::{init_tracing, record_event, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_persona::{PersonaEngine, PersonaInputs};
use apt_policy::PolicyController;
use apt_tunnel::{Frame, RekeyStatus, TunnelSession};
use apt_types::{
    AuthProfile, CarrierBinding, CredentialIdentity, EndpointId, MINIMUM_REPLAY_WINDOW,
    PathSignalEvent, PolicyMode, SessionRole,
};
use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "apt-tunneld", about = "Development CLI for the APT tunnel-node role")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run an end-to-end admission plus tunnel dataplane demo.
    Demo {
        #[arg(long, default_value_t = 1_700_000_000)]
        now: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Demo { now } => {
            let config = ObservabilityConfig::default();
            init_tracing(&config);
            match run_demo(now, &config) {
                Ok(output) => println!("{}", serde_json::to_string_pretty(&output).expect("json serialization should succeed")),
                Err(error) => {
                    eprintln!("demo failed: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn run_demo(now: u64, observability: &ObservabilityConfig) -> Result<serde_json::Value, String> {
    let carrier = D1Carrier::conservative();
    let endpoint_id = EndpointId::new("edge.sg-demo");
    let shared_key = [23_u8; 32];
    let server_secrets = AdmissionServerSecrets::generate().map_err(|error| error.to_string())?;
    let server_static_public = server_secrets.static_keypair.public;

    let mut credentials = CredentialStore::default();
    credentials.set_shared_deployment_key(shared_key);
    let mut server = AdmissionServer::new(AdmissionConfig::conservative(endpoint_id.clone()), credentials, server_secrets);
    let client_credential = ClientCredential {
        auth_profile: AuthProfile::SharedDeployment,
        user_id: None,
        admission_key: shared_key,
        server_static_public,
        enable_lookup_hint: false,
    };
    let mut request = ClientSessionRequest::conservative(endpoint_id.clone(), now);
    request.preferred_carrier = CarrierBinding::D1DatagramUdp;

    let prepared_c0 = initiate_c0(client_credential, request.clone(), &carrier).map_err(|error| error.to_string())?;
    let s1 = match server.handle_c0("tunnel-client", &carrier, &prepared_c0.packet, 1_200, now) {
        ServerResponse::Reply(packet) => packet,
        ServerResponse::Drop(action) => return Err(format!("server dropped C0 with {:?}", action)),
    };
    let prepared_c2 = prepared_c0.state.handle_s1(&s1, &carrier).map_err(|error| error.to_string())?;
    let server_reply = match server.handle_c2("tunnel-client", &carrier, &prepared_c2.packet, now) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(action) => return Err(format!("server dropped C2 with {:?}", action)),
    };
    let client_session = prepared_c2.state.handle_s3(&server_reply.packet, &carrier).map_err(|error| error.to_string())?;

    let mut client_tunnel = TunnelSession::new(
        client_session.session_id,
        SessionRole::Initiator,
        client_session.secrets,
        client_session.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now,
    );
    let mut server_tunnel = TunnelSession::new(
        server_reply.session.session_id,
        SessionRole::Responder,
        server_reply.session.secrets,
        server_reply.session.rekey_limits,
        MINIMUM_REPLAY_WINDOW as u64,
        now,
    );

    let payload = vec![0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef];
    let encoded = client_tunnel
        .encode_packet(&[Frame::IpData(payload.clone()), Frame::Ping], now)
        .map_err(|error| error.to_string())?;
    let decoded = server_tunnel.decode_packet(&encoded.bytes, now).map_err(|error| error.to_string())?;

    let rekey_frame = client_tunnel.initiate_rekey(now + 1).map_err(|error| error.to_string())?;
    let rekey_packet = client_tunnel
        .encode_packet(&[rekey_frame], now + 1)
        .map_err(|error| error.to_string())?;
    let rekey_decoded = server_tunnel
        .decode_packet(&rekey_packet.bytes, now + 1)
        .map_err(|error| error.to_string())?;
    let ack_packet = server_tunnel
        .encode_packet(&rekey_decoded.ack_suggestions, now + 1)
        .map_err(|error| error.to_string())?;
    let _ = client_tunnel
        .decode_packet(&ack_packet.bytes, now + 1)
        .map_err(|error| error.to_string())?;
    let post_rekey = client_tunnel
        .encode_packet(&[Frame::Ping], now + 2)
        .map_err(|error| error.to_string())?;
    let _ = server_tunnel
        .decode_packet(&post_rekey.bytes, now + 2)
        .map_err(|error| error.to_string())?;

    let persona = PersonaEngine::generate(&PersonaInputs {
        persona_seed: client_session.secrets.persona_seed,
        path_profile: request.path_profile,
        chosen_carrier: client_session.chosen_carrier,
        policy_mode: client_session.policy_mode,
        remembered_profile: None,
    });
    let mut controller = PolicyController::new(PolicyMode::StealthFirst, false);
    controller.observe_signal(PathSignalEvent::StableDelivery);
    controller.observe_signal(PathSignalEvent::StableDelivery);
    let mut snapshot = TelemetrySnapshot::new("apt-tunneld-demo");
    let credential_label = match &server_reply.session.credential_identity {
        CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
        CredentialIdentity::User(user) => format!("user:{user}"),
    };
    record_event(
        &mut snapshot,
        &AptEvent::AdmissionAccepted {
            session_id: client_session.session_id,
            carrier: client_session.chosen_carrier,
            credential_identity: credential_label,
        },
        Some(&request.path_profile),
        observability,
    );
    record_event(
        &mut snapshot,
        &AptEvent::TunnelEstablished {
            session_id: client_session.session_id,
            carrier: client_session.chosen_carrier,
            mode: client_session.policy_mode,
        },
        Some(&request.path_profile),
        observability,
    );

    let rekey_status = match client_tunnel.rekey_status(now + 2) {
        RekeyStatus::Healthy => "healthy",
        RekeyStatus::SoftLimitReached => "soft-limit",
        RekeyStatus::HardLimitReached => "hard-limit",
    };
    Ok(json!({
        "role": "tunneld",
        "session_id": client_session.session_id.to_string(),
        "carrier": client_session.chosen_carrier.as_str(),
        "initial_frames_received": decoded.frames.len(),
        "ack_suggestions_for_rekey": rekey_decoded.ack_suggestions.len(),
        "client_send_phase": client_tunnel.send_key_phase(),
        "server_send_phase": server_tunnel.send_key_phase(),
        "rekey_status": rekey_status,
        "persona": {
            "pacing_family": format!("{:?}", persona.scheduler.pacing_family),
            "migration_threshold": persona.scheduler.migration_threshold,
        },
        "policy": {
            "current_mode": format!("{:?}", controller.current_mode),
            "should_migrate": controller.should_migrate(),
        },
        "telemetry": snapshot,
    }))
}
