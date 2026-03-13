//! Development CLI for the APT edge role.

use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionServer, AdmissionServerSecrets, ClientCredential,
    ClientSessionRequest, CredentialStore, PerUserCredential, ServerResponse,
};
use apt_carriers::{CarrierProfile, D1Carrier, S1Carrier};
use apt_observability::{init_tracing, record_event, redact_credential, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_persona::{PersonaEngine, PersonaInputs, RememberedProfile};
use apt_policy::PolicyController;
use apt_types::{AuthProfile, CarrierBinding, CredentialIdentity, EndpointId, PathSignalEvent};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CarrierChoice {
    D1,
    S1,
}

#[derive(Debug, Parser)]
#[command(name = "apt-edge", about = "Development CLI for the APT edge role")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run an end-to-end admission demo and print the edge/server view.
    Demo {
        #[arg(long, value_enum, default_value_t = CarrierChoice::D1)]
        carrier: CarrierChoice,
        #[arg(long, default_value_t = false)]
        per_user: bool,
        #[arg(long, default_value_t = 1_700_000_000)]
        now: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Demo { carrier, per_user, now } => {
            let config = ObservabilityConfig::default();
            init_tracing(&config);
            let result = match carrier {
                CarrierChoice::D1 => run_demo(&D1Carrier::conservative(), per_user, now, &config),
                CarrierChoice::S1 => run_demo(&S1Carrier::conservative(), per_user, now, &config),
            };
            match result {
                Ok(output) => println!("{}", serde_json::to_string_pretty(&output).expect("json serialization should succeed")),
                Err(error) => {
                    eprintln!("demo failed: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn run_demo<C: CarrierProfile>(carrier: &C, per_user: bool, now: u64, observability: &ObservabilityConfig) -> Result<serde_json::Value, String> {
    let source_id = "edge-loopback";
    let endpoint_id = EndpointId::new("edge.sg-demo");
    let admission_key = if per_user { [17_u8; 32] } else { [11_u8; 32] };
    let server_secrets = AdmissionServerSecrets::generate().map_err(|error| error.to_string())?;
    let server_static_public = server_secrets.static_keypair.public;

    let mut credential_store = CredentialStore::default();
    if per_user {
        credential_store.add_user(PerUserCredential {
            user_id: "alice".to_string(),
            admission_key,
        });
    } else {
        credential_store.set_shared_deployment_key(admission_key);
    }
    let mut server = AdmissionServer::new(
        AdmissionConfig::conservative(endpoint_id.clone()),
        credential_store,
        server_secrets,
    );

    let client_credential = ClientCredential {
        auth_profile: if per_user { AuthProfile::PerUser } else { AuthProfile::SharedDeployment },
        user_id: per_user.then(|| "alice".to_string()),
        admission_key,
        server_static_public,
        enable_lookup_hint: per_user,
    };
    let mut request = ClientSessionRequest::conservative(endpoint_id.clone(), now);
    request.preferred_carrier = carrier.binding();
    request.supported_carriers = vec![carrier.binding(), CarrierBinding::D1DatagramUdp, CarrierBinding::S1EncryptedStream];

    let prepared_c0 = initiate_c0(client_credential, request.clone(), carrier).map_err(|error| error.to_string())?;
    let s1 = match server.handle_c0(source_id, carrier, &prepared_c0.packet, 1_200, now) {
        ServerResponse::Reply(packet) => packet,
        ServerResponse::Drop(action) => return Err(format!("edge dropped C0 with {:?}", action)),
    };
    let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier).map_err(|error| error.to_string())?;
    let established_reply = match server.handle_c2(source_id, carrier, &prepared_c2.packet, now) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(action) => return Err(format!("edge dropped C2 with {:?}", action)),
    };

    let persona = PersonaEngine::generate(&PersonaInputs {
        persona_seed: established_reply.session.secrets.persona_seed,
        path_profile: request.path_profile,
        chosen_carrier: established_reply.session.chosen_carrier,
        policy_mode: established_reply.session.policy_mode,
        remembered_profile: Some(RememberedProfile {
            preferred_carrier: established_reply.session.chosen_carrier,
            permissiveness_score: 3,
        }),
    });
    let mut controller = PolicyController::new(established_reply.session.policy_mode, false);
    controller.observe_signal(PathSignalEvent::StableDelivery);
    let mut snapshot = TelemetrySnapshot::new("apt-edge-demo");
    record_event(
        &mut snapshot,
        &AptEvent::AdmissionAccepted {
            session_id: established_reply.session.session_id,
            carrier: established_reply.session.chosen_carrier,
            credential_identity: redact_credential(&established_reply.session.credential_identity),
        },
        Some(&request.path_profile),
        observability,
    );
    record_event(
        &mut snapshot,
        &AptEvent::TunnelEstablished {
            session_id: established_reply.session.session_id,
            carrier: established_reply.session.chosen_carrier,
            mode: established_reply.session.policy_mode,
        },
        Some(&request.path_profile),
        observability,
    );

    let credential_kind = match &established_reply.session.credential_identity {
        CredentialIdentity::SharedDeployment => "shared",
        CredentialIdentity::User(_) => "per-user",
    };
    Ok(json!({
        "role": "edge",
        "session_id": established_reply.session.session_id.to_string(),
        "carrier": established_reply.session.chosen_carrier.as_str(),
        "cipher_suite": established_reply.session.chosen_suite.as_str(),
        "policy_mode": format!("{:?}", established_reply.session.policy_mode),
        "credential_kind": credential_kind,
        "client_identity": established_reply.session.client_identity,
        "resume_ticket_issued": established_reply.session.resume_ticket.is_some(),
        "persona": {
            "preferred_carrier": persona.scheduler.fallback_order.first().map(|binding| binding.as_str()).unwrap_or("none"),
            "pacing_family": format!("{:?}", persona.scheduler.pacing_family),
            "idle_resume_ramp_ms": persona.idle_resume_ramp_ms,
        },
        "policy": {
            "current_mode": format!("{:?}", controller.current_mode),
            "fallback_order": controller.fallback_order(established_reply.session.chosen_carrier).iter().map(|binding| binding.as_str()).collect::<Vec<_>>(),
        },
        "telemetry": snapshot,
    }))
}
