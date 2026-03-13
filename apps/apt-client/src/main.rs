//! Development CLI for the APT client role.

use apt_admission::{
    initiate_c0, AdmissionConfig, AdmissionServer, AdmissionServerSecrets, ClientCredential,
    ClientSessionRequest, CredentialStore, ServerResponse,
};
use apt_carriers::{CarrierProfile, D1Carrier, S1Carrier};
use apt_observability::{init_tracing, record_event, redact_credential, AptEvent, ObservabilityConfig, TelemetrySnapshot};
use apt_persona::{PersonaEngine, PersonaInputs};
use apt_policy::PolicyController;
use apt_types::{AuthProfile, CarrierBinding, EndpointId, PathSignalEvent, PolicyMode};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CarrierChoice {
    D1,
    S1,
}

#[derive(Debug, Parser)]
#[command(name = "apt-client", about = "Development CLI for the APT client role")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a full localhost-style admission demo and print the client view.
    Demo {
        #[arg(long, value_enum, default_value_t = CarrierChoice::D1)]
        carrier: CarrierChoice,
        #[arg(long, default_value_t = 1_700_000_000)]
        now: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Demo { carrier, now } => {
            let config = ObservabilityConfig::default();
            init_tracing(&config);
            let result = match carrier {
                CarrierChoice::D1 => run_demo(&D1Carrier::conservative(), now, &config),
                CarrierChoice::S1 => run_demo(&S1Carrier::conservative(), now, &config),
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

fn run_demo<C: CarrierProfile>(carrier: &C, now: u64, observability: &ObservabilityConfig) -> Result<serde_json::Value, String> {
    let source_id = "client-loopback";
    let endpoint_id = EndpointId::new("edge.sg-demo");
    let shared_key = [9_u8; 32];

    let server_secrets = AdmissionServerSecrets::generate().map_err(|error| error.to_string())?;
    let server_static_public = server_secrets.static_keypair.public;
    let mut credential_store = CredentialStore::default();
    credential_store.set_shared_deployment_key(shared_key);
    let server = AdmissionServer::new(
        AdmissionConfig::conservative(endpoint_id.clone()),
        credential_store,
        server_secrets,
    );
    let client_credential = ClientCredential {
        auth_profile: AuthProfile::SharedDeployment,
        user_id: None,
        admission_key: shared_key,
        server_static_public,
        enable_lookup_hint: false,
    };
    let mut request = ClientSessionRequest::conservative(endpoint_id.clone(), now);
    request.preferred_carrier = carrier.binding();
    request.supported_carriers = vec![carrier.binding(), CarrierBinding::D1DatagramUdp, CarrierBinding::S1EncryptedStream];

    let prepared_c0 = initiate_c0(client_credential, request.clone(), carrier).map_err(|error| error.to_string())?;
    let mut server = server;
    let s1 = match server.handle_c0(source_id, carrier, &prepared_c0.packet, 1_200, now) {
        ServerResponse::Reply(packet) => packet,
        ServerResponse::Drop(action) => return Err(format!("server dropped C0 with {:?}", action)),
    };
    let prepared_c2 = prepared_c0.state.handle_s1(&s1, carrier).map_err(|error| error.to_string())?;
    let established_reply = match server.handle_c2(source_id, carrier, &prepared_c2.packet, now) {
        ServerResponse::Reply(reply) => reply,
        ServerResponse::Drop(action) => return Err(format!("server dropped C2 with {:?}", action)),
    };
    let session = prepared_c2.state.handle_s3(&established_reply.packet, carrier).map_err(|error| error.to_string())?;

    let persona = PersonaEngine::generate(&PersonaInputs {
        persona_seed: session.secrets.persona_seed,
        path_profile: request.path_profile,
        chosen_carrier: session.chosen_carrier,
        policy_mode: session.policy_mode,
        remembered_profile: None,
    });
    let mut controller = PolicyController::new(PolicyMode::StealthFirst, false);
    controller.observe_signal(PathSignalEvent::StableDelivery);
    controller.observe_signal(PathSignalEvent::StableDelivery);
    let mut snapshot = TelemetrySnapshot::new("apt-client-demo");
    let credential_label = redact_credential(&session.credential_identity);
    record_event(
        &mut snapshot,
        &AptEvent::AdmissionAccepted {
            session_id: session.session_id,
            carrier: session.chosen_carrier,
            credential_identity: credential_label,
        },
        Some(&request.path_profile),
        observability,
    );
    record_event(
        &mut snapshot,
        &AptEvent::TunnelEstablished {
            session_id: session.session_id,
            carrier: session.chosen_carrier,
            mode: session.policy_mode,
        },
        Some(&request.path_profile),
        observability,
    );

    Ok(json!({
        "role": "client",
        "session_id": session.session_id.to_string(),
        "carrier": session.chosen_carrier.as_str(),
        "policy_mode": format!("{:?}", session.policy_mode),
        "tunnel_mtu": session.tunnel_mtu,
        "resume_ticket_issued": session.resume_ticket.is_some(),
        "persona": {
            "pacing_family": format!("{:?}", persona.scheduler.pacing_family),
            "burst_size_target": persona.scheduler.burst_size_target,
            "padding_budget_bps": persona.scheduler.padding_budget_bps,
            "fallback_order": persona.scheduler.fallback_order.iter().map(|binding| binding.as_str()).collect::<Vec<_>>(),
            "keepalive_mode": format!("{:?}", persona.scheduler.keepalive_mode),
        },
        "policy": {
            "current_mode": format!("{:?}", controller.current_mode),
            "should_migrate": controller.should_migrate(),
        },
        "telemetry": snapshot,
    }))
}
