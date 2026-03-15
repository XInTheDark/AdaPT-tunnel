use super::*;
use apt_origin::{OriginFamilyId, PublicSessionTransport, ShadowLaneKind};

#[test]
fn client_v2_transport_draft_parses_nested_family_blocks() {
    let parsed: V2ClientTransportConfigDraft = toml::from_str(
        r#"
schema_version = "v2-draft"
preferred_family = "auto"

[d1_policy]
allowed = true
remembered_safe_only = true
explicit_pin_only = false

[s1]
authority = "api.example.com"
endpoint = "api.example.com:443"
cover_family = "api-sync"
profile_version = "2026.03"
deployment_strength = "origin-backed"

[s1.trust]
server_name = "api.example.com"
roots = "native"
pinned_spki = "base64:AAAA"

[d2]
authority = "api.example.com"
endpoint = "api.example.com:443"
cover_family = "object-origin"
profile_version = "2026.03"
deployment_strength = "self-contained"

[d2.trust]
server_name = "api.example.com"
roots = "native"
"#,
    )
    .unwrap();
    assert_eq!(parsed.schema_version, V2SchemaVersion::V2Draft);
    assert_eq!(parsed.preferred_family, V2FamilyPreference::Auto);
    assert!(parsed.d1_policy.allowed);
    assert!(parsed.d1_policy.remembered_safe_only);
    assert_eq!(
        parsed.s1.as_ref().unwrap().deployment_strength,
        V2DeploymentStrength::OriginBacked
    );
    assert_eq!(
        parsed.d2.as_ref().unwrap().trust.server_name.as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn server_v2_transport_draft_parses_surface_blocks() {
    let parsed: V2ServerTransportConfigDraft = toml::from_str(
        r#"
schema_version = "v2-draft"
accepted_cover_profiles = ["api-sync/2026.03", "object-origin/2026.03"]
deployment_strength = "origin-backed"

[s1]
authority = "api.example.com"
bind = "0.0.0.0:443"
public_endpoint = "api.example.com:443"
cover_family = "api-sync"
profile_version = "2026.03"
deployment_strength = "origin-backed"
origin_backend = "https://origin.internal"

[s1.trust]
server_name = "api.example.com"
roots = "native"

[d2]
authority = "api.example.com"
bind = "0.0.0.0:443"
public_endpoint = "api.example.com:443"
cover_family = "object-origin"
profile_version = "2026.03"
deployment_strength = "lab"

[d2.trust]
server_name = "api.example.com"
pinned_certificate = "file:/etc/adapt/d2-cert.pem"
"#,
    )
    .unwrap();
    assert_eq!(parsed.schema_version, V2SchemaVersion::V2Draft);
    assert_eq!(parsed.accepted_cover_profiles.len(), 2);
    assert_eq!(
        parsed.deployment_strength,
        V2DeploymentStrength::OriginBacked
    );
    assert_eq!(
        parsed.s1.as_ref().unwrap().origin_backend.as_deref(),
        Some("https://origin.internal")
    );
    assert_eq!(
        parsed.d2.as_ref().unwrap().deployment_strength,
        V2DeploymentStrength::Lab
    );
}

#[test]
fn v2_transport_draft_resolves_origin_surface_plans() {
    let parsed: V2ClientTransportConfigDraft = toml::from_str(
        r#"
schema_version = "v2-draft"
preferred_family = "auto"

[s1]
authority = "api.example.com"
endpoint = "api.example.com:443"
cover_family = "api-sync"
profile_version = "2026.03"

[s1.trust]
server_name = "api.example.com"

[d2]
authority = "origin.example.com"
endpoint = "origin.example.com:443"
cover_family = "object-origin"
profile_version = "2026.03"

[d2.trust]
server_name = "origin.example.com"
"#,
    )
    .unwrap();

    let plans = parsed.surface_plans().unwrap();
    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0].transport, PublicSessionTransport::S1H2);
    assert_eq!(plans[0].profile.family_id, OriginFamilyId::ApiSync);
    assert_eq!(plans[1].transport, PublicSessionTransport::D2H3);
    assert!(plans[1]
        .profile
        .supports_shadow_lane(ShadowLaneKind::H3Datagram));
}

#[test]
fn v2_transport_draft_rejects_cover_family_transport_mismatch() {
    let parsed: V2ClientTransportConfigDraft = toml::from_str(
        r#"
schema_version = "v2-draft"
preferred_family = "s1"

[s1]
authority = "api.example.com"
endpoint = "api.example.com:443"
cover_family = "object-origin"
profile_version = "2026.03"

[s1.trust]
server_name = "api.example.com"
"#,
    )
    .unwrap();

    let err = parsed.surface_plans().unwrap_err();
    assert_eq!(
        err,
        V2OriginPlanError::TransportMismatch {
            family: "object-origin".to_string(),
            transport: PublicSessionTransport::D2H3,
            expected: PublicSessionTransport::S1H2,
        }
    );
}
