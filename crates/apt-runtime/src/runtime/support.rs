use super::*;
use apt_types::PublicRouteHint;

pub(super) fn client_session_request(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    preferred_carrier: CarrierBinding,
    supported_carriers: &[CarrierBinding],
    masked_fallback_ticket: Option<SealedEnvelope>,
    now: u64,
) -> ClientSessionRequest {
    let mut request = ClientSessionRequest::conservative(config.endpoint_id.clone(), now);
    request.preferred_carrier = preferred_carrier;
    request.supported_carriers = supported_carriers.to_vec();
    request.mode = config.mode;
    request.policy_flags.allow_hybrid_pq = config.session_policy.allow_hybrid_pq;
    request.public_route_hint = persistent_state
        .active_network_profile()
        .map(|profile| profile.context.public_route.clone())
        .unwrap_or_else(|| PublicRouteHint(config.endpoint_id.as_str().to_string()));
    request.path_profile = admission_path_profile(
        persistent_state
            .active_network_profile()
            .map(|profile| &profile.normality),
    );
    request.masked_fallback_ticket = masked_fallback_ticket;
    request
}

pub(super) fn client_credential(config: &ResolvedClientConfig) -> ClientCredential {
    ClientCredential {
        auth_profile: config.auth_profile,
        user_id: config.client_identity.clone(),
        client_static_private: Some(config.client_static_private_key),
        admission_key: config.admission_key,
        server_static_public: config.server_static_public_key,
        enable_lookup_hint: matches!(config.auth_profile, AuthProfile::PerUser),
    }
}

pub(super) fn client_route_exempt_endpoints(config: &ResolvedClientConfig) -> Vec<SocketAddr> {
    vec![config.server_addr]
}

pub(super) fn persist_client_learning(
    persistent_state: &mut ClientPersistentState,
    adaptive: &AdaptiveDatapath,
) {
    let Some(normality) = adaptive.local_normality_profile() else {
        return;
    };
    persistent_state.upsert_active_network_profile(PersistedNetworkProfile {
        context: normality.context.clone(),
        normality,
        remembered_profile: adaptive.remembered_profile(),
        last_mode: adaptive.current_mode(),
        keepalive_learning: adaptive.keepalive_learning_state(),
        last_seen_unix_secs: now_secs(),
    });
}

pub(super) fn extract_destination_ip(packet: &[u8]) -> Option<IpAddr> {
    let version = packet.first().map(|value| value >> 4)?;
    if version == 4 && packet.len() >= 20 {
        Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )))
    } else if version == 6 && packet.len() >= 40 {
        let mut octets = [0_u8; 16];
        octets.copy_from_slice(&packet[24..40]);
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

pub(super) fn tunnel_addresses(transport: &SessionTransportParameters) -> Vec<IpAddr> {
    let mut addresses = vec![IpAddr::V4(transport.client_ipv4)];
    if let Some(ipv6) = transport.client_ipv6 {
        addresses.push(IpAddr::V6(ipv6));
    }
    addresses
}

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn redact_credential(identity: &CredentialIdentity) -> String {
    match identity {
        CredentialIdentity::SharedDeployment => "shared-deployment".to_string(),
        CredentialIdentity::User(user) => format!("user:{user}"),
    }
}
