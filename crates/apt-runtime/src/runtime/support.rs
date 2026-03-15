use super::*;

pub(super) fn client_session_request(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
    preferred_carrier: CarrierBinding,
    supported_carriers: &[CarrierBinding],
    resume_ticket: Option<SealedEnvelope>,
    now: u64,
) -> ClientSessionRequest {
    let mut request = ClientSessionRequest::conservative(config.endpoint_id.clone(), now);
    request.preferred_carrier = preferred_carrier;
    request.supported_carriers = supported_carriers.to_vec();
    request.mode = config.mode;
    request.policy_flags.allow_hybrid_pq = config.session_policy.allow_hybrid_pq;
    request.path_profile = admission_path_profile(
        persistent_state
            .active_network_profile()
            .map(|profile| &profile.normality),
    );
    request.resume_ticket = resume_ticket;
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

pub(super) fn client_carrier_attempt_order(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
) -> Result<Vec<CarrierBinding>, RuntimeError> {
    if config.strict_preferred_carrier {
        return match config.preferred_carrier {
            crate::config::RuntimeCarrierPreference::Auto => Ok(
                carrier_attempt_order_without_strict_override(config, persistent_state),
            ),
            crate::config::RuntimeCarrierPreference::D1 => Ok(vec![CarrierBinding::D1DatagramUdp]),
            crate::config::RuntimeCarrierPreference::D2 => {
                if config.d2.is_some() {
                    Ok(vec![CarrierBinding::D2EncryptedDatagram])
                } else {
                    Err(RuntimeError::InvalidConfig(
                        "D2 was requested explicitly, but no D2 endpoint/certificate is configured"
                            .to_string(),
                    ))
                }
            }
            crate::config::RuntimeCarrierPreference::S1 => Ok(
                carrier_attempt_order_without_strict_override(config, persistent_state),
            ),
        };
    }

    Ok(carrier_attempt_order_without_strict_override(
        config,
        persistent_state,
    ))
}

fn carrier_attempt_order_without_strict_override(
    config: &ResolvedClientConfig,
    persistent_state: &ClientPersistentState,
) -> Vec<CarrierBinding> {
    let mut public_session_families = Vec::new();
    if config.enable_d2_fallback && config.d2.is_some() {
        public_session_families.push(CarrierBinding::D2EncryptedDatagram);
    }
    let mut available = public_session_families.clone();
    available.push(CarrierBinding::D1DatagramUdp);
    let explicit = config.preferred_carrier.binding();
    let remembered = persistent_state
        .active_network_profile()
        .and_then(|profile| profile.remembered_profile.as_ref())
        .map(|profile| profile.preferred_carrier)
        .or(persistent_state.last_successful_carrier);
    let mut order = Vec::new();
    if let Some(binding) = explicit {
        if available.contains(&binding) {
            order.push(binding);
        }
    }
    if let Some(binding) = remembered {
        if available.contains(&binding) && !order.contains(&binding) {
            order.push(binding);
        }
    }
    for binding in public_session_families {
        if available.contains(&binding) && !order.contains(&binding) {
            order.push(binding);
        }
    }
    if available.contains(&CarrierBinding::D1DatagramUdp)
        && !order.contains(&CarrierBinding::D1DatagramUdp)
    {
        order.push(CarrierBinding::D1DatagramUdp);
    }
    order
}

pub(super) fn next_standby_candidate(
    config: &ResolvedClientConfig,
    adaptive: &AdaptiveDatapath,
    paths: &HashMap<u64, ClientPathState>,
    active_path_id: u64,
) -> Option<CarrierBinding> {
    let active_binding = paths.get(&active_path_id)?.binding;
    adaptive.fallback_order().into_iter().find(|binding| {
        runtime_supports_client_binding(config, *binding)
            && !matches!(binding, CarrierBinding::H1RequestResponse)
            && *binding != active_binding
            && (*binding != CarrierBinding::D2EncryptedDatagram
                || (config.enable_d2_fallback && config.d2.is_some()))
            && !paths.values().any(|path| path.binding == *binding)
    })
}

fn runtime_supports_client_binding(config: &ResolvedClientConfig, binding: CarrierBinding) -> bool {
    match binding {
        CarrierBinding::D1DatagramUdp => true,
        CarrierBinding::D2EncryptedDatagram => config.enable_d2_fallback && config.d2.is_some(),
        CarrierBinding::S1EncryptedStream | CarrierBinding::H1RequestResponse => false,
    }
}

pub(super) fn schedule_next_standby_probe(
    now: u64,
    override_secs: u64,
    adaptive: &AdaptiveDatapath,
) -> u64 {
    let base = if override_secs > 0 {
        override_secs
    } else {
        adaptive.standby_health_check_secs()
    }
    .max(10);
    now.saturating_add(jittered_interval_secs(base))
}

pub(super) fn jittered_interval_secs(base: u64) -> u64 {
    let jitter = rand::random::<u8>() % 41;
    let percent = 80 + u64::from(jitter);
    base.saturating_mul(percent) / 100
}

pub(super) fn client_route_exempt_endpoints(config: &ResolvedClientConfig) -> Vec<SocketAddr> {
    let mut endpoints = vec![config.server_addr];
    if let Some(d2) = &config.d2 {
        if !endpoints.contains(&d2.endpoint.addr) {
            endpoints.push(d2.endpoint.addr);
        }
    }
    endpoints
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

pub(super) fn candidate_epoch_slots(now_secs: u64) -> [u64; 3] {
    let slot = now_secs / DEFAULT_ADMISSION_EPOCH_SLOT_SECS;
    [slot.saturating_sub(1), slot, slot.saturating_add(1)]
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
