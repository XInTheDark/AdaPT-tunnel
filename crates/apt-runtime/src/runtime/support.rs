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
    request.policy_mode = config.session_policy.initial_mode;
    request.policy_flags.allow_speed_first = config.session_policy.allow_speed_first;
    request.policy_flags.allow_hybrid_pq = config.session_policy.allow_hybrid_pq;
    request.path_profile = admission_path_profile(
        persistent_state
            .network_profile
            .as_ref()
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
            crate::config::RuntimeCarrierPreference::S1 => {
                if config.stream_server_addr.is_some() {
                    Ok(vec![CarrierBinding::S1EncryptedStream])
                } else {
                    Err(RuntimeError::InvalidConfig(
                        "S1 was requested explicitly, but stream_server_addr is not configured"
                            .to_string(),
                    ))
                }
            }
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
    let mut available = vec![CarrierBinding::D1DatagramUdp];
    if config.enable_d2_fallback && config.d2.is_some() {
        available.push(CarrierBinding::D2EncryptedDatagram);
    }
    if config.enable_s1_fallback && config.stream_server_addr.is_some() {
        available.push(CarrierBinding::S1EncryptedStream);
    }
    let remembered = config
        .preferred_carrier
        .binding()
        .or(persistent_state.last_successful_carrier)
        .or_else(|| {
            persistent_state
                .network_profile
                .as_ref()
                .and_then(|profile| profile.remembered_profile.as_ref())
                .map(|profile| profile.preferred_carrier)
        });
    let mut order = Vec::new();
    if let Some(binding) = remembered {
        if available.contains(&binding) {
            order.push(binding);
        }
    }
    for binding in [
        CarrierBinding::D1DatagramUdp,
        CarrierBinding::D2EncryptedDatagram,
        CarrierBinding::S1EncryptedStream,
    ] {
        if available.contains(&binding) && !order.contains(&binding) {
            order.push(binding);
        }
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
        *binding != active_binding
            && (*binding != CarrierBinding::D2EncryptedDatagram
                || (config.enable_d2_fallback && config.d2.is_some()))
            && (*binding != CarrierBinding::S1EncryptedStream
                || (config.enable_s1_fallback && config.stream_server_addr.is_some()))
            && !paths.values().any(|path| path.binding == *binding)
    })
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
    if let Some(stream_addr) = config.stream_server_addr {
        if !endpoints.contains(&stream_addr) {
            endpoints.push(stream_addr);
        }
    }
    endpoints
}

pub(super) fn persist_client_learning(
    persistent_state: &mut ClientPersistentState,
    adaptive: &AdaptiveDatapath,
) {
    persistent_state.network_profile =
        adaptive
            .local_normality_profile()
            .map(|normality| PersistedNetworkProfile {
                context: normality.context.clone(),
                normality,
                remembered_profile: adaptive.remembered_profile(),
                last_mode: adaptive.current_mode().into(),
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
