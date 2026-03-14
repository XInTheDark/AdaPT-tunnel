use apt_persona::{PersonaEngine, PersonaInputs, PersonaProfile, RememberedProfile};
use apt_policy::{LocalNormalityProfile, PolicyController};
use apt_tunnel::Frame;
use apt_types::{
    CarrierBinding, ConnectionLongevityClass, GatewayFingerprint, KeepaliveMode, LinkType,
    LocalNetworkContext, LossClass, MtuClass, NatClass, NetworkMetadataObservation, PathClass,
    PathProfile, PathSignalEvent, PolicyMode, PublicRouteHint, RttClass,
};
use rand::Rng;
use std::time::Duration;

const POLICY_OBSERVATION_INTERVAL_SECS: u64 = 15;
const QUIET_IMPAIRMENT_THRESHOLD_SECS: u64 = 45;

#[derive(Clone, Debug)]
pub struct AdaptiveDatapath {
    persona_seed: [u8; 32],
    chosen_carrier: CarrierBinding,
    allow_speed_first_by_policy: bool,
    controller: PolicyController,
    persona: PersonaProfile,
    path_profile: PathProfile,
    remembered_profile: Option<RememberedProfile>,
    local_normality: Option<LocalNormalityProfile>,
    keepalive_sample_index: u64,
    next_keepalive_due_secs: u64,
    last_policy_observation_secs: u64,
    last_send_millis: Option<u64>,
    last_recv_millis: Option<u64>,
}

impl AdaptiveDatapath {
    pub fn new_client(
        chosen_carrier: CarrierBinding,
        persona_seed: [u8; 32],
        context: LocalNetworkContext,
        stored_profile: Option<LocalNormalityProfile>,
        remembered_profile: Option<RememberedProfile>,
        initial_mode: PolicyMode,
        allow_speed_first_by_policy: bool,
        initial_path_profile: PathProfile,
        now_secs: u64,
    ) -> Self {
        let local_normality = stored_profile.unwrap_or_else(|| LocalNormalityProfile::new(context));
        let path_profile = infer_path_profile(&local_normality).unwrap_or(initial_path_profile);
        let allow_speed_first = allow_speed_first_by_policy && local_normality.is_bootstrapped();
        let controller = PolicyController::new(initial_mode, allow_speed_first);
        let persona = generate_persona(
            chosen_carrier,
            persona_seed,
            controller.current_mode,
            path_profile,
            remembered_profile.clone(),
        );
        let mut state = Self {
            persona_seed,
            chosen_carrier,
            allow_speed_first_by_policy,
            controller,
            persona,
            path_profile,
            remembered_profile,
            local_normality: Some(local_normality),
            keepalive_sample_index: 0,
            next_keepalive_due_secs: now_secs,
            last_policy_observation_secs: now_secs,
            last_send_millis: None,
            last_recv_millis: None,
        };
        state.reschedule_keepalive(now_secs);
        state
    }

    pub fn new_server(
        chosen_carrier: CarrierBinding,
        persona_seed: [u8; 32],
        initial_mode: PolicyMode,
        allow_speed_first_by_policy: bool,
        initial_path_profile: PathProfile,
        now_secs: u64,
    ) -> Self {
        let controller = PolicyController::new(initial_mode, allow_speed_first_by_policy);
        let persona = generate_persona(
            chosen_carrier,
            persona_seed,
            controller.current_mode,
            initial_path_profile,
            None,
        );
        let mut state = Self {
            persona_seed,
            chosen_carrier,
            allow_speed_first_by_policy,
            controller,
            persona,
            path_profile: initial_path_profile,
            remembered_profile: None,
            local_normality: None,
            keepalive_sample_index: 0,
            next_keepalive_due_secs: now_secs,
            last_policy_observation_secs: now_secs,
            last_send_millis: None,
            last_recv_millis: None,
        };
        state.reschedule_keepalive(now_secs);
        state
    }

    pub fn current_mode(&self) -> PolicyMode {
        self.controller.current_mode
    }

    pub fn fallback_order(&self) -> Vec<CarrierBinding> {
        let mut order = self.persona.scheduler.fallback_order.clone();
        let controller_order = self.controller.fallback_order(self.chosen_carrier);
        for carrier in controller_order.into_iter().rev() {
            if let Some(index) = order.iter().position(|value| *value == carrier) {
                let existing = order.remove(index);
                order.insert(0, existing);
            } else {
                order.insert(0, carrier);
            }
        }
        order
    }

    pub fn standby_health_check_secs(&self) -> u64 {
        u64::from(self.persona.standby_health_check_secs)
    }

    pub fn migration_threshold(&self) -> u8 {
        self.persona.scheduler.migration_threshold
    }

    pub fn remembered_profile(&self) -> Option<RememberedProfile> {
        self.remembered_profile.clone()
    }

    pub fn local_normality_profile(&self) -> Option<LocalNormalityProfile> {
        self.local_normality.clone()
    }

    pub fn note_successful_session(&mut self) {
        if let Some(profile) = &mut self.local_normality {
            profile.note_successful_session();
            self.controller.allow_speed_first =
                self.allow_speed_first_by_policy && profile.is_bootstrapped();
            self.path_profile = infer_path_profile(profile).unwrap_or(self.path_profile);
        } else {
            self.controller.allow_speed_first = self.allow_speed_first_by_policy;
        }
        self.refresh_remembered_profile();
    }

    pub fn burst_cap(&self) -> usize {
        usize::from(self.persona.scheduler.burst_size_target.max(1))
    }

    pub fn pacing_delay(&self, payload_bytes: usize, burst_len: usize) -> Option<Duration> {
        let interactive = payload_bytes <= 384;
        let max_delay_ms = match self.persona.scheduler.pacing_family {
            apt_types::PacingFamily::Smooth => {
                if interactive {
                    4
                } else {
                    8
                }
            }
            apt_types::PacingFamily::Bursty => {
                if burst_len >= self.burst_cap() {
                    0
                } else if interactive {
                    2
                } else {
                    5
                }
            }
            apt_types::PacingFamily::Opportunistic => {
                if interactive {
                    1
                } else {
                    3
                }
            }
        };
        if max_delay_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(
                rand::thread_rng().gen_range(0..=max_delay_ms),
            ))
        }
    }

    pub fn maybe_padding_frame(&self, payload_bytes: usize, keepalive_only: bool) -> Option<Frame> {
        let max_padding = payload_bytes
            .saturating_mul(usize::from(self.persona.scheduler.padding_budget_bps))
            / 10_000;
        let target_padding = self
            .persona
            .scheduler
            .packet_size_bins
            .iter()
            .find(|(_, upper)| usize::from(*upper) > payload_bytes)
            .map(|(lower, upper)| {
                let midpoint = (usize::from(*lower) + usize::from(*upper)) / 2;
                midpoint.saturating_sub(payload_bytes)
            })
            .unwrap_or_default();
        let minimum_cover = if keepalive_only
            && matches!(
                self.persona.scheduler.keepalive_mode,
                KeepaliveMode::SparseCover
            ) {
            24
        } else {
            0
        };
        let padding_len = target_padding.min(max_padding).max(minimum_cover);
        (padding_len >= 8).then(|| Frame::Padding(vec![0_u8; padding_len]))
    }

    pub fn keepalive_due(&self, now_secs: u64, last_send_secs: u64) -> bool {
        if now_secs < self.next_keepalive_due_secs {
            return false;
        }
        !matches!(
            self.persona.scheduler.keepalive_mode,
            KeepaliveMode::SuppressWhenActive
        ) || now_secs.saturating_sub(last_send_secs) >= 5
    }

    pub fn build_keepalive_frames(&mut self, payload_hint: usize, now_secs: u64) -> Vec<Frame> {
        let mut frames = vec![Frame::Ping];
        if let Some(padding) = self.maybe_padding_frame(payload_hint.max(64), true) {
            frames.push(padding);
        }
        self.reschedule_keepalive(now_secs);
        frames
    }

    pub fn record_outbound(&mut self, payload_bytes: usize, burst_len: usize, now_millis: u64) {
        let gap_ms = now_millis.saturating_sub(self.last_send_millis.unwrap_or(now_millis));
        self.record_observation(
            payload_bytes,
            burst_len,
            gap_ms.clamp(0, 60_000) as u32,
            true,
        );
        self.last_send_millis = Some(now_millis);
    }

    pub fn record_inbound(&mut self, payload_bytes: usize, now_millis: u64) {
        let gap_ms = now_millis.saturating_sub(self.last_recv_millis.unwrap_or(now_millis));
        self.record_observation(payload_bytes, 1, gap_ms.clamp(0, 60_000) as u32, true);
        self.last_recv_millis = Some(now_millis);
    }

    pub fn maybe_observe_stability(&mut self, now_secs: u64) -> Option<PolicyMode> {
        if now_secs.saturating_sub(self.last_policy_observation_secs)
            < POLICY_OBSERVATION_INTERVAL_SECS
        {
            return None;
        }
        self.last_policy_observation_secs = now_secs;
        self.apply_signal(PathSignalEvent::StableDelivery, now_secs)
    }

    pub fn maybe_observe_quiet_impairment(
        &mut self,
        now_secs: u64,
        last_recv_secs: u64,
    ) -> Option<PolicyMode> {
        if now_secs.saturating_sub(last_recv_secs) < QUIET_IMPAIRMENT_THRESHOLD_SECS {
            return None;
        }
        self.apply_signal(PathSignalEvent::RttInflation, now_secs)
    }

    pub fn apply_signal(&mut self, signal: PathSignalEvent, now_secs: u64) -> Option<PolicyMode> {
        if let Some(profile) = &self.local_normality {
            self.controller.allow_speed_first =
                self.allow_speed_first_by_policy && profile.is_bootstrapped();
        } else {
            self.controller.allow_speed_first = self.allow_speed_first_by_policy;
        }
        let previous = self.controller.current_mode;
        let current = self.controller.observe_signal(signal);
        if current != previous {
            self.regenerate_persona();
            self.refresh_remembered_profile();
            self.reschedule_keepalive(now_secs);
            Some(current)
        } else {
            None
        }
    }

    pub fn note_activity(&mut self, now_secs: u64) {
        self.reschedule_keepalive(now_secs);
    }

    fn regenerate_persona(&mut self) {
        self.path_profile = self
            .local_normality
            .as_ref()
            .and_then(infer_path_profile)
            .unwrap_or(self.path_profile);
        self.persona = generate_persona(
            self.chosen_carrier,
            self.persona_seed,
            self.controller.current_mode,
            self.path_profile,
            self.remembered_profile.clone(),
        );
    }

    fn refresh_remembered_profile(&mut self) {
        let permissiveness_score = match self.controller.current_mode {
            PolicyMode::StealthFirst => 48,
            PolicyMode::Balanced => 144,
            PolicyMode::SpeedFirst => 224,
        };
        self.remembered_profile = Some(RememberedProfile {
            preferred_carrier: self.chosen_carrier,
            permissiveness_score,
        });
    }

    fn record_observation(
        &mut self,
        payload_bytes: usize,
        burst_len: usize,
        gap_ms: u32,
        tunnel_traffic: bool,
    ) {
        let Some(profile) = &mut self.local_normality else {
            return;
        };
        profile.record_observation(&NetworkMetadataObservation {
            packet_size: payload_bytes.clamp(64, 4_096) as u16,
            inter_send_gap_ms: gap_ms.clamp(0, 60_000),
            burst_length: burst_len.clamp(1, 256) as u16,
            upstream_downstream_ratio_class: 2,
            path_profile: self.path_profile,
            longevity: if profile.successful_sessions > 0 {
                ConnectionLongevityClass::Moderate
            } else {
                ConnectionLongevityClass::Ephemeral
            },
            tunnel_traffic,
        });
        self.path_profile = infer_path_profile(profile).unwrap_or(self.path_profile);
    }

    fn reschedule_keepalive(&mut self, now_secs: u64) {
        let interval = PersonaEngine::sample_keepalive_interval(
            &PersonaInputs {
                persona_seed: self.persona_seed,
                path_profile: self.path_profile,
                chosen_carrier: self.chosen_carrier,
                policy_mode: self.controller.current_mode,
                remembered_profile: self.remembered_profile.clone(),
            },
            None,
            self.keepalive_sample_index,
        );
        self.keepalive_sample_index = self.keepalive_sample_index.saturating_add(1);
        self.next_keepalive_due_secs = now_secs.saturating_add(interval);
    }
}

fn generate_persona(
    chosen_carrier: CarrierBinding,
    persona_seed: [u8; 32],
    policy_mode: PolicyMode,
    path_profile: PathProfile,
    remembered_profile: Option<RememberedProfile>,
) -> PersonaProfile {
    PersonaEngine::generate(&PersonaInputs {
        persona_seed,
        path_profile,
        chosen_carrier,
        policy_mode,
        remembered_profile,
    })
}

pub fn build_client_network_context(
    endpoint_label: &str,
    public_route_label: &str,
) -> LocalNetworkContext {
    LocalNetworkContext {
        link_type: LinkType::Unknown,
        gateway: GatewayFingerprint("default-gateway".to_string()),
        local_label: endpoint_label.to_string(),
        public_route: PublicRouteHint(public_route_label.to_string()),
    }
}

#[must_use]
pub fn admission_path_profile(stored_profile: Option<&LocalNormalityProfile>) -> PathProfile {
    stored_profile
        .and_then(infer_path_profile)
        .unwrap_or_else(PathProfile::unknown)
}

fn infer_path_profile(profile: &LocalNormalityProfile) -> Option<PathProfile> {
    let summary = profile.summary().ok()?;
    let path = if summary.weighted_observations >= 200.0 && summary.median_gap_ms <= 30 {
        PathClass::Stable
    } else if summary.median_gap_ms <= 80 {
        PathClass::Variable
    } else {
        PathClass::Constrained
    };
    let mtu = if summary.median_packet_size >= 1_200 {
        MtuClass::Large
    } else if summary.median_packet_size >= 800 {
        MtuClass::Medium
    } else {
        MtuClass::Small
    };
    let rtt = if summary.median_gap_ms <= 20 {
        RttClass::Low
    } else if summary.median_gap_ms <= 75 {
        RttClass::Moderate
    } else {
        RttClass::High
    };
    Some(PathProfile {
        path,
        mtu,
        rtt,
        loss: LossClass::Unknown,
        nat: NatClass::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_datapath_bootstraps_and_persists_learning() {
        let context = build_client_network_context("edge-a", "198.51.100.10:51820");
        let mut adaptive = AdaptiveDatapath::new_client(
            CarrierBinding::D1DatagramUdp,
            [7_u8; 32],
            context,
            None,
            None,
            PolicyMode::StealthFirst,
            true,
            PathProfile::unknown(),
            0,
        );
        adaptive.note_successful_session();
        adaptive.record_outbound(900, 2, 50);
        adaptive.record_inbound(1_050, 75);
        assert!(adaptive.local_normality_profile().is_some());
        assert!(adaptive.remembered_profile().is_some());
    }

    #[test]
    fn keepalive_frames_include_cover_padding_when_sparse_cover_is_active() {
        let context = build_client_network_context("edge-a", "route-a");
        let mut adaptive = AdaptiveDatapath::new_client(
            CarrierBinding::D1DatagramUdp,
            [11_u8; 32],
            context,
            None,
            None,
            PolicyMode::StealthFirst,
            true,
            PathProfile::unknown(),
            0,
        );
        adaptive.persona.scheduler.keepalive_mode = KeepaliveMode::SparseCover;
        let frames = adaptive.build_keepalive_frames(80, 10);
        assert!(matches!(frames.first(), Some(Frame::Ping)));
        assert!(frames
            .iter()
            .any(|frame| matches!(frame, Frame::Padding(_))));
    }

    #[test]
    fn stable_delivery_can_change_policy_mode() {
        let context = build_client_network_context("edge-a", "route-a");
        let mut adaptive = AdaptiveDatapath::new_client(
            CarrierBinding::D1DatagramUdp,
            [19_u8; 32],
            context,
            None,
            None,
            PolicyMode::StealthFirst,
            true,
            PathProfile::unknown(),
            0,
        );
        for tick in [15, 30, 45, 60, 75] {
            let _ = adaptive.maybe_observe_stability(tick);
        }
        assert_eq!(adaptive.current_mode(), PolicyMode::Balanced);
    }
}
