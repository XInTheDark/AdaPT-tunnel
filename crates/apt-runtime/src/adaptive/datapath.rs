use super::*;
use crate::adaptive::keepalive::AdaptiveKeepaliveController;
use crate::config::PersistedKeepaliveLearningState;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AdaptiveRuntimeConfig {
    pub initial_mode: PolicyMode,
    pub operator_mode: Mode,
    pub allow_speed_first_by_policy: bool,
    pub keepalive_base_interval_secs: u64,
}

#[derive(Clone, Debug)]
pub struct AdaptiveDatapath {
    pub(super) persona_seed: [u8; 32],
    pub(super) chosen_carrier: CarrierBinding,
    pub(super) allow_speed_first_by_policy: bool,
    pub(super) controller: PolicyController,
    pub(super) persona: PersonaProfile,
    pub(super) path_profile: PathProfile,
    pub(super) remembered_profile: Option<RememberedProfile>,
    pub(super) local_normality: Option<LocalNormalityProfile>,
    pub(super) keepalive: AdaptiveKeepaliveController,
    pub(super) last_policy_observation_secs: u64,
    pub(super) last_send_millis: Option<u64>,
    pub(super) last_recv_millis: Option<u64>,
    pub(super) observations_since_path_refresh: u16,
    pub(super) session_started_millis: u64,
    pub(super) session_outbound_bytes: u64,
    pub(super) session_inbound_bytes: u64,
}

impl AdaptiveDatapath {
    pub fn new_client(
        chosen_carrier: CarrierBinding,
        persona_seed: [u8; 32],
        context: LocalNetworkContext,
        stored_profile: Option<LocalNormalityProfile>,
        remembered_profile: Option<RememberedProfile>,
        runtime_config: AdaptiveRuntimeConfig,
        initial_path_profile: PathProfile,
        keepalive_learning: Option<PersistedKeepaliveLearningState>,
        now_secs: u64,
    ) -> Self {
        let mut local_normality =
            stored_profile.unwrap_or_else(|| LocalNormalityProfile::new(context));
        local_normality.begin_new_session();
        let path_profile =
            super::normality::infer_path_profile(&local_normality).unwrap_or(initial_path_profile);
        let allow_speed_first =
            runtime_config.allow_speed_first_by_policy && local_normality.is_bootstrapped();
        let controller = PolicyController::new(runtime_config.initial_mode, allow_speed_first);
        let persona = super::shaping::generate_persona(
            chosen_carrier,
            persona_seed,
            controller.current_mode,
            path_profile,
            remembered_profile.clone(),
        );
        let mut state = Self {
            persona_seed,
            chosen_carrier,
            allow_speed_first_by_policy: runtime_config.allow_speed_first_by_policy,
            controller,
            persona,
            path_profile,
            remembered_profile,
            local_normality: Some(local_normality),
            keepalive: AdaptiveKeepaliveController::new(
                persona_seed,
                runtime_config.operator_mode,
                runtime_config.keepalive_base_interval_secs,
                keepalive_learning,
                now_secs,
            ),
            last_policy_observation_secs: now_secs,
            last_send_millis: None,
            last_recv_millis: None,
            observations_since_path_refresh: 0,
            session_started_millis: now_secs.saturating_mul(1_000),
            session_outbound_bytes: 0,
            session_inbound_bytes: 0,
        };
        state.reschedule_keepalive(now_secs);
        state
    }

    pub fn new_server(
        chosen_carrier: CarrierBinding,
        persona_seed: [u8; 32],
        runtime_config: AdaptiveRuntimeConfig,
        initial_path_profile: PathProfile,
        now_secs: u64,
    ) -> Self {
        let controller = PolicyController::new(
            runtime_config.initial_mode,
            runtime_config.allow_speed_first_by_policy,
        );
        let persona = super::shaping::generate_persona(
            chosen_carrier,
            persona_seed,
            controller.current_mode,
            initial_path_profile,
            None,
        );
        let mut state = Self {
            persona_seed,
            chosen_carrier,
            allow_speed_first_by_policy: runtime_config.allow_speed_first_by_policy,
            controller,
            persona,
            path_profile: initial_path_profile,
            remembered_profile: None,
            local_normality: None,
            keepalive: AdaptiveKeepaliveController::new(
                persona_seed,
                runtime_config.operator_mode,
                runtime_config.keepalive_base_interval_secs,
                None,
                now_secs,
            ),
            last_policy_observation_secs: now_secs,
            last_send_millis: None,
            last_recv_millis: None,
            observations_since_path_refresh: 0,
            session_started_millis: now_secs.saturating_mul(1_000),
            session_outbound_bytes: 0,
            session_inbound_bytes: 0,
        };
        state.reschedule_keepalive(now_secs);
        state
    }

    pub fn current_mode(&self) -> PolicyMode {
        self.controller.current_mode
    }

    pub fn remembered_profile(&self) -> Option<RememberedProfile> {
        self.remembered_profile.clone()
    }

    pub fn keepalive_learning_state(&self) -> PersistedKeepaliveLearningState {
        self.keepalive.learning_state()
    }

    #[cfg(test)]
    pub fn keepalive_target_interval_secs(&self) -> u64 {
        self.keepalive.target_interval_secs()
    }

    pub fn keepalive_mode(&self) -> KeepaliveMode {
        self.keepalive
            .effective_mode(self.persona.scheduler.keepalive_mode)
    }

    pub fn local_normality_profile(&self) -> Option<LocalNormalityProfile> {
        self.local_normality.clone()
    }
}
