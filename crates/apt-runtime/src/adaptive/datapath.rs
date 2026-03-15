use super::*;

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
    pub(super) keepalive_sample_index: u64,
    pub(super) keepalive_interval_secs: u64,
    pub(super) next_keepalive_due_secs: u64,
    pub(super) last_policy_observation_secs: u64,
    pub(super) last_send_millis: Option<u64>,
    pub(super) last_recv_millis: Option<u64>,
    pub(super) observations_since_path_refresh: u16,
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
        let path_profile =
            super::normality::infer_path_profile(&local_normality).unwrap_or(initial_path_profile);
        let allow_speed_first = allow_speed_first_by_policy && local_normality.is_bootstrapped();
        let controller = PolicyController::new(initial_mode, allow_speed_first);
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
            allow_speed_first_by_policy,
            controller,
            persona,
            path_profile,
            remembered_profile,
            local_normality: Some(local_normality),
            keepalive_sample_index: 0,
            keepalive_interval_secs: 0,
            next_keepalive_due_secs: now_secs,
            last_policy_observation_secs: now_secs,
            last_send_millis: None,
            last_recv_millis: None,
            observations_since_path_refresh: 0,
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
            allow_speed_first_by_policy,
            controller,
            persona,
            path_profile: initial_path_profile,
            remembered_profile: None,
            local_normality: None,
            keepalive_sample_index: 0,
            keepalive_interval_secs: 0,
            next_keepalive_due_secs: now_secs,
            last_policy_observation_secs: now_secs,
            last_send_millis: None,
            last_recv_millis: None,
            observations_since_path_refresh: 0,
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

    pub fn local_normality_profile(&self) -> Option<LocalNormalityProfile> {
        self.local_normality.clone()
    }
}
