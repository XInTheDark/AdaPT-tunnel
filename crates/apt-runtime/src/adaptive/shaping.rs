use super::*;

impl AdaptiveDatapath {
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

    pub fn burst_cap(&self) -> usize {
        usize::from(self.persona.scheduler.burst_size_target.max(1))
    }

    pub fn maybe_padding_frame(&self, payload_bytes: usize, keepalive_only: bool) -> Option<Frame> {
        if matches!(self.controller.current_mode, PolicyMode::SpeedFirst) {
            return None;
        }
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
        let minimum_cover =
            if keepalive_only && matches!(self.keepalive_mode(), KeepaliveMode::SparseCover) {
                24
            } else {
                0
            };
        let padding_len = target_padding.min(max_padding).max(minimum_cover);
        (padding_len >= 8).then(|| Frame::Padding(vec![0_u8; padding_len]))
    }

    pub(super) fn regenerate_persona(&mut self) {
        self.path_profile = self
            .local_normality
            .as_ref()
            .and_then(super::normality::infer_path_profile)
            .unwrap_or(self.path_profile);
        self.persona = generate_persona(
            self.chosen_carrier,
            self.persona_seed,
            self.controller.current_mode,
            self.path_profile,
            self.remembered_profile.clone(),
        );
    }
}

pub(super) fn generate_persona(
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
