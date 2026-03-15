use apt_types::{CarrierBinding, PathSignalEvent, PolicyMode};
use serde::{Deserialize, Serialize};

/// Runtime controller for policy-mode transitions and migration pressure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyController {
    /// Current policy mode.
    pub current_mode: PolicyMode,
    /// Whether automatic speed-first mode is allowed.
    pub allow_speed_first: bool,
    stable_score: i16,
    impairment_score: i16,
}

impl PolicyController {
    /// Creates a new controller.
    #[must_use]
    pub fn new(initial_mode: PolicyMode, allow_speed_first: bool) -> Self {
        Self {
            current_mode: initial_mode,
            allow_speed_first,
            stable_score: 0,
            impairment_score: 0,
        }
    }

    /// Applies a path signal and returns the updated mode.
    pub fn observe_signal(&mut self, signal: PathSignalEvent) -> PolicyMode {
        match signal {
            PathSignalEvent::StableDelivery => {
                self.stable_score = (self.stable_score + 1).min(16);
                self.impairment_score = (self.impairment_score - 1).max(0);
            }
            PathSignalEvent::HandshakeBlackhole
            | PathSignalEvent::ImmediateReset
            | PathSignalEvent::FallbackFailure => {
                self.impairment_score = (self.impairment_score + 2).min(16);
                self.stable_score = (self.stable_score - 2).max(0);
            }
            PathSignalEvent::SizeSpecificLoss
            | PathSignalEvent::MtuBlackhole
            | PathSignalEvent::RttInflation
            | PathSignalEvent::NatRebinding => {
                self.impairment_score = (self.impairment_score + 1).min(16);
                self.stable_score = (self.stable_score - 1).max(0);
            }
        }
        self.current_mode = if self.impairment_score >= 2 {
            PolicyMode::StealthFirst
        } else if self.allow_speed_first && self.stable_score >= 10 {
            PolicyMode::SpeedFirst
        } else if self.stable_score >= 4 {
            PolicyMode::Balanced
        } else {
            self.current_mode
        };
        self.current_mode
    }

    /// Returns whether current impairment pressure justifies migration.
    #[must_use]
    pub fn should_migrate(&self) -> bool {
        self.impairment_score >= 3
    }

    /// Produces a conservative fallback order with the impaired carrier deprioritized.
    #[must_use]
    pub fn fallback_order(&self, current: CarrierBinding) -> Vec<CarrierBinding> {
        let mut order = CarrierBinding::conservative_fallback_order().to_vec();
        if self.should_migrate() {
            if let Some(index) = order.iter().position(|carrier| *carrier == current) {
                let current_binding = order.remove(index);
                order.push(current_binding);
            }
        }
        order
    }
}
