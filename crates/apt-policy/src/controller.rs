use apt_types::{CarrierBinding, Mode, PathSignalEvent};
use serde::{Deserialize, Serialize};

const MAX_SIGNAL_SCORE: u8 = 12;
const MAX_STABILITY_CREDIT: u8 = 24;

/// Runtime controller for numeric-mode adjustments and migration pressure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyController {
    /// Current effective numeric mode.
    pub current_mode: Mode,
    negotiated_mode: Mode,
    bootstrapped: bool,
    seeded_bias: u8,
    stability_credit: u8,
    severe_impairment: u8,
    rebinding_pressure: u8,
    idle_timeout_pressure: u8,
    mtu_pressure: u8,
    rtt_pressure: u8,
    fallback_pressure: u8,
}

impl PolicyController {
    /// Creates a new controller.
    #[must_use]
    pub fn new(negotiated_mode: Mode, bootstrapped: bool, persisted_mode: Option<Mode>) -> Self {
        let seeded_bias = persisted_mode
            .map(|mode| mode.value().saturating_sub(negotiated_mode.value()))
            .unwrap_or_default()
            .min(MAX_SIGNAL_SCORE.saturating_mul(2));
        let mut controller = Self {
            current_mode: negotiated_mode,
            negotiated_mode,
            bootstrapped,
            seeded_bias,
            stability_credit: 0,
            severe_impairment: 0,
            rebinding_pressure: 0,
            idle_timeout_pressure: 0,
            mtu_pressure: 0,
            rtt_pressure: 0,
            fallback_pressure: 0,
        };
        controller.recompute_mode();
        controller
    }

    /// Updates whether the active profile has enough evidence to leave bootstrap mode.
    pub fn set_bootstrapped(&mut self, bootstrapped: bool) -> Mode {
        self.bootstrapped = bootstrapped;
        self.recompute_mode()
    }

    /// Applies a path signal and returns the updated mode.
    pub fn observe_signal(&mut self, signal: PathSignalEvent) -> Mode {
        match signal {
            PathSignalEvent::StableDelivery => {
                self.stability_credit = self
                    .stability_credit
                    .saturating_add(2)
                    .min(MAX_STABILITY_CREDIT);
                self.seeded_bias = self.seeded_bias.saturating_sub(1);
                self.decay_impairments(1);
            }
            PathSignalEvent::FallbackSuccess => {
                self.stability_credit = self
                    .stability_credit
                    .saturating_add(3)
                    .min(MAX_STABILITY_CREDIT);
                self.seeded_bias = self.seeded_bias.saturating_sub(2);
                self.severe_impairment = self.severe_impairment.saturating_sub(1);
                self.rebinding_pressure = self.rebinding_pressure.saturating_sub(1);
                self.idle_timeout_pressure = self.idle_timeout_pressure.saturating_sub(1);
                self.mtu_pressure = self.mtu_pressure.saturating_sub(1);
                self.rtt_pressure = self.rtt_pressure.saturating_sub(1);
                self.fallback_pressure = self.fallback_pressure.saturating_sub(2);
            }
            PathSignalEvent::HandshakeBlackhole | PathSignalEvent::ImmediateReset => {
                self.severe_impairment = self
                    .severe_impairment
                    .saturating_add(2)
                    .min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(2);
            }
            PathSignalEvent::NatRebinding => {
                self.rebinding_pressure = self
                    .rebinding_pressure
                    .saturating_add(2)
                    .min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(1);
            }
            PathSignalEvent::IdleTimeoutSymptoms => {
                self.idle_timeout_pressure = self
                    .idle_timeout_pressure
                    .saturating_add(1)
                    .min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(1);
            }
            PathSignalEvent::SizeSpecificLoss => {
                self.mtu_pressure = self.mtu_pressure.saturating_add(1).min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(1);
            }
            PathSignalEvent::MtuBlackhole => {
                self.mtu_pressure = self.mtu_pressure.saturating_add(2).min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(1);
            }
            PathSignalEvent::RttInflation => {
                self.rtt_pressure = self.rtt_pressure.saturating_add(1).min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(1);
            }
            PathSignalEvent::FallbackFailure => {
                self.fallback_pressure = self
                    .fallback_pressure
                    .saturating_add(2)
                    .min(MAX_SIGNAL_SCORE);
                self.stability_credit = self.stability_credit.saturating_sub(1);
            }
        }
        self.recompute_mode()
    }

    /// Returns whether current impairment pressure justifies migration.
    #[must_use]
    pub fn should_migrate(&self) -> bool {
        self.migration_pressure() >= 4
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

    fn recompute_mode(&mut self) -> Mode {
        let base_mode = self.negotiated_mode.value();
        let bootstrap_bias = if self.bootstrapped {
            0
        } else {
            bootstrap_bias_for_mode(base_mode)
        };
        let impairment_bias = u16::from(self.severe_impairment) * 8
            + u16::from(self.rebinding_pressure) * 5
            + u16::from(self.idle_timeout_pressure) * 4
            + u16::from(self.mtu_pressure) * 4
            + u16::from(self.rtt_pressure) * 2
            + u16::from(self.fallback_pressure) * 3
            + u16::from(self.seeded_bias);
        let stability_relief = u16::from(self.stability_credit) * 2;
        let dynamic_bias = impairment_bias
            .saturating_add(u16::from(bootstrap_bias))
            .saturating_sub(stability_relief)
            .min(u16::from(Mode::MAX.saturating_sub(base_mode)));
        self.current_mode = Mode::new(base_mode.saturating_add(dynamic_bias as u8))
            .expect("controller mode stays within bounds");
        self.current_mode
    }

    fn decay_impairments(&mut self, amount: u8) {
        self.severe_impairment = self.severe_impairment.saturating_sub(amount);
        self.rebinding_pressure = self.rebinding_pressure.saturating_sub(amount);
        self.idle_timeout_pressure = self.idle_timeout_pressure.saturating_sub(amount);
        self.mtu_pressure = self.mtu_pressure.saturating_sub(amount);
        self.rtt_pressure = self.rtt_pressure.saturating_sub(amount);
        self.fallback_pressure = self.fallback_pressure.saturating_sub(amount);
    }

    fn migration_pressure(&self) -> u8 {
        self.severe_impairment
            .saturating_mul(2)
            .saturating_add(self.rebinding_pressure)
            .saturating_add(self.fallback_pressure)
            .saturating_add(self.mtu_pressure)
            .saturating_add(self.idle_timeout_pressure / 2)
    }
}

fn bootstrap_bias_for_mode(mode: u8) -> u8 {
    let remaining = u16::from(Mode::MAX.saturating_sub(mode));
    remaining.saturating_mul(28).div_ceil(u16::from(Mode::MAX)) as u8
}
