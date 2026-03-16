use apt_carriers::{CarrierProfile, InvalidInputBehavior};
use apt_crypto::SealedEnvelope;
use apt_types::CarrierBinding;
use serde::{Deserialize, Serialize};

/// Envelope embedded into a legal API-sync request slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSyncRequestUpgradeEnvelope {
    pub lookup_hint: Option<[u8; 8]>,
    pub envelope: SealedEnvelope,
}

/// Envelope embedded into a legal API-sync response slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSyncResponseUpgradeEnvelope {
    pub envelope: SealedEnvelope,
}

/// Carrier metadata for the H2 API-sync public-session family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiSyncH2Carrier {
    max_record_size: u16,
    tunnel_mtu: u16,
}

impl ApiSyncH2Carrier {
    #[must_use]
    pub const fn new(max_record_size: u16, tunnel_mtu: u16) -> Self {
        Self {
            max_record_size,
            tunnel_mtu,
        }
    }

    #[must_use]
    pub const fn conservative() -> Self {
        Self::new(16_384, 1_380)
    }
}

impl Default for ApiSyncH2Carrier {
    fn default() -> Self {
        Self::conservative()
    }
}

impl CarrierProfile for ApiSyncH2Carrier {
    fn binding(&self) -> CarrierBinding {
        CarrierBinding::S1EncryptedStream
    }

    fn max_record_size(&self) -> u16 {
        self.max_record_size
    }

    fn tunnel_mtu(&self) -> u16 {
        self.tunnel_mtu
    }

    fn invalid_input_behavior(&self) -> InvalidInputBehavior {
        InvalidInputBehavior::DecoySurface
    }
}
