use super::*;
use crate::adaptive::{canonicalize_local_network_context, local_network_profile_key};
use std::collections::BTreeMap;

const MAX_NETWORK_PROFILES: usize = 16;
const DEFAULT_KEEPALIVE_TARGET_INTERVAL_SECS: u64 = 25;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersistedIdleOutcomeSummary {
    #[default]
    Unknown,
    IdleSurvived,
    Rebinding,
    QuietTimeout,
    Impaired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedKeepaliveLearningState {
    pub current_target_interval_secs: u64,
    pub last_idle_outcome: PersistedIdleOutcomeSummary,
    pub success_counter: u16,
    pub failure_counter: u16,
}

impl Default for PersistedKeepaliveLearningState {
    fn default() -> Self {
        Self {
            current_target_interval_secs: DEFAULT_KEEPALIVE_TARGET_INTERVAL_SECS,
            last_idle_outcome: PersistedIdleOutcomeSummary::Unknown,
            success_counter: 0,
            failure_counter: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistedNetworkProfile {
    pub context: LocalNetworkContext,
    pub normality: LocalNormalityProfile,
    pub remembered_profile: Option<RememberedProfile>,
    pub last_mode: Mode,
    #[serde(default)]
    pub keepalive_learning: PersistedKeepaliveLearningState,
    #[serde(default)]
    pub last_seen_unix_secs: u64,
}

impl PersistedNetworkProfile {
    #[must_use]
    pub fn new(context: LocalNetworkContext, last_mode: Mode, last_seen_unix_secs: u64) -> Self {
        let context = canonicalize_local_network_context(&context);
        Self {
            normality: LocalNormalityProfile::new(context.clone()),
            context,
            remembered_profile: None,
            last_mode,
            keepalive_learning: PersistedKeepaliveLearningState::default(),
            last_seen_unix_secs,
        }
    }

    #[must_use]
    pub fn for_remote_route(route_hint: impl Into<String>) -> Self {
        Self::new(
            LocalNetworkContext {
                link_type: LinkType::Unknown,
                gateway: GatewayFingerprint("unknown".to_string()),
                local_label: "default".to_string(),
                public_route: PublicRouteHint(route_hint.into()),
            },
            Mode::STEALTH,
            0,
        )
    }

    fn canonicalize(&mut self) {
        self.context = canonicalize_local_network_context(&self.context);
        self.normality.context = self.context.clone();
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ClientPersistentState {
    pub last_status: Option<RuntimeStatus>,
    pub resume_ticket: Option<Vec<u8>>,
    #[serde(default)]
    pub last_successful_carrier: Option<CarrierBinding>,
    #[serde(default)]
    pub network_profiles: BTreeMap<String, PersistedNetworkProfile>,
    #[serde(default)]
    pub last_active_profile_key: Option<String>,
    #[serde(default, rename = "network_profile", skip_serializing)]
    legacy_network_profile: Option<PersistedNetworkProfile>,
}

impl ClientPersistentState {
    pub fn load(path: &Path) -> Result<Self, RuntimeError> {
        match fs::read_to_string(path) {
            Ok(raw) => {
                let mut state: Self = toml::from_str(&raw)?;
                state.migrate_legacy_profile();
                maybe_upgrade_toml_file(path, &raw, &state)?;
                Ok(state)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(RuntimeError::IoWithPath {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    pub fn store(&self, path: &Path) -> Result<(), RuntimeError> {
        let serialized = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| RuntimeError::IoWithPath {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(path, serialized).map_err(|source| RuntimeError::IoWithPath {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    #[must_use]
    pub fn active_network_profile(&self) -> Option<&PersistedNetworkProfile> {
        self.last_active_profile_key
            .as_ref()
            .and_then(|key| self.network_profiles.get(key))
    }

    pub fn active_network_profile_mut(&mut self) -> Option<&mut PersistedNetworkProfile> {
        let key = self.last_active_profile_key.clone()?;
        self.network_profiles.get_mut(&key)
    }

    pub fn activate_network_profile(
        &mut self,
        context: LocalNetworkContext,
        now_secs: u64,
        default_mode: Mode,
    ) -> String {
        let context = canonicalize_local_network_context(&context);
        let key = local_network_profile_key(&context);
        let entry = self.network_profiles.entry(key.clone()).or_insert_with(|| {
            PersistedNetworkProfile::new(context.clone(), default_mode, now_secs)
        });
        entry.context = context.clone();
        entry.normality.context = context;
        entry.last_seen_unix_secs = now_secs;
        self.last_active_profile_key = Some(key.clone());
        self.enforce_profile_limit();
        key
    }

    pub fn upsert_active_network_profile(&mut self, mut profile: PersistedNetworkProfile) {
        profile.canonicalize();
        let key = local_network_profile_key(&profile.context);
        self.network_profiles.insert(key.clone(), profile);
        self.last_active_profile_key = Some(key);
        self.enforce_profile_limit();
    }

    fn migrate_legacy_profile(&mut self) {
        if let Some(mut legacy_profile) = self.legacy_network_profile.take() {
            legacy_profile.canonicalize();
            if self.network_profiles.is_empty() {
                let key = local_network_profile_key(&legacy_profile.context);
                self.last_active_profile_key = Some(key.clone());
                self.network_profiles.insert(key, legacy_profile);
            }
        }
        for profile in self.network_profiles.values_mut() {
            profile.canonicalize();
        }
        self.enforce_profile_limit();
    }

    fn enforce_profile_limit(&mut self) {
        while self.network_profiles.len() > MAX_NETWORK_PROFILES {
            let candidate = self
                .network_profiles
                .iter()
                .min_by(|left, right| {
                    left.1
                        .last_seen_unix_secs
                        .cmp(&right.1.last_seen_unix_secs)
                        .then_with(|| left.0.cmp(right.0))
                })
                .map(|(key, _)| key.clone());
            let Some(candidate) = candidate else {
                break;
            };
            self.network_profiles.remove(&candidate);
            if self.last_active_profile_key.as_deref() == Some(candidate.as_str()) {
                self.last_active_profile_key = None;
            }
        }
        if self
            .last_active_profile_key
            .as_ref()
            .is_some_and(|key| self.network_profiles.contains_key(key))
        {
            return;
        }
        self.last_active_profile_key = self
            .network_profiles
            .iter()
            .max_by(|left, right| {
                left.1
                    .last_seen_unix_secs
                    .cmp(&right.1.last_seen_unix_secs)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(key, _)| key.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Serialize)]
    struct LegacyClientPersistentState {
        last_status: Option<RuntimeStatus>,
        resume_ticket: Option<Vec<u8>>,
        last_successful_carrier: Option<CarrierBinding>,
        network_profile: Option<PersistedNetworkProfile>,
    }

    fn context(label: &str) -> LocalNetworkContext {
        LocalNetworkContext {
            link_type: LinkType::Wifi,
            gateway: GatewayFingerprint(format!("gw-{label}")),
            local_label: format!("ssid-{label}"),
            public_route: PublicRouteHint(format!("route-{label}")),
        }
    }

    fn temp_state_path(prefix: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}.toml"))
    }

    #[test]
    fn legacy_single_profile_state_migrates_to_keyed_store() {
        let path = temp_state_path("adapt-legacy-state");
        let legacy_profile = PersistedNetworkProfile::new(context("home"), Mode::BALANCED, 77);
        let legacy_state = LegacyClientPersistentState {
            last_status: Some(RuntimeStatus::Starting),
            resume_ticket: None,
            last_successful_carrier: Some(CarrierBinding::D1DatagramUdp),
            network_profile: Some(legacy_profile.clone()),
        };
        fs::write(&path, toml::to_string_pretty(&legacy_state).unwrap()).unwrap();

        let loaded = ClientPersistentState::load(&path).unwrap();
        let expected_key = local_network_profile_key(&legacy_profile.context);
        assert_eq!(loaded.network_profiles.len(), 1);
        assert_eq!(
            loaded.last_active_profile_key.as_deref(),
            Some(expected_key.as_str())
        );
        assert_eq!(
            loaded.active_network_profile().unwrap().context,
            legacy_profile.context
        );

        let upgraded = fs::read_to_string(&path).unwrap();
        assert!(upgraded.contains("[network_profiles."));
        assert!(!upgraded.contains("[network_profile]"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn activating_equivalent_contexts_reuses_the_same_profile_key() {
        let mut state = ClientPersistentState::default();
        let first = LocalNetworkContext {
            link_type: LinkType::Named(" WiFi ".to_string()),
            gateway: GatewayFingerprint(" GW-A ".to_string()),
            local_label: "Home SSID".to_string(),
            public_route: PublicRouteHint("D1:198.51.100.10:51820".to_string()),
        };
        let second = LocalNetworkContext {
            link_type: LinkType::Named("wifi".to_string()),
            gateway: GatewayFingerprint("gw-a".to_string()),
            local_label: "home ssid".to_string(),
            public_route: PublicRouteHint("d1:198.51.100.10:51820".to_string()),
        };

        let first_key = state.activate_network_profile(first, 10, Mode::BALANCED);
        state
            .active_network_profile_mut()
            .unwrap()
            .normality
            .note_successful_session();
        let second_key = state.activate_network_profile(second, 20, Mode::BALANCED);

        assert_eq!(first_key, second_key);
        assert_eq!(state.network_profiles.len(), 1);
        assert_eq!(
            state
                .active_network_profile()
                .unwrap()
                .normality
                .successful_sessions,
            1
        );
    }

    #[test]
    fn lru_eviction_keeps_the_most_recent_sixteen_profiles() {
        let mut state = ClientPersistentState::default();
        let first_key = local_network_profile_key(&context("0"));
        for index in 0..17 {
            let mut profile = PersistedNetworkProfile::new(
                context(&index.to_string()),
                Mode::BALANCED,
                index as u64,
            );
            profile.last_seen_unix_secs = index as u64;
            state.upsert_active_network_profile(profile);
        }
        assert_eq!(state.network_profiles.len(), 16);
        assert!(!state.network_profiles.contains_key(&first_key));
        assert!(state.last_active_profile_key.is_some());
    }
}
