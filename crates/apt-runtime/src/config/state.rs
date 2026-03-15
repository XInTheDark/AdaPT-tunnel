use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersistedNetworkProfile {
    pub context: LocalNetworkContext,
    pub normality: LocalNormalityProfile,
    pub remembered_profile: Option<RememberedProfile>,
    pub last_mode: Mode,
}

impl PersistedNetworkProfile {
    #[must_use]
    pub fn for_remote_route(route_hint: impl Into<String>) -> Self {
        let context = LocalNetworkContext {
            link_type: LinkType::Unknown,
            gateway: GatewayFingerprint("unknown".to_string()),
            local_label: "default".to_string(),
            public_route: PublicRouteHint(route_hint.into()),
        };
        Self {
            normality: LocalNormalityProfile::new(context.clone()),
            context,
            remembered_profile: None,
            last_mode: Mode::STEALTH,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ClientPersistentState {
    pub last_status: Option<RuntimeStatus>,
    pub resume_ticket: Option<Vec<u8>>,
    #[serde(default)]
    pub last_successful_carrier: Option<CarrierBinding>,
    #[serde(default)]
    pub network_profile: Option<PersistedNetworkProfile>,
}

impl ClientPersistentState {
    pub fn load(path: &Path) -> Result<Self, RuntimeError> {
        match fs::read_to_string(path) {
            Ok(raw) => {
                let state: Self = toml::from_str(&raw)?;
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
}
