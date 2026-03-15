use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Explicit schema marker for non-default v2 draft transport blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum V2SchemaVersion {
    #[default]
    V2Draft,
}

/// Operator preference across v2 transport families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum V2FamilyPreference {
    #[default]
    Auto,
    S1,
    D2,
    D1,
}

/// Coarse declaration of how strong the public-service deployment is expected to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum V2DeploymentStrength {
    #[default]
    SelfContained,
    OriginBacked,
    Lab,
}

/// Trust material carried by a v2 public-session family block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct V2SurfaceTrustConfig {
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub roots: Option<String>,
    #[serde(default)]
    pub pinned_certificate: Option<String>,
    #[serde(default)]
    pub pinned_spki: Option<String>,
}

/// Client-side configuration for one public-session family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2ClientFamilyConfig {
    pub authority: String,
    pub endpoint: String,
    pub trust: V2SurfaceTrustConfig,
    pub cover_family: String,
    pub profile_version: String,
    #[serde(default)]
    pub deployment_strength: V2DeploymentStrength,
}

/// Policy describing whether `D1` may still be used as a low-stealth fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2D1FallbackPolicy {
    #[serde(default = "default_d1_allowed")]
    pub allowed: bool,
    #[serde(default = "default_true")]
    pub remembered_safe_only: bool,
    #[serde(default)]
    pub explicit_pin_only: bool,
}

impl Default for V2D1FallbackPolicy {
    fn default() -> Self {
        Self {
            allowed: default_d1_allowed(),
            remembered_safe_only: default_true(),
            explicit_pin_only: false,
        }
    }
}

/// Draft client-side v2 transport block kept separate from the current live schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2ClientTransportConfigDraft {
    #[serde(default)]
    pub schema_version: V2SchemaVersion,
    #[serde(default)]
    pub preferred_family: V2FamilyPreference,
    #[serde(default)]
    pub s1: Option<V2ClientFamilyConfig>,
    #[serde(default)]
    pub d2: Option<V2ClientFamilyConfig>,
    #[serde(default)]
    pub d1_policy: V2D1FallbackPolicy,
}

/// Server-side configuration for one v2 public-service surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2ServerSurfaceConfig {
    pub authority: String,
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub trust: V2SurfaceTrustConfig,
    pub cover_family: String,
    pub profile_version: String,
    #[serde(default)]
    pub deployment_strength: V2DeploymentStrength,
    #[serde(default)]
    pub origin_backend: Option<String>,
}

/// Draft server-side v2 transport block kept separate from the current live schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2ServerTransportConfigDraft {
    #[serde(default)]
    pub schema_version: V2SchemaVersion,
    #[serde(default)]
    pub s1: Option<V2ServerSurfaceConfig>,
    #[serde(default)]
    pub d2: Option<V2ServerSurfaceConfig>,
    #[serde(default)]
    pub accepted_cover_profiles: Vec<String>,
    #[serde(default)]
    pub deployment_strength: V2DeploymentStrength,
}

const fn default_true() -> bool {
    true
}

const fn default_d1_allowed() -> bool {
    true
}
