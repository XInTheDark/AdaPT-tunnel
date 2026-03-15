use apt_origin::{OriginFamilyProfile, PublicSessionTransport};
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

/// Resolved client-side planning view combining v2 config with an `apt-origin` profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ClientSurfacePlan {
    pub transport: PublicSessionTransport,
    pub authority: String,
    pub endpoint: String,
    pub trust: V2SurfaceTrustConfig,
    pub deployment_strength: V2DeploymentStrength,
    pub profile: OriginFamilyProfile,
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

/// Resolved server-side planning view combining v2 config with an `apt-origin` profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V2ServerSurfacePlan {
    pub transport: PublicSessionTransport,
    pub authority: String,
    pub bind: SocketAddr,
    pub public_endpoint: String,
    pub trust: V2SurfaceTrustConfig,
    pub deployment_strength: V2DeploymentStrength,
    pub origin_backend: Option<String>,
    pub profile: OriginFamilyProfile,
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

/// Errors produced while resolving draft v2 family blocks into origin planning metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V2OriginPlanError {
    UnknownCoverFamily(String),
    ProfileVersionMismatch {
        family: String,
        expected: String,
        actual: String,
    },
    TransportMismatch {
        family: String,
        transport: PublicSessionTransport,
        expected: PublicSessionTransport,
    },
}

impl V2ClientFamilyConfig {
    pub fn to_surface_plan(
        &self,
        transport: PublicSessionTransport,
    ) -> Result<V2ClientSurfacePlan, V2OriginPlanError> {
        let profile = resolve_origin_profile(&self.cover_family, &self.profile_version, transport)?;
        Ok(V2ClientSurfacePlan {
            transport,
            authority: self.authority.clone(),
            endpoint: self.endpoint.clone(),
            trust: self.trust.clone(),
            deployment_strength: self.deployment_strength,
            profile,
        })
    }
}

impl V2ServerSurfaceConfig {
    pub fn to_surface_plan(
        &self,
        transport: PublicSessionTransport,
    ) -> Result<V2ServerSurfacePlan, V2OriginPlanError> {
        let profile = resolve_origin_profile(&self.cover_family, &self.profile_version, transport)?;
        Ok(V2ServerSurfacePlan {
            transport,
            authority: self.authority.clone(),
            bind: self.bind,
            public_endpoint: self.public_endpoint.clone(),
            trust: self.trust.clone(),
            deployment_strength: self.deployment_strength,
            origin_backend: self.origin_backend.clone(),
            profile,
        })
    }
}

impl V2ClientTransportConfigDraft {
    pub fn surface_plans(&self) -> Result<Vec<V2ClientSurfacePlan>, V2OriginPlanError> {
        let mut plans = Vec::new();
        if let Some(s1) = &self.s1 {
            plans.push(s1.to_surface_plan(PublicSessionTransport::S1H2)?);
        }
        if let Some(d2) = &self.d2 {
            plans.push(d2.to_surface_plan(PublicSessionTransport::D2H3)?);
        }
        Ok(plans)
    }
}

impl V2ServerTransportConfigDraft {
    pub fn surface_plans(&self) -> Result<Vec<V2ServerSurfacePlan>, V2OriginPlanError> {
        let mut plans = Vec::new();
        if let Some(s1) = &self.s1 {
            plans.push(s1.to_surface_plan(PublicSessionTransport::S1H2)?);
        }
        if let Some(d2) = &self.d2 {
            plans.push(d2.to_surface_plan(PublicSessionTransport::D2H3)?);
        }
        Ok(plans)
    }
}

const fn default_true() -> bool {
    true
}

const fn default_d1_allowed() -> bool {
    true
}

fn resolve_origin_profile(
    family: &str,
    profile_version: &str,
    expected_transport: PublicSessionTransport,
) -> Result<OriginFamilyProfile, V2OriginPlanError> {
    let profile = OriginFamilyProfile::starter_profile(family)
        .ok_or_else(|| V2OriginPlanError::UnknownCoverFamily(family.to_string()))?;
    if profile.profile_version != profile_version {
        return Err(V2OriginPlanError::ProfileVersionMismatch {
            family: family.to_string(),
            expected: profile.profile_version,
            actual: profile_version.to_string(),
        });
    }
    if profile.transport != expected_transport {
        return Err(V2OriginPlanError::TransportMismatch {
            family: family.to_string(),
            transport: profile.transport,
            expected: expected_transport,
        });
    }
    Ok(profile)
}
