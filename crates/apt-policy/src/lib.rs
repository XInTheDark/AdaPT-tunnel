//! Policy control and local-normality bootstrap support.
//!
//! The first-cut policy layer keeps learning intentionally conservative. It uses
//! only metadata permitted by the spec, clips updates, weights tunnel traffic
//! less than ambient traffic, and exposes simple mode-transition logic.

mod controller;
mod normality;

#[cfg(test)]
mod tests;

pub use controller::PolicyController;
pub use normality::{inferred_path_profile, LocalNormalityProfile, PolicyError, ProfileSummary};
