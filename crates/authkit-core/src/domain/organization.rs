//! Organization compatibility shim.
//!
//! Organizations are removed in favour of applications as tenants (ADR-0011).
//! This module re-exports [`Application`] under the legacy name so that the rest of the
//! codebase can migrate incrementally. New code must use [`Application`] directly.

pub use crate::domain::application::Application as Organization;
pub use crate::domain::application::ApplicationStatus as OrganizationStatus;
