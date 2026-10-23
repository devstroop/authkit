//! HTTP adapter for the native server.

pub mod error;
mod metadata;
mod request_id;
mod routes;

pub use error::{OAuthError, OAuthErrorCode};
pub use routes::{ReadinessError, ReadinessProbe, SqlStoreReadiness, router};
