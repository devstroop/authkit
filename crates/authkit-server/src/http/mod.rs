//! HTTP adapter for the native server.

pub mod account;
pub mod admin;
pub mod authorize;
pub mod login;
pub mod logout;
pub mod mfa;
pub mod organization;
pub mod rate_limit;
pub mod reset;
pub mod revoke;
pub mod token;
pub mod userinfo;

pub mod error;
mod metadata;
mod request_id;
mod routes;
mod security_headers;
mod session;

pub use error::{OAuthError, OAuthErrorCode};
pub use routes::{
    ReadinessError, ReadinessProbe, SqlStoreReadiness, router, router_with_sessions,
    router_with_sessions_and_tokens, with_session_security,
};
pub use session::SessionContext;
