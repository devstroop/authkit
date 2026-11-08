//! HTTP adapter for the native server.

pub mod account;
pub mod admin;
pub mod authorize;
pub mod home;
pub mod login;
pub mod logout;
pub mod magic_auth;
pub mod mfa;
pub mod org_selection;
pub mod organization;
pub mod passkeys;
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
    router_with_sessions_and_tokens, router_with_sessions_and_tokens_and_email,
    with_session_security,
};
pub use session::SessionContext;
