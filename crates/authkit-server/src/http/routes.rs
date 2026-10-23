//! Health, readiness, and fallback routes.

use std::fmt;
use std::sync::Arc;

use authkit_store::SqlStore;
use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Router, middleware};
use serde_json::json;

use crate::config::Issuer;
use crate::http::request_id;
use crate::http::security_headers::{SecurityHeaders, security_headers};
use crate::http::session::{SessionSecurityState, session_context};
use crate::session::SessionService;
use crate::signing::KeyRing;

/// A readiness check that can be run without blocking the async runtime.
pub trait ReadinessProbe: Send + Sync {
    /// Returns `Ok(())` when the dependency is ready to receive traffic.
    fn check(&self) -> Result<(), ReadinessError>;
}

/// A readiness failure with no sensitive detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessError;

impl fmt::Display for ReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("readiness check failed")
    }
}

impl std::error::Error for ReadinessError {}

/// A readiness probe backed by a SQLx store.
pub struct SqlStoreReadiness {
    store: Arc<SqlStore>,
}

impl SqlStoreReadiness {
    /// Creates a probe for the given store.
    pub fn new(store: Arc<SqlStore>) -> Self {
        Self { store }
    }
}

impl ReadinessProbe for SqlStoreReadiness {
    fn check(&self) -> Result<(), ReadinessError> {
        self.store.ping().map_err(|_| ReadinessError)
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) readiness: Arc<dyn ReadinessProbe>,
    pub(crate) keys: Arc<KeyRing>,
    pub(crate) issuer: Issuer,
}

impl AppState {
    fn new(readiness: Arc<dyn ReadinessProbe>, keys: Arc<KeyRing>, issuer: Issuer) -> Self {
        Self {
            readiness,
            keys,
            issuer,
        }
    }
}

/// Builds the native server router.
///
/// This base router has no session or browser-security layers. The binary uses
/// [`router_with_sessions`]; the base router keeps metadata and health tests independent of
/// session storage.
pub fn router(readiness: Arc<dyn ReadinessProbe>, keys: Arc<KeyRing>, issuer: Issuer) -> Router {
    base_router(readiness, keys, issuer).layer(middleware::from_fn(request_id::request_context))
}

/// Builds the production router with session resolution, CSRF checks, and security headers.
pub fn router_with_sessions(
    readiness: Arc<dyn ReadinessProbe>,
    keys: Arc<KeyRing>,
    issuer: Issuer,
    sessions: Arc<SessionService>,
    hsts: bool,
) -> Router {
    with_session_security(
        base_router(readiness, keys, issuer.clone()),
        sessions,
        issuer,
        hsts,
    )
}

/// Applies session resolution, CSRF checks, security headers, and request correlation.
///
/// This is public so integration tests and alternate route sets use the same middleware
/// order as the native server.
pub fn with_session_security(
    router: Router,
    sessions: Arc<SessionService>,
    issuer: Issuer,
    hsts: bool,
) -> Router {
    let state = SessionSecurityState {
        service: sessions,
        issuer,
    };
    router
        .layer(middleware::from_fn_with_state(state, session_context))
        .layer(middleware::from_fn_with_state(
            SecurityHeaders::new(hsts),
            security_headers,
        ))
        .layer(middleware::from_fn(request_id::request_context))
}

fn base_router(readiness: Arc<dyn ReadinessProbe>, keys: Arc<KeyRing>, issuer: Issuer) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route(
            "/.well-known/openid-configuration",
            get(crate::http::metadata::openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(crate::http::metadata::oauth_authorization_server),
        )
        .route("/oauth2/jwks", get(crate::http::metadata::jwks))
        .fallback(not_found)
        .with_state(AppState::new(readiness, keys, issuer))
}

async fn health() -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"status": "ok"})),
    )
        .into_response()
}

async fn ready(State(state): State<AppState>) -> Response {
    let probe = state.readiness.clone();
    let ready = tokio::task::spawn_blocking(move || probe.check().is_ok())
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(error = %error, "readiness probe task failed");
            false
        });

    if ready {
        (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"status": "ready"})),
        )
            .into_response()
    } else {
        tracing::warn!("readiness check failed");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"status": "unavailable"})),
        )
            .into_response()
    }
}

async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": "not_found"})),
    )
        .into_response()
}
