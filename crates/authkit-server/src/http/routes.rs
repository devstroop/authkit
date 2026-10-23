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

use crate::http::request_id;

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
    readiness: Arc<dyn ReadinessProbe>,
}

impl AppState {
    fn new(readiness: Arc<dyn ReadinessProbe>) -> Self {
        Self { readiness }
    }
}

/// Builds the native server router.
pub fn router(readiness: Arc<dyn ReadinessProbe>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .fallback(not_found)
        .with_state(AppState::new(readiness))
        .layer(middleware::from_fn(request_id::request_context))
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
