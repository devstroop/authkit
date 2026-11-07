//! Lightweight Prometheus-style metrics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

#[derive(Default)]
pub struct Metrics {
    requests_total: AtomicU64,
    responses_2xx: AtomicU64,
    responses_4xx: AtomicU64,
    responses_5xx: AtomicU64,
    latency_ms_total: AtomicU64,
    latency_observations: AtomicU64,
}

static METRICS: OnceLock<Arc<Metrics>> = OnceLock::new();

/// Returns the process-wide metrics registry.
pub fn global() -> Arc<Metrics> {
    METRICS.get_or_init(|| Arc::new(Metrics::default())).clone()
}

/// Installs a metrics registry if one has not already been installed.
pub fn install(metrics: Arc<Metrics>) {
    let _ = METRICS.set(metrics);
}

/// Records request counts, status classes, and latency.
pub async fn middleware(request: Request, next: Next) -> Response {
    let metrics = global();
    metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed().as_millis() as u64;
    metrics.latency_ms_total.fetch_add(elapsed, Ordering::Relaxed);
    metrics.latency_observations.fetch_add(1, Ordering::Relaxed);
    match response.status().as_u16() {
        200..=299 => {
            metrics.responses_2xx.fetch_add(1, Ordering::Relaxed);
        }
        400..=499 => {
            metrics.responses_4xx.fetch_add(1, Ordering::Relaxed);
        }
        500..=599 => {
            metrics.responses_5xx.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    response
}

/// Renders the metrics in a Prometheus-compatible text format.
pub fn render() -> String {
    let metrics = global();
    format!(
        "# HELP authkit_requests_total Total HTTP requests.\\n\
         # TYPE authkit_requests_total counter\\n\
         authkit_requests_total {}\\n\
         # HELP authkit_responses_2xx Total 2xx responses.\\n\
         # TYPE authkit_responses_2xx counter\\n\
         authkit_responses_2xx {}\\n\
         # HELP authkit_responses_4xx Total 4xx responses.\\n\
         # TYPE authkit_responses_4xx counter\\n\
         authkit_responses_4xx {}\\n\
         # HELP authkit_responses_5xx Total 5xx responses.\\n\
         # TYPE authkit_responses_5xx counter\\n\
         authkit_responses_5xx {}\\n\
         # HELP authkit_request_latency_ms_total Total request latency in milliseconds.\\n\
         # TYPE authkit_request_latency_ms_total counter\\n\
         authkit_request_latency_ms_total {}\\n\
         # HELP authkit_request_latency_observations Total latency observations.\\n\
         # TYPE authkit_request_latency_observations counter\\n\
         authkit_request_latency_observations {}\\n",
        metrics.requests_total.load(Ordering::Relaxed),
        metrics.responses_2xx.load(Ordering::Relaxed),
        metrics.responses_4xx.load(Ordering::Relaxed),
        metrics.responses_5xx.load(Ordering::Relaxed),
        metrics.latency_ms_total.load(Ordering::Relaxed),
        metrics.latency_observations.load(Ordering::Relaxed),
    )
}

/// Axum handler for `/metrics`.
pub async fn handler() -> Response {
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render(),
    )
        .into_response()
}
