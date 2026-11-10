//! Tenant resolution helpers: resolve an application for the current request host.

use std::sync::Arc;

use authkit_core::domain::Application;
use authkit_core::ports::ApplicationRepository;
use authkit_store::SqlStore;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tokio::task_local;

task_local! {
    static CURRENT: Option<Application>;
}

pub fn current() -> Option<Application> {
    CURRENT.try_get().ok().flatten()
}

pub async fn scope<F>(application: Option<Application>, future: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT.scope(application, future).await
}

/// Resolve an application for a host name (best-effort).
pub fn resolve_for_host<R: ApplicationRepository>(repo: &R, host: &str) -> Option<Application> {
    if host.is_empty() {
        return None;
    }
    repo.find_by_domain(host).ok().flatten()
}

pub fn resolve_for_host_arc(repo: Arc<SqlStore>, host: String) -> Option<Application> {
    resolve_for_host(repo.as_ref(), &host)
}

pub async fn tenant_middleware(
    State(store): State<Arc<SqlStore>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(':').next().unwrap_or(s).to_ascii_lowercase())
        .unwrap_or_default();
    let application = if host.is_empty() {
        None
    } else {
        let store = store.clone();
        let host = host.clone();
        tokio::task::spawn_blocking(move || resolve_for_host_arc(store, host))
            .await
            .ok()
            .flatten()
    };
    scope(application, next.run(request)).await
}

/// Derive an issuer URL for the current request, falling back to the configured issuer.
pub fn current_issuer(fallback: &str) -> String {
    if let Some(app) = current() {
        let domain = app.primary_domain();
        if !domain.is_empty() {
            return format!("https://{domain}");
        }
    }
    fallback.to_owned()
}
