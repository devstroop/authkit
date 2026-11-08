//! Branding helpers: resolve a brand for the current request host and expose it to templates.

use std::sync::Arc;

use authkit_core::domain::Brand;
use authkit_core::ports::BrandRepository;
use authkit_store::SqlStore;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tokio::task_local;

task_local! {
    static CURRENT: Option<Brand>;
}

pub fn current() -> Option<Brand> {
    CURRENT.try_get().ok().flatten()
}

pub fn current_title(default: &str) -> String {
    current()
        .map(|b| b.title().to_owned())
        .unwrap_or_else(|| default.to_owned())
}

pub fn current_logo() -> String {
    current()
        .and_then(|b| b.logo_url().map(str::to_owned))
        .unwrap_or_default()
}

pub fn current_favicon() -> String {
    current()
        .and_then(|b| b.favicon_url().map(str::to_owned))
        .unwrap_or_default()
}

pub fn current_custom_css() -> String {
    current()
        .and_then(|b| b.custom_css().map(str::to_owned))
        .unwrap_or_default()
}

pub fn has_brand() -> bool {
    current().is_some()
}

pub async fn scope<F>(brand: Option<Brand>, future: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT.scope(brand, future).await
}

/// Resolve a brand for a host name (best-effort).
pub fn resolve_for_host<R: BrandRepository>(repo: &R, host: &str) -> Option<Brand> {
    // Try domain match first, then fall back to None.
    repo.find_by_domain(host).ok().flatten()
}

pub fn resolve_for_host_arc<R: BrandRepository + 'static>(
    repo: Arc<R>,
    host: String,
) -> Option<Brand> {
    resolve_for_host(repo.as_ref(), &host)
}

pub async fn branding_middleware(
    State(store): State<Arc<SqlStore>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(':').next().unwrap_or(s).to_owned())
        .unwrap_or_default();
    let brand = if host.is_empty() {
        None
    } else {
        resolve_for_host(store.as_ref(), &host)
    };
    scope(brand, next.run(request)).await
}
