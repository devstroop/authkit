use std::sync::Arc;

use authkit_core::domain::{DomainError, ErrorCode};
use authkit_server::http::{OAuthError, ReadinessError, ReadinessProbe, SqlStoreReadiness, router};
use authkit_store::SqlStore;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use serde_json::Value;
use tower::ServiceExt;

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn check(&self) -> Result<(), ReadinessError> {
        Ok(())
    }
}

struct AlwaysUnavailable;

impl ReadinessProbe for AlwaysUnavailable {
    fn check(&self) -> Result<(), ReadinessError> {
        Err(ReadinessError)
    }
}

async fn request(app: Router, uri: &str) -> (StatusCode, HeaderMap, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("run request");
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = serde_json::from_slice(&body).expect("parse JSON body");
    (status, headers, body)
}

#[tokio::test]
async fn healthz_is_independent_of_database_readiness() {
    let app = router(Arc::new(AlwaysUnavailable));
    let (status, headers, body) = request(app, "/healthz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn readyz_reports_ready_when_the_probe_succeeds() {
    let app = router(Arc::new(AlwaysReady));
    let (status, headers, body) = request(app, "/readyz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn readyz_returns_503_without_leaking_details() {
    let app = router(Arc::new(AlwaysUnavailable));
    let (status, headers, body) = request(app, "/readyz").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "unavailable");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn readyz_checks_a_sqlite_database() {
    let store = tokio::task::spawn_blocking(|| {
        let store = SqlStore::connect("sqlite::memory:", 5).expect("connect SQLite");
        store.migrate().expect("migrate SQLite");
        store
    })
    .await
    .expect("blocking store task");
    let store = Arc::new(store);
    let app = router(Arc::new(SqlStoreReadiness::new(store.clone())));

    let (status, _, body) = request(app, "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");

    let store = Arc::into_inner(store).expect("sole store reference");
    tokio::task::spawn_blocking(move || drop(store))
        .await
        .expect("drop store");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_connection_and_ping_when_configured() {
    let Some(url) = std::env::var("TEST_POSTGRES_URL").ok() else {
        eprintln!("skipping Postgres startup check: TEST_POSTGRES_URL is not set");
        return;
    };
    let store = tokio::task::spawn_blocking(move || {
        let store = SqlStore::connect(&url, 2).expect("connect Postgres");
        store.ping().expect("ping Postgres");
        store
    })
    .await
    .expect("blocking store task");
    tokio::task::spawn_blocking(move || drop(store))
        .await
        .expect("drop store");
}

#[tokio::test]
async fn valid_request_ids_are_echoed() {
    let app = router(Arc::new(AlwaysReady));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("x-request-id", "client-request-123")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("run request");

    assert_eq!(response.headers()["x-request-id"], "client-request-123");
}

#[tokio::test]
async fn invalid_request_ids_are_replaced() {
    let app = router(Arc::new(AlwaysReady));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("x-request-id", "not a valid id")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("run request");

    let request_id = response.headers()["x-request-id"]
        .to_str()
        .expect("ASCII request id");
    assert_ne!(request_id, "not a valid id");
    assert!(!request_id.is_empty());
}

#[tokio::test]
async fn unknown_routes_return_a_safe_404() {
    let app = router(Arc::new(AlwaysReady));
    let (status, headers, body) = request(app, "/missing").await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn oauth_errors_do_not_leak_internal_messages() {
    let error = OAuthError::from(DomainError::new(
        ErrorCode::Internal,
        "database password was rejected",
    ));
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = String::from_utf8(body.to_vec()).expect("utf-8 body");
    assert!(body.contains("server_error"));
    assert!(!body.contains("database password"));
}
