use std::sync::Arc;

use authkit_core::domain::{DomainError, ErrorCode};
use authkit_server::config::{Environment, Issuer};
use authkit_server::http::{OAuthError, ReadinessError, ReadinessProbe, SqlStoreReadiness, router};
use authkit_server::signing::{KeyRing, KeyState, SigningKey};
use authkit_store::SqlStore;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use serde_json::Value;
use tower::ServiceExt;

fn test_issuer() -> Issuer {
    Issuer::parse("https://auth.example.com", Environment::Production).expect("valid issuer")
}

fn test_keys() -> Arc<KeyRing> {
    let active = SigningKey::generate(KeyState::Active, 1_000).expect("generate active key");
    Arc::new(KeyRing::new(vec![active]).expect("valid keyring"))
}

fn app(readiness: Arc<dyn ReadinessProbe>) -> Router {
    router(readiness, test_keys(), test_issuer())
}

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

async fn request_with_headers(
    app: Router,
    uri: &str,
    request_headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder().uri(uri);
    for (name, value) in request_headers {
        request = request.header(*name, *value);
    }
    let response = app
        .oneshot(request.body(Body::empty()).expect("build request"))
        .await
        .expect("run request");
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body")
        .to_vec();
    (status, headers, body)
}

async fn request(app: Router, uri: &str) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, body) = request_with_headers(app, uri, &[]).await;
    let body = serde_json::from_slice(&body).expect("parse JSON body");
    (status, headers, body)
}

#[tokio::test]
async fn healthz_is_independent_of_database_readiness() {
    let app = app(Arc::new(AlwaysUnavailable));
    let (status, headers, body) = request(app, "/healthz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn readyz_reports_ready_when_the_probe_succeeds() {
    let app = app(Arc::new(AlwaysReady));
    let (status, headers, body) = request(app, "/readyz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn readyz_returns_503_without_leaking_details() {
    let app = app(Arc::new(AlwaysUnavailable));
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
    let app = app(Arc::new(SqlStoreReadiness::new(store.clone())));

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
async fn discovery_documents_match_and_omit_unimplemented_endpoints() {
    let app = app(Arc::new(AlwaysReady));
    let (status, headers, oidc) = request(app.clone(), "/.well-known/openid-configuration").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(oidc["issuer"], "https://auth.example.com");
    assert_eq!(oidc["jwks_uri"], "https://auth.example.com/oauth2/jwks");
    assert_eq!(oidc["id_token_signing_alg_values_supported"][0], "ES256");
    for unimplemented in [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "revocation_endpoint",
        "end_session_endpoint",
        "registration_endpoint",
    ] {
        assert!(oidc.get(unimplemented).is_none());
    }
    assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=300");
    assert!(headers.contains_key(header::ETAG));

    let (status, _, oauth) = request(app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(oidc, oauth);
}

#[tokio::test]
async fn jwks_publishes_only_current_public_keys() {
    let now = 1_700_000_000;
    let active = SigningKey::generate(KeyState::Active, now).expect("active key");
    let next = SigningKey::generate(KeyState::Next, now).expect("next key");
    let retired = SigningKey::generate(KeyState::Retired, now)
        .expect("retired key")
        .with_publish_until(Some(u64::MAX));
    let expired = SigningKey::generate(KeyState::Retired, now)
        .expect("expired key")
        .with_publish_until(Some(0));
    let compromised = SigningKey::generate(KeyState::Compromised, now).expect("compromised key");
    let keys = Arc::new(
        KeyRing::new(vec![active, next, retired, expired, compromised]).expect("valid keyring"),
    );
    let app = router(Arc::new(AlwaysReady), keys, test_issuer());

    let (status, headers, body) = request(app, "/oauth2/jwks").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "public, max-age=300");
    let keys = body["keys"].as_array().expect("JWKS keys");
    assert_eq!(keys.len(), 3);
    for key in keys {
        assert!(key.get("d").is_none());
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert!(key["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
    }
}

#[tokio::test]
async fn metadata_supports_etag_revalidation() {
    let app = app(Arc::new(AlwaysReady));
    let path = "/.well-known/openid-configuration";
    let (status, headers, body) = request_with_headers(app.clone(), path, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.is_empty());
    let etag = headers[header::ETAG].to_str().expect("ETag").to_owned();

    let (status, headers, body) =
        request_with_headers(app, path, &[("if-none-match", &etag)]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(headers[header::ETAG], etag);
}

#[tokio::test]
async fn valid_request_ids_are_echoed() {
    let app = app(Arc::new(AlwaysReady));
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
    let app = app(Arc::new(AlwaysReady));
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
    let app = app(Arc::new(AlwaysReady));
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
