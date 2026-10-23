use std::sync::Arc;

use authkit_core::domain::id::UserEntity;
use authkit_core::domain::{DisplayName, Email, Id, SessionAudience, Timestamp, User};
use authkit_core::ports::UserRepository;
use authkit_server::config::{Environment, Issuer, SessionConfig, SessionLifetime};
use authkit_server::http::{SessionContext, with_session_security};
use authkit_server::session::{SessionService, SystemClock};
use authkit_store::SqlStore;
use axum::body::{Body, to_bytes};
use axum::extract::Extension;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use tower::ServiceExt;

const PEPPER: [u8; 32] = [7; 32];
const USER_SUFFIX: &str = "0123456789abcdef";

struct Fixture {
    store: Arc<SqlStore>,
    service: Arc<SessionService>,
    user_id: Id<UserEntity>,
}

fn fixture() -> Fixture {
    let store = SqlStore::sqlite_in_memory().expect("in-memory store");
    store.migrate().expect("migrated store");
    let user = User::new(
        Id::from_suffix(USER_SUFFIX).expect("valid user id"),
        Email::parse("session-test@example.com").expect("valid email"),
        DisplayName::parse("Session Test").expect("valid display name"),
        Timestamp::from_millis(1),
    );
    UserRepository::insert(&store, &user).expect("inserted user");
    let config = SessionConfig::new(
        PEPPER.to_vec(),
        true,
        SessionLifetime::new(1_800, 43_200),
        SessionLifetime::new(900, 28_800),
    );
    let store = Arc::new(store);
    let service = Arc::new(SessionService::new(
        store.clone(),
        config,
        Environment::Test,
        Arc::new(SystemClock),
    ));
    Fixture {
        store,
        service,
        user_id: user.id().clone(),
    }
}

async fn fixture_async() -> Fixture {
    tokio::task::spawn_blocking(fixture)
        .await
        .expect("fixture task")
}

async fn cleanup(fixture: Fixture) {
    drop(fixture.service);
    let store = Arc::into_inner(fixture.store).expect("sole store reference");
    tokio::task::spawn_blocking(move || drop(store))
        .await
        .expect("store drop task");
}

fn issuer() -> Issuer {
    Issuer::parse("https://auth.example.com", Environment::Production).expect("valid issuer")
}

async fn optional_session(session: Option<Extension<SessionContext>>) -> Response {
    match session {
        Some(Extension(context)) => Json(json!({
            "session": context.session().id().as_str(),
            "csrf": context.csrf_token(),
        }))
        .into_response(),
        None => Json(json!({"session": null})).into_response(),
    }
}

async fn echo_session(Extension(context): Extension<SessionContext>, body: Body) -> Response {
    let body = to_bytes(body, usize::MAX).await.expect("read body");
    Json(json!({
        "session": context.session().id().as_str(),
        "body_len": body.len(),
    }))
    .into_response()
}

async fn set_session_cookie() -> Response {
    (
        [(header::SET_COOKIE, "authkit_session=fresh; Path=/")],
        "ok",
    )
        .into_response()
}

fn test_app(service: Arc<SessionService>) -> Router {
    with_session_security(
        Router::new()
            .route("/secure", get(optional_session).post(echo_session))
            .route("/admin/secure", get(optional_session).post(echo_session))
            .route("/handoff", get(set_session_cookie)),
        service,
        issuer(),
        false,
    )
}

async fn send(
    app: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
    body: Body,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = app
        .oneshot(request.body(body).expect("build request"))
        .await
        .expect("run request");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response");
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, headers, body)
}

fn cookie_headers(name: &str, token: &str) -> Vec<(&'static str, String)> {
    vec![("cookie", format!("{name}={token}"))]
}

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn session_cookie_resolves_and_adds_browser_headers() {
    let fixture = fixture_async().await;
    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let app = test_app(fixture.service.clone());

    let (status, headers, body) = send(
        app,
        Method::GET,
        "/secure",
        &cookie_headers("authkit_session", created.token().as_str()),
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session"], created.session().id().as_str());
    assert_eq!(body["csrf"], fixture.service.csrf_token(created.session()));
    let cookies = set_cookies(&headers);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("authkit_session="))
    );
    assert!(cookies.iter().any(|cookie| cookie.contains("HttpOnly")));
    assert!(cookies.iter().any(|cookie| cookie.contains("SameSite=Lax")));
    assert_eq!(headers[header::VARY], "Cookie");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));

    cleanup(fixture).await;
}

#[tokio::test]
async fn unsafe_requests_require_a_valid_csrf_token_and_same_origin() {
    let fixture = fixture_async().await;
    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let csrf = fixture.service.csrf_token(created.session());
    let mut headers = cookie_headers("authkit_session", created.token().as_str());
    headers.push(("origin", "https://auth.example.com".to_owned()));

    let app = test_app(fixture.service.clone());
    let (status, _, body) = send(
        app.clone(),
        Method::POST,
        "/secure",
        &headers,
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "csrf_rejected");

    let store = fixture.store.clone();
    let events = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("security.csrf_rejected")
    })
    .await
    .expect("audit query task")
    .expect("audit query");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].actor(),
        &authkit_core::domain::AuditActor::User(fixture.user_id.clone())
    );
    assert_eq!(events[0].attributes()[0].key(), "request_id");
    assert_eq!(events[0].attributes()[3].value(), "invalid_csrf");

    let mut with_csrf = headers.clone();
    with_csrf.push(("x-csrf-token", csrf));
    let (status, _, body) = send(
        app.clone(),
        Method::POST,
        "/secure",
        &with_csrf,
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session"], created.session().id().as_str());

    let mut cross_origin = with_csrf.clone();
    cross_origin.retain(|(name, _)| *name != "origin");
    cross_origin.push(("origin", "https://evil.example".to_owned()));
    let (status, _, body) = send(app, Method::POST, "/secure", &cross_origin, Body::empty()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "csrf_rejected");

    let store = fixture.store.clone();
    let events = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("security.csrf_rejected")
    })
    .await
    .expect("audit query task")
    .expect("audit query");
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .any(|event| event.attributes().iter().any(|attribute| {
                attribute.key() == "reason" && attribute.value() == "origin_mismatch"
            }))
    );

    cleanup(fixture).await;
}

#[tokio::test]
async fn form_csrf_is_accepted_and_the_body_is_preserved() {
    let fixture = fixture_async().await;
    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let csrf = fixture.service.csrf_token(created.session());
    let body = format!("_csrf={csrf}&message=hello");
    let mut headers = cookie_headers("authkit_session", created.token().as_str());
    headers.push(("origin", "https://auth.example.com".to_owned()));
    headers.push((
        "content-type",
        "application/x-www-form-urlencoded".to_owned(),
    ));

    let app = test_app(fixture.service.clone());
    let (status, _, response) = send(
        app,
        Method::POST,
        "/secure",
        &headers,
        Body::from(body.clone()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["body_len"], body.len());

    cleanup(fixture).await;
}

#[tokio::test]
async fn invalid_cookies_are_cleared_and_fail_closed_for_unsafe_methods() {
    let fixture = fixture_async().await;
    let app = test_app(fixture.service.clone());

    let (status, headers, body) = send(
        app.clone(),
        Method::GET,
        "/secure",
        &cookie_headers("authkit_session", "not-a-token"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session"], Value::Null);
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|cookie| cookie.contains("Max-Age=0"))
    );

    let mut headers = cookie_headers("authkit_session", "not-a-token");
    headers.push(("origin", "https://auth.example.com".to_owned()));
    let (status, headers, body) = send(app, Method::POST, "/secure", &headers, Body::empty()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthenticated");
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|cookie| cookie.contains("Max-Age=0"))
    );

    cleanup(fixture).await;
}

#[tokio::test]
async fn handlers_can_replace_the_session_cookie() {
    let fixture = fixture_async().await;
    let app = test_app(fixture.service.clone());

    let (status, headers, _) = send(
        app.clone(),
        Method::GET,
        "/handoff",
        &cookie_headers("authkit_session", "not-a-token"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cookies = set_cookies(&headers);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].starts_with("authkit_session=fresh"));
    assert!(!cookies[0].contains("Max-Age=0"));

    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let (status, headers, _) = send(
        app,
        Method::GET,
        "/handoff",
        &cookie_headers("authkit_session", created.token().as_str()),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cookies = set_cookies(&headers);
    assert_eq!(cookies.len(), 1);
    assert!(cookies[0].starts_with("authkit_session=fresh"));

    cleanup(fixture).await;
}

#[tokio::test]
async fn admin_routes_use_only_the_strict_admin_cookie() {
    let fixture = fixture_async().await;
    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Admin,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let app = test_app(fixture.service.clone());

    let (status, headers, body) = send(
        app.clone(),
        Method::GET,
        "/admin/secure",
        &cookie_headers("authkit_admin_session", created.token().as_str()),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session"], created.session().id().as_str());
    assert!(
        set_cookies(&headers)
            .iter()
            .any(|cookie| cookie.contains("SameSite=Strict"))
    );

    let (status, _, body) = send(
        app,
        Method::GET,
        "/admin/secure",
        &cookie_headers("authkit_session", created.token().as_str()),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session"], Value::Null);

    cleanup(fixture).await;
}

#[tokio::test]
async fn state_changing_routes_are_not_reachable_with_get() {
    let fixture = fixture_async().await;
    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let app = with_session_security(
        Router::new().route(
            "/mutate",
            axum::routing::post(|| async { StatusCode::NO_CONTENT }),
        ),
        fixture.service.clone(),
        issuer(),
        false,
    );
    let (status, _, _) = send(
        app,
        Method::GET,
        "/mutate",
        &cookie_headers("authkit_session", created.token().as_str()),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    cleanup(fixture).await;
}

#[tokio::test]
async fn oauth_protocol_posts_are_not_subject_to_cookie_csrf() {
    let fixture = fixture_async().await;
    let created = fixture
        .service
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.service.clock().now(),
        )
        .await
        .expect("created session");
    let app = with_session_security(
        Router::new().route(
            "/oauth2/token",
            axum::routing::post(|| async { StatusCode::OK }),
        ),
        fixture.service.clone(),
        issuer(),
        false,
    );
    let (status, _, _) = send(
        app.clone(),
        Method::POST,
        "/oauth2/token",
        &cookie_headers("authkit_session", created.token().as_str()),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = send(
        app,
        Method::POST,
        "/oauth2/token",
        &cookie_headers("authkit_session", "not-a-token"),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    cleanup(fixture).await;
}

#[tokio::test]
async fn security_headers_are_applied_to_unrelated_routes() {
    let fixture = fixture_async().await;
    let app = with_session_security(
        Router::new().route("/healthz", get(|| async { "ok" })),
        fixture.service.clone(),
        issuer(),
        true,
    );
    let (status, headers, _) = send(app, Method::GET, "/healthz", &[], Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
    assert_eq!(
        headers[header::STRICT_TRANSPORT_SECURITY],
        "max-age=31536000"
    );

    cleanup(fixture).await;
}
