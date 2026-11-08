use std::sync::Arc;

use authkit_core::domain::id::{ApplicationEntity, Id, OAuthClientEntity, UserEntity};
use authkit_core::domain::{
    Application, ApplicationKind, ClientId, ClientType, DisplayName, Email, GrantType, Membership,
    Nonce, OAuthClient, OAuthClientSpec, Organization, PkceChallenge, RedirectUri, Scope, ScopeSet,
    SessionAudience, Slug, Timestamp, TokenEndpointAuthMethod, User,
};
use authkit_core::ports::{
    ApplicationRepository, MembershipRepository, OAuthClientRepository, OrganizationRepository,
    UserRepository,
};
use authkit_server::authorization::{AuthorizationService, ConsentMode, IssueCode};
use authkit_server::config::{Environment, Issuer, SessionConfig, SessionLifetime, TokenConfig};
use authkit_server::http::{ReadinessProbe, SqlStoreReadiness, router_with_sessions_and_tokens};
use authkit_server::session::{SessionService, SessionToken, SystemClock};
use authkit_server::signing::{KeyRing, KeyState, SigningKey, unix_now};
use authkit_server::tokens::{TokenService, hash_client_secret};
use authkit_store::SqlStore;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::form_urlencoded::Serializer;

const PEPPER: [u8; 32] = [9; 32];
const USER_ID: &str = "0000000000000001";
const ORGANIZATION_ID: &str = "0000000000000002";
const MEMBERSHIP_ID: &str = "0000000000000003";
const APPLICATION_ID: &str = "0000000000000004";
const CLIENT_ROW_ID: &str = "0000000000000005";
const CLIENT_ID: &str = "token-test-client";
const CLIENT_SECRET: &str = "token-test-secret-value";
const REDIRECT_URI: &str = "https://app.example.com/callback";
const LOGOUT_URI: &str = "https://app.example.com/logged-out";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

struct Fixture {
    store: Arc<SqlStore>,
    sessions: Arc<SessionService>,
    authorization: Arc<AuthorizationService>,
    tokens: Arc<TokenService>,
    user_id: Id<UserEntity>,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    challenge: String,
}

fn typed_id<E: authkit_core::domain::id::Entity>(value: &str) -> Id<E> {
    Id::from_suffix(value).expect("valid identifier suffix")
}

fn issuer() -> Issuer {
    Issuer::parse("https://auth.example.com", Environment::Production).expect("valid issuer")
}

fn fixture() -> Fixture {
    let store = SqlStore::sqlite_in_memory().expect("in-memory store");
    store.migrate().expect("migrated store");
    let now = Timestamp::from_millis(1_000);
    let user = User::new(
        typed_id(USER_ID),
        Email::parse("token-test@example.com").expect("valid email"),
        DisplayName::parse("Token Test").expect("valid display name"),
        now,
    );
    let organization = Organization::new(
        typed_id(ORGANIZATION_ID),
        Slug::parse("token-test").expect("valid slug"),
        DisplayName::parse("Token Test Org").expect("valid name"),
        now,
    );
    let membership = Membership::active(
        typed_id(MEMBERSHIP_ID),
        organization.id().clone(),
        user.id().clone(),
        now,
    );
    let application = Application::new(
        typed_id::<ApplicationEntity>(APPLICATION_ID),
        organization.id().clone(),
        Slug::parse("token-test-app").expect("valid slug"),
        DisplayName::parse("Token Test App").expect("valid name"),
        ApplicationKind::Web,
        true,
        now,
    );
    let secret_hash = hash_client_secret(&PEPPER, CLIENT_SECRET).expect("hashed secret");
    let client = OAuthClient::new(
        typed_id::<OAuthClientEntity>(CLIENT_ROW_ID),
        OAuthClientSpec {
            application_id: application.id().clone(),
            client_id: ClientId::parse(CLIENT_ID).expect("valid client id"),
            name: DisplayName::parse("Token Test Client").expect("valid name"),
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            secret_hash: Some(secret_hash.clone()),
            require_pkce: true,
            redirect_uris: vec![RedirectUri::parse(REDIRECT_URI).expect("valid redirect")],
            post_logout_redirect_uris: vec![
                RedirectUri::parse(LOGOUT_URI).expect("valid redirect"),
            ],
            allowed_scopes: ScopeSet::new([
                Scope::parse("openid").expect("valid scope"),
                Scope::parse("profile").expect("valid scope"),
                Scope::parse("email").expect("valid scope"),
                Scope::parse("offline_access").expect("valid scope"),
                Scope::parse("api:read").expect("valid scope"),
            ]),
            allowed_grant_types: vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
            ],
        },
        now,
    )
    .expect("valid client");

    UserRepository::insert(&store, &user).expect("inserted user");
    OrganizationRepository::insert(&store, &organization).expect("inserted organization");
    let tenant = authkit_core::domain::TenantContext::new(organization.id().clone());
    MembershipRepository::insert(&store, &tenant, &membership).expect("inserted membership");
    ApplicationRepository::insert(&store, &tenant, &application).expect("inserted application");
    OAuthClientRepository::insert(&store, &tenant, &client).expect("inserted client");

    let store = Arc::new(store);
    let config = SessionConfig::new(
        PEPPER.to_vec(),
        true,
        SessionLifetime::new(1_800, 43_200),
        SessionLifetime::new(900, 28_800),
    );
    let clock: Arc<dyn authkit_core::ports::Clock + Send + Sync> = Arc::new(SystemClock);
    let sessions = Arc::new(SessionService::new(
        store.clone(),
        config,
        Environment::Test,
        clock.clone(),
    ));
    let authorization = Arc::new(AuthorizationService::new(
        store.clone(),
        issuer(),
        clock.clone(),
    ));
    let keys = Arc::new(
        KeyRing::new(vec![
            SigningKey::generate(KeyState::Active, unix_now()).expect("active signing key"),
        ])
        .expect("valid keyring"),
    );
    let tokens = Arc::new(TokenService::new(
        store.clone(),
        issuer(),
        clock,
        keys,
        sessions.clone(),
        authorization.clone(),
        TokenConfig::new(600, 600, 2_592_000, 31_536_000, 60),
        PEPPER.to_vec(),
    ));
    let digest = Sha256::digest(VERIFIER.as_bytes());
    Fixture {
        store,
        sessions,
        authorization,
        tokens,
        user_id: user.id().clone(),
        client_id: client.client_id().clone(),
        redirect_uri: RedirectUri::parse(REDIRECT_URI).expect("valid redirect"),
        challenge: URL_SAFE_NO_PAD.encode(digest),
    }
}

async fn fixture_async() -> Fixture {
    tokio::task::spawn_blocking(fixture)
        .await
        .expect("fixture task")
}

fn app(fixture: &Fixture) -> Router {
    let readiness: Arc<dyn ReadinessProbe> =
        Arc::new(SqlStoreReadiness::new(fixture.store.clone()));
    let keys = Arc::new(
        KeyRing::new(vec![
            SigningKey::generate(KeyState::Active, unix_now()).expect("active signing key"),
        ])
        .expect("valid keyring"),
    );
    router_with_sessions_and_tokens(
        readiness,
        keys,
        issuer(),
        fixture.sessions.clone(),
        Some(fixture.authorization.clone()),
        Some(fixture.tokens.clone()),
        false,
    )
}

async fn cleanup(fixture: Fixture) {
    drop(fixture.tokens);
    drop(fixture.sessions);
    drop(fixture.authorization);
    let store = Arc::into_inner(fixture.store).expect("sole store reference");
    tokio::task::spawn_blocking(move || drop(store))
        .await
        .expect("store drop task");
}

async fn create_session(fixture: &Fixture) -> (String, String) {
    let created = fixture
        .sessions
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            Timestamp::from_millis(unix_now() * 1_000),
        )
        .await
        .expect("created session");
    (
        created.token().as_str().to_owned(),
        created.session().id().as_str().to_owned(),
    )
}

async fn issue_code(
    fixture: &Fixture,
    session_token: &str,
    scopes: &[&str],
    nonce: Option<&str>,
) -> String {
    let now = Timestamp::from_millis(unix_now() * 1_000);
    let token = SessionToken::from_cookie(session_token).expect("canonical session token");
    let sessions = fixture.sessions.clone();
    let session = sessions
        .load(&token, now)
        .await
        .expect("session load")
        .expect("session exists");
    let context = fixture
        .authorization
        .resolve_client(&fixture.client_id)
        .await
        .expect("client lookup")
        .expect("client exists");
    fixture
        .authorization
        .issue_code(IssueCode {
            context,
            user_id: fixture.user_id.clone(),
            session_id: session.id().clone(),
            auth_time: session.created_at(),
            redirect_uri: fixture.redirect_uri.clone(),
            scopes: ScopeSet::new(
                scopes
                    .iter()
                    .map(|scope| Scope::parse(*scope).expect("valid scope")),
            ),
            nonce: nonce.map(|nonce| Nonce::parse(nonce).expect("valid nonce")),
            pkce_challenge: PkceChallenge::parse(fixture.challenge.clone())
                .expect("valid challenge"),
            request_id: "issue-code".to_owned(),
            consent_mode: ConsentMode::Automatic,
        })
        .await
        .expect("issued code")
}

fn basic_header() -> String {
    let encoded = STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"));
    format!("Basic {encoded}")
}

fn token_form(pairs: &[(&str, &str)]) -> String {
    let mut form = Serializer::new(String::new());
    for (name, value) in pairs {
        form.append_pair(name, value);
    }
    form.finish()
}

async fn send(
    app: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
    body: Body,
) -> (StatusCode, HeaderMap, String) {
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
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn json(body: &str) -> Value {
    serde_json::from_str(body).expect("JSON body")
}

fn jwt_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload");
    let decoded = URL_SAFE_NO_PAD.decode(payload).expect("base64 payload");
    serde_json::from_slice(&decoded).expect("JSON payload")
}

fn jwt_header(token: &str) -> Value {
    let header = token.split('.').next().expect("JWT header");
    let decoded = URL_SAFE_NO_PAD.decode(header).expect("base64 header");
    serde_json::from_slice(&decoded).expect("JSON header")
}

async fn token_request(
    fixture: &Fixture,
    pairs: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let (status, headers, body) = send(
        app(fixture),
        Method::POST,
        "/oauth2/token",
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("authorization", basic_header()),
        ],
        Body::from(token_form(pairs)),
    )
    .await;
    let value = if body.is_empty() {
        Value::Null
    } else {
        json(&body)
    };
    (status, headers, value)
}

#[tokio::test]
async fn authorization_code_exchange_refresh_rotation_and_reuse_detection() {
    let fixture = fixture_async().await;
    let (session_token, _) = create_session(&fixture).await;
    let code = issue_code(
        &fixture,
        &session_token,
        &["openid", "profile", "email", "offline_access"],
        Some("nonce-123"),
    )
    .await;

    let (status, headers, body) = token_request(
        &fixture,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::PRAGMA], "no-cache");
    let access = body["access_token"].as_str().expect("access token");
    let id_token = body["id_token"].as_str().expect("id token");
    let refresh = body["refresh_token"].as_str().expect("refresh token");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid profile email offline_access");
    assert_eq!(jwt_header(access)["typ"], "at+jwt");
    assert_eq!(jwt_header(id_token)["typ"], "JWT");
    let access_claims = jwt_payload(access);
    assert_eq!(access_claims["sub"], fixture.user_id.as_str());
    assert_eq!(access_claims["aud"], CLIENT_ID);
    assert_eq!(access_claims["client_id"], CLIENT_ID);
    assert_eq!(
        access_claims[authkit_server::tokens::ORGANIZATION_CLAIM],
        format!("org_{ORGANIZATION_ID}")
    );
    let id_claims = jwt_payload(id_token);
    assert_eq!(id_claims["nonce"], "nonce-123");
    assert_eq!(id_claims["name"], "Token Test");
    assert_eq!(id_claims["email"], "token-test@example.com");

    let (status, _, body) = send(
        app(&fixture),
        Method::GET,
        "/oauth2/userinfo",
        &[("authorization", format!("Bearer {access}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let userinfo = json(&body);
    assert_eq!(userinfo["sub"], fixture.user_id.as_str());
    assert_eq!(userinfo["name"], "Token Test");
    assert_eq!(userinfo["email"], "token-test@example.com");

    let (status, _, body) = send(
        app(&fixture),
        Method::GET,
        "/oauth2/userinfo",
        &[("authorization", format!("Bearer {id_token}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("invalid_token"));

    let (status, _, body) = token_request(
        &fixture,
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_access = body["access_token"].as_str().expect("access token");
    let new_refresh = body["refresh_token"].as_str().expect("refresh token");
    assert_ne!(new_refresh, refresh);
    assert_eq!(
        body["id_token"]
            .as_str()
            .map(|token| jwt_payload(token)["nonce"].clone()),
        Some(Value::Null)
    );

    let (status, _, body) = token_request(
        &fixture,
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    let (status, _, body) = token_request(
        &fixture,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_refresh),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    let (status, _, _) = send(
        app(&fixture),
        Method::GET,
        "/oauth2/userinfo",
        &[("authorization", format!("Bearer {new_access}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let store = fixture.store.clone();
    let reuse = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("token.refresh.reuse")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    assert_eq!(reuse.len(), 1);

    cleanup(fixture).await;
}

#[tokio::test]
async fn reused_authorization_code_is_rejected() {
    let fixture = fixture_async().await;
    let (session_token, _) = create_session(&fixture).await;
    let code = issue_code(&fixture, &session_token, &["openid"], None).await;
    let request = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", VERIFIER),
    ];

    let (status, _, body) = token_request(&fixture, &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = token_request(&fixture, &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    cleanup(fixture).await;
}

#[tokio::test]
async fn token_endpoint_rejects_multiple_client_authentication_methods() {
    let fixture = fixture_async().await;
    let (status, _, body) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/token",
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("authorization", basic_header()),
        ],
        Body::from(token_form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_request");
    cleanup(fixture).await;
}

#[tokio::test]
async fn wrong_client_secret_is_rejected() {
    let fixture = fixture_async().await;
    let bad = STANDARD.encode(format!("{CLIENT_ID}:wrong-secret"));
    let (status, headers, body) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/token",
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("authorization", format!("Basic {bad}")),
        ],
        Body::from(token_form(&[("grant_type", "client_credentials")])),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["error"], "invalid_client");
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Basic realm=\"token\"");
    cleanup(fixture).await;
}

#[tokio::test]
async fn client_credentials_issues_no_refresh_or_id_token() {
    let fixture = fixture_async().await;
    let (status, _, body) = token_request(
        &fixture,
        &[("grant_type", "client_credentials"), ("scope", "api:read")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("id_token").is_none());
    assert_eq!(body["scope"], "api:read");
    let access = body["access_token"].as_str().expect("access token");
    let claims = jwt_payload(access);
    assert_eq!(claims["sub"], CLIENT_ID);
    assert_eq!(claims["client_id"], CLIENT_ID);

    let (status, _, _) = send(
        app(&fixture),
        Method::GET,
        "/oauth2/userinfo",
        &[("authorization", format!("Bearer {access}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    cleanup(fixture).await;
}

#[tokio::test]
async fn revocation_revokes_the_refresh_family() {
    let fixture = fixture_async().await;
    let (session_token, _) = create_session(&fixture).await;
    let code = issue_code(
        &fixture,
        &session_token,
        &["openid", "offline_access"],
        None,
    )
    .await;
    let (status, _, body) = token_request(
        &fixture,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh = body["refresh_token"].as_str().expect("refresh token");

    let (status, headers, body) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/revoke",
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("authorization", basic_header()),
        ],
        Body::from(token_form(&[
            ("token", refresh),
            ("token_type_hint", "refresh_token"),
        ])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");

    let (status, _, body) = token_request(
        &fixture,
        &[("grant_type", "refresh_token"), ("refresh_token", refresh)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    let (status, _, _) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/revoke",
        &[
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("authorization", basic_header()),
        ],
        Body::from(token_form(&[("token", "unknown-token")])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    cleanup(fixture).await;
}

#[tokio::test]
async fn logout_validates_redirect_and_revokes_the_session() {
    let fixture = fixture_async().await;
    let (session_token, _) = create_session(&fixture).await;
    let code = issue_code(
        &fixture,
        &session_token,
        &["openid", "offline_access"],
        None,
    )
    .await;
    let (status, _, body) = token_request(
        &fixture,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id_token = body["id_token"].as_str().expect("id token");

    let (status, headers, _) = send(
        app(&fixture),
        Method::GET,
        &format!(
            "/oauth2/logout?id_token_hint={id_token}&post_logout_redirect_uri={LOGOUT_URI}&state=done"
        ),
        &[("cookie", format!("authkit_session={session_token}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = headers[header::LOCATION].to_str().expect("location");
    assert!(location.starts_with(LOGOUT_URI));
    assert!(location.contains("state=done"));
    assert!(
        headers[header::SET_COOKIE]
            .to_str()
            .expect("cookie")
            .contains("Max-Age=0")
    );

    let now = Timestamp::from_millis(unix_now() * 1_000);
    let session_token = SessionToken::from_cookie(&session_token).expect("session token");
    let loaded = fixture
        .sessions
        .load(&session_token, now)
        .await
        .expect("session load");
    assert!(loaded.is_none_or(|session| !session.is_valid(now)));

    let (session_token, _) = create_session(&fixture).await;
    let (status, headers, body) = send(
        app(&fixture),
        Method::GET,
        &format!(
            "/oauth2/logout?id_token_hint={id_token}&post_logout_redirect_uri=https://evil.example/out"
        ),
        &[("cookie", format!("authkit_session={session_token}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::LOCATION).is_none());
    assert!(body.contains("Signed out"));
    cleanup(fixture).await;
}

#[tokio::test]
async fn discovery_advertises_token_endpoints_only_when_enabled() {
    let fixture = fixture_async().await;
    let (status, _, body) = send(
        app(&fixture),
        Method::GET,
        "/.well-known/openid-configuration",
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let document = json(&body);
    assert_eq!(
        document["token_endpoint"],
        "https://auth.example.com/oauth2/token"
    );
    assert_eq!(
        document["userinfo_endpoint"],
        "https://auth.example.com/oauth2/userinfo"
    );
    assert_eq!(
        document["revocation_endpoint"],
        "https://auth.example.com/oauth2/revoke"
    );
    assert_eq!(
        document["end_session_endpoint"],
        "https://auth.example.com/oauth2/logout"
    );
    assert_eq!(
        document["grant_types_supported"],
        serde_json::json!(["authorization_code", "refresh_token", "client_credentials"])
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn token_endpoint_requires_form_content_type() {
    let fixture = fixture_async().await;
    let (status, _, body) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/token",
        &[
            ("content-type", "application/json".to_owned()),
            ("authorization", basic_header()),
        ],
        Body::from("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_request");
    cleanup(fixture).await;
}

#[test]
fn client_secret_hash_round_trips() {
    let hash = hash_client_secret(&PEPPER, CLIENT_SECRET).expect("hash");
    assert!(authkit_server::tokens::verify_client_secret(
        &PEPPER,
        &hash,
        CLIENT_SECRET
    ));
    assert!(!authkit_server::tokens::verify_client_secret(
        &PEPPER, &hash, "wrong"
    ));
}
