use std::sync::Arc;

use authkit_core::domain::id::{ApplicationEntity, Id, OAuthClientEntity, UserEntity};
use authkit_core::domain::{
    Application, ApplicationKind, ClientId, ClientType, DisplayName, Email, GrantType, Membership,
    OAuthClient, OAuthClientSpec, Organization, RedirectUri, Scope, ScopeSet, SessionAudience,
    Slug, Timestamp, TokenEndpointAuthMethod, User,
};
use authkit_core::ports::{
    ApplicationRepository, MembershipRepository, OAuthClientRepository, OrganizationRepository,
    UserRepository,
};
use authkit_server::authorization::{AuthorizationService, RedeemCode};
use authkit_server::config::{Environment, Issuer, SessionConfig, SessionLifetime};
use authkit_server::http::{ReadinessProbe, SqlStoreReadiness, router_with_sessions};
use authkit_server::session::{SessionService, SystemClock};
use authkit_server::signing::{KeyRing, KeyState, SigningKey};
use authkit_store::SqlStore;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use url::form_urlencoded::Serializer;

const PEPPER: [u8; 32] = [9; 32];
const USER_ID: &str = "0000000000000001";
const ORGANIZATION_ID: &str = "0000000000000002";
const MEMBERSHIP_ID: &str = "0000000000000003";
const APPLICATION_ID: &str = "0000000000000004";
const CLIENT_ROW_ID: &str = "0000000000000005";
const CLIENT_ID: &str = "authorization-test-client";
const REDIRECT_URI: &str = "https://app.example.com/callback";
const STATE: &str = "state-123";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

struct Fixture {
    store: Arc<SqlStore>,
    sessions: Arc<SessionService>,
    authorization: Arc<AuthorizationService>,
    user_id: Id<UserEntity>,
    client_id: ClientId,
    redirect_uri: RedirectUri,
    challenge: String,
}

fn typed_id<E: authkit_core::domain::id::Entity>(value: &str) -> Id<E> {
    Id::from_suffix(value).expect("valid identifier suffix")
}

fn fixture(first_party: bool) -> Fixture {
    let store = SqlStore::sqlite_in_memory().expect("in-memory store");
    store.migrate().expect("migrated store");
    let now = Timestamp::from_millis(1_000);
    let user = User::new(
        typed_id(USER_ID),
        Email::parse("authorize-test@example.com").expect("valid email"),
        DisplayName::parse("Authorize Test").expect("valid display name"),
        now,
    );
    let organization = Organization::new(
        typed_id(ORGANIZATION_ID),
        Slug::parse("authorize-test").expect("valid slug"),
        DisplayName::parse("Authorize Test Org").expect("valid name"),
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
        Slug::parse("authorize-test-app").expect("valid slug"),
        DisplayName::parse("Authorize Test App").expect("valid name"),
        ApplicationKind::Web,
        first_party,
        now,
    );
    let client = OAuthClient::new(
        typed_id::<OAuthClientEntity>(CLIENT_ROW_ID),
        OAuthClientSpec {
            application_id: application.id().clone(),
            client_id: ClientId::parse(CLIENT_ID).expect("valid client id"),
            name: DisplayName::parse("Authorize Test Client").expect("valid name"),
            client_type: ClientType::Public,
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            secret_hash: None,
            require_pkce: true,
            redirect_uris: vec![RedirectUri::parse(REDIRECT_URI).expect("valid redirect")],
            post_logout_redirect_uris: Vec::new(),
            allowed_scopes: ScopeSet::new([
                Scope::parse("openid").expect("valid scope"),
                Scope::parse("profile").expect("valid scope"),
                Scope::parse("email").expect("valid scope"),
            ]),
            allowed_grant_types: vec![GrantType::AuthorizationCode],
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
    let sessions = Arc::new(SessionService::new(
        store.clone(),
        config,
        Environment::Test,
        Arc::new(SystemClock),
    ));
    let authorization = Arc::new(AuthorizationService::new(
        store.clone(),
        issuer(),
        Arc::new(SystemClock),
    ));
    let digest = Sha256::digest(VERIFIER.as_bytes());
    Fixture {
        store,
        sessions,
        authorization,
        user_id: user.id().clone(),
        client_id: client.client_id().clone(),
        redirect_uri: RedirectUri::parse(REDIRECT_URI).expect("valid redirect"),
        challenge: URL_SAFE_NO_PAD.encode(digest),
    }
}

async fn fixture_async(first_party: bool) -> Fixture {
    tokio::task::spawn_blocking(move || fixture(first_party))
        .await
        .expect("fixture task")
}

fn issuer() -> Issuer {
    Issuer::parse("https://auth.example.com", Environment::Production).expect("valid issuer")
}

fn app(fixture: &Fixture) -> Router {
    let readiness: Arc<dyn ReadinessProbe> =
        Arc::new(SqlStoreReadiness::new(fixture.store.clone()));
    let keys = Arc::new(
        KeyRing::new(vec![
            SigningKey::generate(KeyState::Active, 1_000).expect("active signing key"),
        ])
        .expect("valid keyring"),
    );
    router_with_sessions(
        readiness,
        keys,
        issuer(),
        fixture.sessions.clone(),
        Some(fixture.authorization.clone()),
        false,
    )
}

async fn session_cookie(fixture: &Fixture) -> (String, String) {
    let created = fixture
        .sessions
        .create(
            fixture.user_id.clone(),
            None,
            SessionAudience::Account,
            fixture.sessions.clock().now(),
        )
        .await
        .expect("created session");
    let csrf = fixture.sessions.csrf_token(created.session());
    (created.token().as_str().to_owned(), csrf)
}

fn authorize_query(
    fixture: &Fixture,
    redirect_uri: &str,
    method: &str,
    extra: &[(&str, &str)],
) -> String {
    authorize_query_with_scope(fixture, redirect_uri, "profile email", method, extra)
}

fn authorize_query_with_scope(
    fixture: &Fixture,
    redirect_uri: &str,
    scope: &str,
    method: &str,
    extra: &[(&str, &str)],
) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("client_id", fixture.client_id.as_str());
    query.append_pair("redirect_uri", redirect_uri);
    query.append_pair("response_type", "code");
    query.append_pair("scope", scope);
    query.append_pair("state", STATE);
    query.append_pair("code_challenge", &fixture.challenge);
    query.append_pair("code_challenge_method", method);
    for (name, value) in extra {
        query.append_pair(name, value);
    }
    query.finish()
}

fn consent_form(fixture: &Fixture, csrf: &str, decision: &str) -> String {
    let mut form = Serializer::new(String::new());
    form.append_pair("_csrf", csrf);
    form.append_pair("client_id", fixture.client_id.as_str());
    form.append_pair("redirect_uri", fixture.redirect_uri.as_str());
    form.append_pair("response_type", "code");
    form.append_pair("scope", "profile email");
    form.append_pair("state", STATE);

    form.append_pair("code_challenge", &fixture.challenge);
    form.append_pair("code_challenge_method", "S256");
    form.append_pair("decision", decision);
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

fn location(headers: &HeaderMap) -> url::Url {
    url::Url::parse(
        headers
            .get(header::LOCATION)
            .expect("location header")
            .to_str()
            .expect("valid location"),
    )
    .expect("valid redirect URL")
}

fn attribute<'a>(event: &'a authkit_core::domain::AuditEvent, key: &str) -> Option<&'a str> {
    event
        .attributes()
        .iter()
        .find(|attribute| attribute.key() == key)
        .map(authkit_core::domain::AuditAttribute::value)
}

async fn cleanup(fixture: Fixture) {
    drop(fixture.sessions);
    drop(fixture.authorization);
    let store = Arc::into_inner(fixture.store).expect("sole store reference");
    tokio::task::spawn_blocking(move || drop(store))
        .await
        .expect("store drop task");
}

#[tokio::test]
async fn discovery_advertises_authorization_endpoint() {
    let fixture = fixture_async(false).await;
    let (status, _, body) = send(
        app(&fixture),
        Method::GET,
        "/.well-known/openid-configuration",
        &[],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let document: serde_json::Value = serde_json::from_str(&body).expect("discovery JSON");
    assert_eq!(
        document["authorization_endpoint"],
        "https://auth.example.com/oauth2/authorize"
    );
    assert_eq!(
        document["response_types_supported"],
        serde_json::json!(["code"])
    );
    assert_eq!(
        document["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        document["subject_types_supported"],
        serde_json::json!(["public"])
    );
    assert_eq!(document["claims_parameter_supported"], false);
    assert_eq!(document["request_parameter_supported"], false);
    assert_eq!(document["request_uri_parameter_supported"], false);
    cleanup(fixture).await;
}

#[tokio::test]
async fn rejects_unregistered_redirect_uri_without_redirecting() {
    let fixture = fixture_async(false).await;
    let query = authorize_query(&fixture, "https://evil.example/callback", "S256", &[]);
    let (status, headers, body) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::LOCATION).is_none());
    assert!(body.contains("not registered"));
    cleanup(fixture).await;
}

#[tokio::test]
async fn third_party_consent_issues_code_and_replay_fails() {
    let fixture = fixture_async(false).await;
    let (token, csrf) = session_cookie(&fixture).await;
    let query = authorize_query(&fixture, fixture.redirect_uri.as_str(), "S256", &[]);
    let cookie = vec![("cookie", format!("authkit_session={token}"))];

    let (status, headers, body) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &cookie,
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Allow access"));
    assert!(headers.get(header::LOCATION).is_none());

    let form = consent_form(&fixture, &csrf, "allow");
    let mut headers = cookie.clone();
    headers.push((
        "content-type",
        "application/x-www-form-urlencoded".to_owned(),
    ));
    headers.push(("origin", "https://auth.example.com".to_owned()));
    let (status, headers, _) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/authorize/consent",
        &headers,
        Body::from(form),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let redirect = location(&headers);
    let pairs = redirect.query_pairs().collect::<Vec<_>>();
    let code = pairs
        .iter()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.to_string())
        .expect("authorization code");
    assert_eq!(
        pairs
            .iter()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.as_ref()),
        Some(STATE)
    );

    let redeemed = fixture
        .authorization
        .redeem_code(RedeemCode {
            client_id: fixture.client_id.clone(),
            code: code.clone(),
            redirect_uri: fixture.redirect_uri.clone(),
            code_verifier: VERIFIER.to_owned(),
            request_id: "redeem-1".to_owned(),
        })
        .await
        .expect("redeemed code");
    assert_eq!(redeemed.user_id(), &fixture.user_id);

    let replay = fixture
        .authorization
        .redeem_code(RedeemCode {
            client_id: fixture.client_id.clone(),
            code,
            redirect_uri: fixture.redirect_uri.clone(),
            code_verifier: VERIFIER.to_owned(),
            request_id: "redeem-2".to_owned(),
        })
        .await;
    assert_eq!(
        replay,
        Err(authkit_server::authorization::RedeemError::InvalidGrant)
    );

    let store = fixture.store.clone();
    let issued = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("authorization.code.issue")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    assert_eq!(issued.len(), 1);

    let store = fixture.store.clone();
    let rejections = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("authorization.request.reject")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    assert!(
        rejections
            .iter()
            .any(|event| attribute(event, "reason") == Some("code_replay"))
    );

    let store = fixture.store.clone();
    let grants = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("authorization.consent.grant")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    assert_eq!(grants.len(), 1);
    assert_eq!(attribute(&grants[0], "consent"), Some("explicit"));

    cleanup(fixture).await;
}

#[tokio::test]
async fn first_party_client_skips_consent() {
    let fixture = fixture_async(true).await;
    let (token, _) = session_cookie(&fixture).await;
    let query = authorize_query(&fixture, fixture.redirect_uri.as_str(), "S256", &[]);
    let (status, headers, body) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[("cookie", format!("authkit_session={token}"))],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(body.is_empty());
    assert!(
        location(&headers)
            .query_pairs()
            .any(|(name, _)| name == "code")
    );

    let store = fixture.store.clone();
    let grants = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("authorization.consent.grant")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    assert_eq!(grants.len(), 1);
    assert_eq!(attribute(&grants[0], "consent"), Some("automatic"));
    cleanup(fixture).await;
}

#[tokio::test]
async fn first_party_prompt_consent_still_renders() {
    let fixture = fixture_async(true).await;
    let (token, _) = session_cookie(&fixture).await;
    let query = authorize_query(
        &fixture,
        fixture.redirect_uri.as_str(),
        "S256",
        &[("prompt", "consent")],
    );
    let (status, headers, body) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[("cookie", format!("authkit_session={token}"))],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::LOCATION).is_none());
    assert!(body.contains("Allow access"));
    cleanup(fixture).await;
}

#[tokio::test]
async fn redemption_rejects_wrong_verifier_and_redirect_without_consuming() {
    let fixture = fixture_async(true).await;
    let (token, _) = session_cookie(&fixture).await;
    let query = authorize_query(&fixture, fixture.redirect_uri.as_str(), "S256", &[]);
    let (status, headers, _) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[("cookie", format!("authkit_session={token}"))],
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let code = location(&headers)
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.into_owned())
        .expect("authorization code");

    let wrong_verifier = fixture
        .authorization
        .redeem_code(RedeemCode {
            client_id: fixture.client_id.clone(),
            code: code.clone(),
            redirect_uri: fixture.redirect_uri.clone(),
            code_verifier: format!("{VERIFIER}x"),
            request_id: "wrong-verifier".to_owned(),
        })
        .await;
    assert_eq!(
        wrong_verifier,
        Err(authkit_server::authorization::RedeemError::InvalidGrant)
    );

    let wrong_redirect =
        RedirectUri::parse("https://app.example.com/other").expect("valid redirect");
    let wrong_redirect_result = fixture
        .authorization
        .redeem_code(RedeemCode {
            client_id: fixture.client_id.clone(),
            code: code.clone(),
            redirect_uri: wrong_redirect,
            code_verifier: VERIFIER.to_owned(),
            request_id: "wrong-redirect".to_owned(),
        })
        .await;
    assert_eq!(
        wrong_redirect_result,
        Err(authkit_server::authorization::RedeemError::InvalidGrant)
    );

    let second_client = OAuthClient::new(
        typed_id::<OAuthClientEntity>("0000000000000006"),
        OAuthClientSpec {
            application_id: typed_id::<ApplicationEntity>(APPLICATION_ID),
            client_id: ClientId::parse("authorization-test-client-2").expect("valid client id"),
            name: DisplayName::parse("Second Client").expect("valid name"),
            client_type: ClientType::Public,
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            secret_hash: None,
            require_pkce: true,
            redirect_uris: vec![RedirectUri::parse(REDIRECT_URI).expect("valid redirect")],
            post_logout_redirect_uris: Vec::new(),
            allowed_scopes: ScopeSet::new([
                Scope::parse("profile").expect("valid scope"),
                Scope::parse("email").expect("valid scope"),
            ]),
            allowed_grant_types: vec![GrantType::AuthorizationCode],
        },
        Timestamp::from_millis(1_000),
    )
    .expect("valid second client");
    let second_client_id = second_client.client_id().clone();
    let store = fixture.store.clone();
    let tenant = authkit_core::domain::TenantContext::new(typed_id(ORGANIZATION_ID));
    tokio::task::spawn_blocking(move || {
        OAuthClientRepository::insert(&*store, &tenant, &second_client)
    })
    .await
    .expect("insert task")
    .expect("insert second client");

    let wrong_client = fixture
        .authorization
        .redeem_code(RedeemCode {
            client_id: second_client_id,
            code: code.clone(),
            redirect_uri: fixture.redirect_uri.clone(),
            code_verifier: VERIFIER.to_owned(),
            request_id: "wrong-client".to_owned(),
        })
        .await;
    assert_eq!(
        wrong_client,
        Err(authkit_server::authorization::RedeemError::InvalidGrant)
    );

    let redeemed = fixture
        .authorization
        .redeem_code(RedeemCode {
            client_id: fixture.client_id.clone(),
            code,
            redirect_uri: fixture.redirect_uri.clone(),
            code_verifier: VERIFIER.to_owned(),
            request_id: "correct-verifier".to_owned(),
        })
        .await;
    assert!(redeemed.is_ok(), "failures must not consume the code");

    let store = fixture.store.clone();
    let rejections = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("authorization.request.reject")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    let reasons = rejections
        .iter()
        .filter_map(|event| attribute(event, "reason"))
        .collect::<Vec<_>>();
    assert!(reasons.contains(&"pkce_mismatch"));
    assert!(reasons.contains(&"wrong_redirect_uri"));
    assert!(reasons.contains(&"wrong_client"));

    cleanup(fixture).await;
}

#[tokio::test]
async fn openid_requests_require_nonce() {
    let fixture = fixture_async(false).await;
    let query = authorize_query_with_scope(
        &fixture,
        fixture.redirect_uri.as_str(),
        "openid profile",
        "S256",
        &[],
    );
    let (status, headers, _) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    let redirect = location(&headers);
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "error")
            .map(|(_, value)| value.into_owned()),
        Some("invalid_request".to_owned())
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn rejects_unsupported_security_parameters() {
    let fixture = fixture_async(false).await;
    let (token, _) = session_cookie(&fixture).await;
    let cookie = vec![("cookie", format!("authkit_session={token}"))];

    for (name, value) in [
        ("claims", "{}"),
        ("acr_values", "urn:mace:incommon:iap:silver"),
        ("resource", "https://api.example.com"),
    ] {
        let query = authorize_query(
            &fixture,
            fixture.redirect_uri.as_str(),
            "S256",
            &[(name, value)],
        );
        let (status, headers, _) = send(
            app(&fixture),
            Method::GET,
            &format!("/oauth2/authorize?{query}"),
            &cookie,
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{name}");
        let redirect = location(&headers);
        assert_eq!(
            redirect
                .query_pairs()
                .find(|(key, _)| key == "error")
                .map(|(_, value)| value.into_owned()),
            Some("invalid_request".to_owned()),
            "{name}"
        );
    }
    cleanup(fixture).await;
}

#[tokio::test]
async fn requires_s256_pkce() {
    let fixture = fixture_async(false).await;
    let query = authorize_query(&fixture, fixture.redirect_uri.as_str(), "plain", &[]);
    let (status, headers, _) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    let redirect = location(&headers);
    let pairs = redirect.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        pairs
            .iter()
            .find(|(name, _)| name == "error")
            .map(|(_, value)| value.as_ref()),
        Some("invalid_request")
    );
    assert_eq!(
        pairs
            .iter()
            .find(|(name, _)| name == "state")
            .map(|(_, value)| value.as_ref()),
        Some(STATE)
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn prompt_none_without_consent_redirects_consent_required() {
    let fixture = fixture_async(false).await;
    let (token, _) = session_cookie(&fixture).await;
    let query = authorize_query(
        &fixture,
        fixture.redirect_uri.as_str(),
        "S256",
        &[("prompt", "none")],
    );
    let (status, headers, _) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[("cookie", format!("authkit_session={token}"))],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    let redirect = location(&headers);
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "error")
            .map(|(_, value)| value.into_owned()),
        Some("consent_required".to_owned())
    );
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned()),
        Some(STATE.to_owned())
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn prompt_none_without_session_redirects_login_required() {
    let fixture = fixture_async(false).await;
    let query = authorize_query(
        &fixture,
        fixture.redirect_uri.as_str(),
        "S256",
        &[("prompt", "none")],
    );
    let (status, headers, _) = send(
        app(&fixture),
        Method::GET,
        &format!("/oauth2/authorize?{query}"),
        &[],
        Body::empty(),
    )
    .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location(&headers)
            .query_pairs()
            .find(|(name, _)| name == "error")
            .map(|(_, value)| value.into_owned()),
        Some("login_required".to_owned())
    );
    cleanup(fixture).await;
}

#[tokio::test]
async fn consent_post_requires_csrf_and_same_origin() {
    let fixture = fixture_async(false).await;
    let (token, csrf) = session_cookie(&fixture).await;
    let form = consent_form(&fixture, &csrf, "allow").replacen(&format!("_csrf={csrf}&"), "", 1);
    let (status, headers, _) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/authorize/consent",
        &[
            ("cookie", format!("authkit_session={token}")),
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("origin", "https://auth.example.com".to_owned()),
        ],
        Body::from(form),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(headers.get(header::LOCATION).is_none());

    let form = consent_form(&fixture, &csrf, "allow");
    let (status, _, _) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/authorize/consent",
        &[
            ("cookie", format!("authkit_session={token}")),
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("origin", "https://evil.example".to_owned()),
        ],
        Body::from(form),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    cleanup(fixture).await;
}

#[tokio::test]
async fn denial_redirects_access_denied_and_is_audited() {
    let fixture = fixture_async(false).await;
    let (token, csrf) = session_cookie(&fixture).await;
    let form = consent_form(&fixture, &csrf, "deny");
    let (status, headers, _) = send(
        app(&fixture),
        Method::POST,
        "/oauth2/authorize/consent",
        &[
            ("cookie", format!("authkit_session={token}")),
            (
                "content-type",
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("origin", "https://auth.example.com".to_owned()),
        ],
        Body::from(form),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location(&headers)
            .query_pairs()
            .find(|(name, _)| name == "error")
            .map(|(_, value)| value.into_owned()),
        Some("access_denied".to_owned())
    );

    let store = fixture.store.clone();
    let denials = tokio::task::spawn_blocking(move || {
        store.list_audit_events_by_action("authorization.consent.deny")
    })
    .await
    .expect("audit task")
    .expect("audit query");
    assert_eq!(denials.len(), 1);
    cleanup(fixture).await;
}
