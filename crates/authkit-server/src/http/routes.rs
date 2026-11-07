//! Health, readiness, and fallback routes.

use std::fmt;
use std::sync::Arc;

use authkit_store::SqlStore;
use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use serde_json::json;

use crate::authorization::AuthorizationService;
use crate::config::Issuer;
use crate::http::account;
use crate::http::admin;
use crate::http::login;
use crate::http::mfa;
use crate::http::organization;
use crate::http::request_id;
use crate::http::reset;
use crate::http::security_headers::{SecurityHeaders, security_headers};
use crate::http::session::{SessionSecurityState, session_context};
use crate::metrics;
use crate::session::SessionService;
use crate::signing::KeyRing;
use crate::tokens::TokenService;
use authkit_core::ports::EmailSender;

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
    pub(crate) sessions: Option<Arc<SessionService>>,
    pub(crate) authorization: Option<Arc<AuthorizationService>>,
    pub(crate) tokens: Option<Arc<TokenService>>,
    pub(crate) email: Arc<dyn EmailSender + Send + Sync>,
}

impl AppState {
    fn new(
        readiness: Arc<dyn ReadinessProbe>,
        keys: Arc<KeyRing>,
        issuer: Issuer,
        sessions: Option<Arc<SessionService>>,
        authorization: Option<Arc<AuthorizationService>>,
        tokens: Option<Arc<TokenService>>,
        email: Arc<dyn EmailSender + Send + Sync>,
    ) -> Self {
        Self {
            readiness,
            keys,
            issuer,
            sessions,
            authorization,
            tokens,
            email,
        }
    }
}

/// Builds the native server router.
///
/// This base router has no session or browser-security layers. The binary uses
/// [`router_with_sessions`]; the base router keeps metadata and health tests independent of
/// session storage.
pub fn router(readiness: Arc<dyn ReadinessProbe>, keys: Arc<KeyRing>, issuer: Issuer) -> Router {
    base_router(
        readiness,
        keys,
        issuer,
        None,
        None,
        None,
        Arc::new(crate::email::DevEmailSender),
    )
    .layer(middleware::from_fn(request_id::request_context))
}

/// Builds the production router with session resolution, CSRF checks, and security headers.
pub fn router_with_sessions(
    readiness: Arc<dyn ReadinessProbe>,
    keys: Arc<KeyRing>,
    issuer: Issuer,
    sessions: Arc<SessionService>,
    authorization: Option<Arc<AuthorizationService>>,
    hsts: bool,
) -> Router {
    with_session_security(
        base_router(
            readiness,
            keys,
            issuer.clone(),
            Some(sessions.clone()),
            authorization,
            None,
            Arc::new(crate::email::DevEmailSender),
        ),
        sessions,
        issuer,
        hsts,
    )
}

/// Builds the production router with token endpoints enabled.
pub fn router_with_sessions_and_tokens(
    readiness: Arc<dyn ReadinessProbe>,
    keys: Arc<KeyRing>,
    issuer: Issuer,
    sessions: Arc<SessionService>,
    authorization: Option<Arc<AuthorizationService>>,
    tokens: Option<Arc<TokenService>>,
    hsts: bool,
) -> Router {
    with_session_security(
        base_router(
            readiness,
            keys,
            issuer.clone(),
            Some(sessions.clone()),
            authorization,
            tokens,
            Arc::new(crate::email::DevEmailSender),
        ),
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

fn base_router(
    readiness: Arc<dyn ReadinessProbe>,
    keys: Arc<KeyRing>,
    issuer: Issuer,
    sessions: Option<Arc<SessionService>>,
    authorization: Option<Arc<AuthorizationService>>,
    tokens: Option<Arc<TokenService>>,
    email: Arc<dyn EmailSender + Send + Sync>,
) -> Router {
    metrics::install(metrics::global());
    let mut router = Router::new()
        .route("/healthz", get(health))
        .route("/static/htmx.min.js", get(static_htmx))
        .route("/metrics", get(metrics::handler))
        .route("/readyz", get(ready))
        .route("/login", get(login::login_page).post(login::login_submit))
        .route("/login/mfa", post(mfa::login_verify))
        .route(
            "/register",
            get(login::register_page).post(login::register_submit),
        )
        .route(
            "/password-reset",
            get(reset::request_reset_page).post(reset::request_reset_submit),
        )
        .route(
            "/password-reset/confirm",
            get(reset::confirm_reset_page).post(reset::confirm_reset_submit),
        )
        .route("/verify-email", get(reset::verify_email_page))
        .route("/verify-email/confirm", post(reset::verify_email_confirm))
        .route("/account", get(account::account_page))
        .route(
            "/account/profile",
            get(account::profile_page).post(account::update_profile),
        )
        .route("/account/password", post(account::change_password))
        .route("/account/applications", get(account::connected_apps_page))
        .route(
            "/account/consents/{id}/revoke",
            post(account::revoke_consent),
        )
        .route("/account/mfa", get(mfa::account_page))
        .route("/account/mfa/enroll", post(mfa::enroll))
        .route("/account/mfa/verify", post(mfa::verify_enrollment))
        .route("/account/mfa/disable", post(mfa::disable))
        .route("/account/mfa/recovery-codes", get(mfa::recovery_codes_page))
        .route(
            "/account/mfa/recovery-codes/generate",
            post(mfa::generate_recovery_codes),
        )
        .route(
            "/admin/login",
            get(admin::login_page).post(admin::login_submit),
        )
        .route("/admin", get(admin::dashboard))
        .route("/admin/logout", post(admin::logout))
        .route("/admin/administrators", post(admin::grant_admin))
        .route(
            "/admin/administrators/{id}/disable",
            post(admin::disable_admin),
        )
        .route(
            "/admin/signing-keys/rotate",
            post(admin::rotate_signing_key),
        )
        .route("/admin/mfa/enroll", post(admin::mfa_enroll))
        .route("/admin/mfa/verify", post(admin::mfa_verify))
        .route(
            "/organizations",
            get(organization::organizations_page).post(organization::create_organization),
        )
        .route(
            "/organizations/{org_id}/members",
            get(organization::members_page).post(organization::add_member),
        )
        .route(
            "/organizations/{org_id}/invitations",
            get(organization::invitations_page).post(organization::create_invitation),
        )
        .route(
            "/organizations/{org_id}/invitations/{invitation_id}/revoke",
            post(organization::revoke_invitation),
        )
        .route(
            "/organizations/{org_id}/roles",
            get(organization::roles_page).post(organization::create_role),
        )
        .route(
            "/organizations/{org_id}/applications",
            get(organization::applications_page).post(organization::create_application),
        )
        .route(
            "/organizations/{org_id}/oauth-clients",
            get(organization::oauth_clients_page).post(organization::create_oauth_client),
        )
        .route(
            "/organizations/{org_id}/oauth-clients/{client_id}",
            get(organization::oauth_client_detail),
        )
        .route(
            "/organizations/{org_id}/oauth-clients/{client_id}/redirect-uris",
            post(organization::add_redirect_uri),
        )
        .route(
            "/organizations/{org_id}/oauth-clients/{client_id}/redirect-uris/remove",
            post(organization::remove_redirect_uri),
        )
        .route(
            "/organizations/{org_id}/oauth-clients/{client_id}/scopes",
            post(organization::replace_scopes),
        )
        .route(
            "/organizations/{org_id}/role-bindings",
            post(organization::bind_role),
        )
        .route(
            "/invitations/accept",
            get(organization::accept_invitation_page).post(organization::accept_invitation),
        )
        .route("/account/verify-email", get(reset::request_verify_page))
        .route(
            "/account/verify-email-request",
            post(reset::request_verify_submit),
        )
        .route(
            "/account/sessions/{id}/revoke",
            post(account::revoke_session),
        )
        .route(
            "/.well-known/openid-configuration",
            get(crate::http::metadata::openid_configuration),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(crate::http::metadata::oauth_authorization_server),
        )
        .route("/oauth2/jwks", get(crate::http::metadata::jwks))
        .route(
            "/oauth2/authorize.css",
            get(crate::http::authorize::stylesheet),
        );
    if authorization.is_some() {
        router = router
            .route("/oauth2/authorize", get(crate::http::authorize::authorize))
            .route(
                "/oauth2/authorize/consent",
                post(crate::http::authorize::consent),
            );
    }
    if tokens.is_some() {
        router = router
            .route("/oauth2/token", post(crate::http::token::token))
            .route(
                "/oauth2/userinfo",
                get(crate::http::userinfo::userinfo).post(crate::http::userinfo::userinfo_post),
            )
            .route("/oauth2/revoke", post(crate::http::revoke::revoke))
            .route(
                "/oauth2/logout",
                get(crate::http::logout::logout_get).post(crate::http::logout::logout_post),
            );
    }
    let router = router.layer(axum::middleware::from_fn(metrics::middleware));
    router.fallback(not_found).with_state(AppState::new(
        readiness,
        keys,
        issuer,
        sessions,
        authorization,
        tokens,
        email,
    ))
}

async fn static_htmx() -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        include_str!("../../static/htmx.min.js"),
    )
        .into_response()
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
