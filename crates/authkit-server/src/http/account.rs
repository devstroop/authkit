//! Minimal account security pages.

use askama::Template;
use authkit_core::domain::WriteOutcome;
use authkit_core::domain::email::Email;
use authkit_core::domain::id::ConsentEntity;
use authkit_core::domain::id::SessionEntity;
use authkit_core::domain::one_time_token::{OneTimeToken, OneTimeTokenPurpose};
use authkit_core::domain::time::Timestamp;
use authkit_core::domain::{DisplayName, TenantContext};
use authkit_core::ports::IdGenerator;
use authkit_core::ports::{
    ConsentRepository, CredentialRepository, OAuthClientRepository, OneTimeTokenRepository,
    RateLimiter, SessionRepository, UserRepository,
};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::http::rate_limit::client_ip;
use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::password::verify_password;

#[derive(Template)]
#[template(path = "pages/account.html")]
struct AccountTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    sessions: Vec<SessionView>,
}

#[derive(Clone)]
struct SessionView {
    id: String,
    status: String,
}

#[derive(Template)]
#[template(path = "fragments/account/sessions.html")]
struct AccountSessionsFragment<'a> {
    csrf: &'a str,
    sessions: Vec<SessionView>,
}

pub(crate) async fn account_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };

    let csrf = sessions.csrf_token(session.session());
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let listed = tokio::task::spawn_blocking(move || {
        authkit_core::ports::SessionRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await;

    let mut session_views = Vec::new();
    if let Ok(Ok(sessions_list)) = listed {
        for s in sessions_list {
            session_views.push(SessionView {
                id: s.id().as_str().to_owned(),
                status: if s.is_valid(sessions.clock().now()) {
                    "active".to_owned()
                } else {
                    "inactive".to_owned()
                },
            });
        }
    }

    if headers.get("HX-Request").is_some() {
        let fragment = AccountSessionsFragment {
            csrf: &csrf,
            sessions: session_views.clone(),
        };
        let body = fragment.render().unwrap_or_default();
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response();
    }

    let template = AccountTemplate {
        title: "title_account",
        csrf: &csrf,
        sessions: session_views,
    };
    let body = template.render().unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

pub(crate) async fn change_password(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    _headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };

    let mut params = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        params.insert(key.into_owned(), value.into_owned());
    }
    let current_password = params.get("current_password").cloned().unwrap_or_default();
    let new_password = params.get("new_password").cloned().unwrap_or_default();
    if current_password.is_empty() || new_password.is_empty() {
        return bad_request();
    }

    let store = sessions.store().clone();
    let user_id = session.session().user_id().clone();
    let credential = match tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || {
            let credentials = CredentialRepository::list_for_user(store.as_ref(), &user_id)?;
            Ok::<_, authkit_core::domain::DomainError>(credentials.into_iter().find(|c| {
                c.kind() == authkit_core::domain::CredentialKind::Password && c.is_active()
            }))
        }
    })
    .await
    {
        Ok(Ok(Some(credential))) => credential,
        _ => return bad_request(),
    };

    let verifier = match credential.as_password() {
        Some(value) => value.clone(),
        None => return bad_request(),
    };
    if !verify_password(&current_password, &verifier) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::CACHE_CONTROL, "no-store")],
            axum::Json(json!({"error": "invalid_password"})),
        )
            .into_response();
    }

    let new_verifier = match crate::password::hash_password(&new_password) {
        Ok(value) => value,
        Err(_) => return bad_request(),
    };

    let original_version = credential.version();
    let mut updated = credential;
    if updated
        .replace_password(new_verifier, sessions.clock().now())
        .is_err()
    {
        return bad_request();
    }

    let store_clone = store.clone();
    let updated_clone = updated.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        CredentialRepository::update(store_clone.as_ref(), &updated_clone, original_version)
    })
    .await;

    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }

    let current_session_id = session.session().id().clone();
    let store_for_sessions = store.clone();
    let user_id_for_sessions = user_id.clone();
    let now_for_sessions = sessions.clock().now();
    let _ = tokio::task::spawn_blocking(move || {
        let sessions_list =
            SessionRepository::list_for_user(store_for_sessions.as_ref(), &user_id_for_sessions)?;
        for target in sessions_list {
            if target.id() == &current_session_id || !target.is_valid(now_for_sessions) {
                continue;
            }
            let expected = target.version();
            let mut revoked = target;
            revoked.revoke(now_for_sessions);
            let _ = SessionRepository::update(store_for_sessions.as_ref(), &revoked, expected);
        }
        Ok::<_, authkit_core::domain::DomainError>(())
    })
    .await;

    if let Ok(Ok(Some(user))) = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    {
        let _ = state.email.send(
            user.email(),
            "Your password was changed",
            "Your account password was changed. If this was not you, contact support.",
        );
    }
    redirect("/account")
}

pub(crate) async fn request_email_change(
    State(state): State<AppState>,
    _headers: HeaderMap,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };

    let mut params = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        params.insert(key.into_owned(), value.into_owned());
    }
    let new_email_raw = params.get("new_email").cloned().unwrap_or_default();
    if new_email_raw.is_empty() {
        return bad_request();
    }
    let new_email = match Email::parse(&new_email_raw) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };

    let store = sessions.store().clone();
    let user_id = session.session().user_id().clone();
    let user = match tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    {
        Ok(Ok(Some(u))) => u,
        _ => return unavailable(),
    };

    // Ensure new email is not already in use.
    let application_id = user.application_id().cloned();
    if let Ok(Ok(Some(_))) = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = new_email.clone();
        let application_id = application_id.clone();
        move || UserRepository::find_by_email(store.as_ref(), application_id.as_ref(), &email)
    })
    .await
    {
        return bad_request();
    }

    let old_email = user.email().clone();

    let token_plain = crate::http::reset::random_token();
    let pepper = sessions.pepper().to_vec();
    let hash = crate::http::reset::hash_token(&token_plain, &pepper);
    let now = sessions.clock().now();
    let expires = Timestamp::from_millis(now.as_millis().saturating_add(24 * 60 * 60 * 1000));
    let token = match OneTimeToken::new(
        crate::session::SecureIdGenerator
            .generate::<authkit_core::domain::id::OneTimeTokenEntity>()
            .expect("id"),
        user.id().clone(),
        OneTimeTokenPurpose::EmailChange,
        hash,
        now,
        expires,
    ) {
        Ok(t) => t,
        Err(_) => return unavailable(),
    };
    let store_clone = store.clone();
    let insert = tokio::task::spawn_blocking(move || {
        OneTimeTokenRepository::insert(store_clone.as_ref(), &token)
    })
    .await;
    if insert.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }

    let link = format!(
        "/account/email-change/confirm?token={}&email={}",
        token_plain,
        new_email.as_str()
    );
    let _ = state.email.send(
        &new_email,
        "Confirm your new email",
        &format!("Use this link to confirm your new email address: {}", link),
    );
    // Notify old address.
    let _ = state.email.send(
        &old_email,
        "Email change requested",
        "A request was made to change the email on your account. If this was not you, contact support.",
    );
    #[cfg(debug_assertions)]
    tracing::info!(
        target = "authkit.dev.email_change",
        "email change token for {} (dev only): {}",
        new_email.as_str(),
        token_plain
    );

    redirect("/account")
}

pub(crate) async fn email_change_confirm_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let token = q.get("token").cloned().unwrap_or_default();
    let email = q.get("email").cloned().unwrap_or_default();
    let csrf = sessions.csrf_token(session.session());
    let template = EmailChangeConfirmTemplate {
        title: "Confirm email change",
        csrf: &csrf,
        token: &token,
        email: &email,
    };
    let body = template.render().unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

pub(crate) async fn confirm_email_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        params.insert(key.into_owned(), value.into_owned());
    }
    let token_plain = params.get("token").cloned().unwrap_or_default();
    let new_email_raw = params.get("email").cloned().unwrap_or_default();
    if token_plain.is_empty() || new_email_raw.is_empty() {
        return bad_request();
    }
    let new_email = match Email::parse(&new_email_raw) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };

    let trusted = std::env::var("AUTHKIT_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .filter_map(|v| v.trim().parse().ok())
        .collect::<Vec<_>>();
    let trusted = if trusted.is_empty()
        && std::env::var("AUTHKIT_TRUSTED_PROXIES")
            .unwrap_or_default()
            .contains('*')
    {
        vec!["0.0.0.0".parse().unwrap()]
    } else {
        trusted
    };
    let ip = client_ip(&headers, None, &trusted);
    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let key = format!("verify:ip:{ip}");
    let _ = tokio::task::spawn_blocking({
        let store = store.clone();
        let key = key.clone();
        move || RateLimiter::check(store.as_ref(), &key, 20, 300, now)
    })
    .await;

    let pepper = sessions.pepper().to_vec();
    let hash = crate::http::reset::hash_token(&token_plain, &pepper);
    let found = tokio::task::spawn_blocking({
        let store = store.clone();
        let hash = hash.clone();
        move || {
            OneTimeTokenRepository::find_by_hash(
                store.as_ref(),
                &hash,
                OneTimeTokenPurpose::EmailChange,
            )
        }
    })
    .await;
    let token = match found {
        Ok(Ok(Some(t))) => t,
        _ => return bad_request(),
    };
    if !token.is_usable(now) {
        return bad_request();
    }

    // Ensure token belongs to the signed-in user.
    if token.user_id() != session.session().user_id() {
        return bad_request();
    }

    let user_id = token.user_id().clone();
    let user = match tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    {
        Ok(Ok(Some(u))) => u,
        _ => return bad_request(),
    };

    // Ensure new email not in use by another account.
    let application_id = user.application_id().cloned();
    if let Ok(Ok(Some(other))) = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = new_email.clone();
        let application_id = application_id.clone();
        move || UserRepository::find_by_email(store.as_ref(), application_id.as_ref(), &email)
    })
    .await
        && other.id() != user.id()
    {
        return bad_request();
    }

    let old_email = user.email().clone();
    let original_version = user.version();
    let mut updated = user;
    if updated.change_email(new_email.clone(), now).is_err() {
        return bad_request();
    }
    let store_clone = store.clone();
    let updated_clone = updated.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        UserRepository::update(store_clone.as_ref(), &updated_clone, original_version)
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }

    // Consume token.
    let store_clone = store.clone();
    let tid = token.id().clone();
    let _ = tokio::task::spawn_blocking(move || {
        OneTimeTokenRepository::consume(store_clone.as_ref(), &tid, now)
    })
    .await;

    // Revoke other sessions.
    let current_session_id = session.session().id().clone();
    let store_for_sessions = store.clone();
    let user_id_for_sessions = user_id.clone();
    let now_for_sessions = now;
    let _ = tokio::task::spawn_blocking(move || {
        let sessions_list =
            SessionRepository::list_for_user(store_for_sessions.as_ref(), &user_id_for_sessions)?;
        for target in sessions_list {
            if target.id() == &current_session_id || !target.is_valid(now_for_sessions) {
                continue;
            }
            let expected = target.version();
            let mut revoked = target;
            revoked.revoke(now_for_sessions);
            let _ = SessionRepository::update(store_for_sessions.as_ref(), &revoked, expected);
        }
        Ok::<_, authkit_core::domain::DomainError>(())
    })
    .await;

    // Notify old address.
    let _ = state.email.send(
        &old_email,
        "Your email was changed",
        "The email address on your account was changed. If this was not you, contact support.",
    );

    redirect("/account")
}

fn redirect(location: &str) -> Response {
    match axum::http::HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error": "invalid_request"})),
    )
        .into_response()
}

pub(crate) async fn revoke_session(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };

    let parsed_id = match authkit_core::domain::Id::<SessionEntity>::parse(&id) {
        Ok(value) => value,
        Err(_) => return bad_request(),
    };

    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let outcome = tokio::task::spawn_blocking(move || {
        if let Some(mut target) = SessionRepository::find_by_id(store.as_ref(), &parsed_id)? {
            if target.user_id() != session.session().user_id() {
                return Ok::<_, authkit_core::domain::DomainError>(false);
            }
            let expected = target.version();
            target.revoke(now);
            let result = SessionRepository::update(store.as_ref(), &target, expected)?;
            Ok(result.is_applied())
        } else {
            Ok(false)
        }
    })
    .await;

    if outcome.ok().and_then(|r| r.ok()).unwrap_or(false) {
        redirect("/account")
    } else {
        unavailable()
    }
}

#[derive(Clone)]
struct ConnectedAppView {
    client_name: String,
    scopes: String,
    consent_id: String,
}

#[derive(askama::Template)]
#[template(path = "pages/connected_apps.html")]
struct ConnectedAppsTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    apps: Vec<ConnectedAppView>,
}

pub(crate) async fn connected_apps_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let listed = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || ConsentRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await;

    let mut apps = Vec::new();
    if let Ok(Ok(consents)) = listed {
        for c in consents {
            if c.revoked_at().is_some() {
                continue;
            }
            let tenant = TenantContext::new(c.application_id().clone());
            let client_name = tokio::task::spawn_blocking({
                let store = store.clone();
                let tenant = tenant.clone();
                let client_id = c.client_id().clone();
                move || {
                    OAuthClientRepository::find_by_id(store.as_ref(), &tenant, &client_id)
                        .ok()
                        .flatten()
                        .map(|client| client.name().as_str().to_owned())
                        .unwrap_or_else(|| "Unknown client".to_owned())
                }
            })
            .await
            .unwrap_or_else(|_| "Unknown client".to_owned());

            apps.push(ConnectedAppView {
                client_name,
                scopes: c
                    .scopes()
                    .as_slice()
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
                consent_id: c.id().as_str().to_owned(),
            });
        }
    }

    let template = ConnectedAppsTemplate {
        title: "title_connected_apps",
        csrf: &csrf,
        apps,
    };
    let body = template.render().unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

pub(crate) async fn revoke_consent(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let parsed_id = match authkit_core::domain::Id::<ConsentEntity>::parse(&id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let user_id = session.session().user_id().clone();
    let outcome = tokio::task::spawn_blocking(move || {
        // find consent without tenant: search all? We need org. Query by id globally.
        // ConsentRepository is tenant-scoped; use a direct store query via find_consent? Not exposed.
        // Instead, iterate user's consents.
        let consents = ConsentRepository::list_for_user(store.as_ref(), &user_id)?;
        let consent = consents
            .into_iter()
            .find(|c| c.id() == &parsed_id && c.is_active());
        let Some(mut consent) = consent else {
            return Ok::<_, authkit_core::domain::DomainError>(false);
        };
        let tenant = TenantContext::new(consent.application_id().clone());
        let expected = consent.version();
        consent.revoke(now);
        let result = ConsentRepository::update(store.as_ref(), &tenant, &consent, expected)?;
        Ok(result.is_applied())
    })
    .await;

    if outcome.ok().and_then(|r| r.ok()).unwrap_or(false) {
        redirect("/account/applications")
    } else {
        unavailable()
    }
}

#[derive(askama::Template)]
#[template(path = "pages/profile.html")]
struct ProfileTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    display_name: &'a str,
}

#[derive(askama::Template)]
#[template(path = "pages/email_change_confirm.html")]
struct EmailChangeConfirmTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    token: &'a str,
    email: &'a str,
}

pub(crate) async fn profile_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let display_name = user
        .map(|u| u.display_name().as_str().to_owned())
        .unwrap_or_default();
    let template = ProfileTemplate {
        title: "title_profile",
        csrf: &csrf,
        display_name: &display_name,
    };
    let body = template.render().unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

pub(crate) async fn update_profile(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.into_owned(), v.into_owned());
    }
    let new_name = params.get("display_name").cloned().unwrap_or_default();
    let display_name = match DisplayName::parse(&new_name) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };

    let store = sessions.store().clone();
    let user_id = session.session().user_id().clone();
    let now = sessions.clock().now();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(mut user) = user else {
        return unavailable();
    };
    let original_version = user.version();
    let _ = user.rename(display_name, now);

    let store_clone = store.clone();
    let updated = user.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        UserRepository::update(store_clone.as_ref(), &updated, original_version)
    })
    .await;

    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }
    redirect("/account/profile")
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error": "temporarily_unavailable"})),
    )
        .into_response()
}
