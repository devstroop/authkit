//! Password reset and email verification flows (dev email delivery is logged).

use askama::Template;
use authkit_core::domain::id::OneTimeTokenEntity;
use authkit_core::domain::{Email, OneTimeToken, OneTimeTokenPurpose, WriteOutcome};
use authkit_core::ports::{
    CredentialRepository, IdGenerator, OneTimeTokenRepository, RateLimiter, UserRepository,
};
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::http::rate_limit::client_ip;
use crate::http::routes::AppState;
use crate::password::hash_password;
use base64::Engine;

#[derive(Deserialize)]
pub(crate) struct TokenQuery {
    token: Option<String>,
}

#[derive(Template)]
#[template(path = "pages/request_reset.html")]
struct RequestResetTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
}

pub(crate) async fn request_reset_page(
    State(state): State<AppState>,
    session: Option<axum::extract::Extension<crate::http::session::SessionContext>>,
) -> Response {
    let csrf_value = if let Some(ext) = session {
        if let Some(sessions) = state.sessions.as_ref() {
            sessions.csrf_token(ext.0.session()).to_owned()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let template = RequestResetTemplate {
        title: "title_reset_password",
        csrf: &csrf_value,
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

pub(crate) async fn request_reset_submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.into_owned(), v.into_owned());
    }
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
    if let Some(sessions) = state.sessions.as_ref() {
        let store = sessions.store().clone();
        let now = sessions.clock().now();
        let key = format!("reset:ip:{ip}");
        let result = tokio::task::spawn_blocking({
            let store = store.clone();
            let key = key.clone();
            move || RateLimiter::check(store.as_ref(), &key, 20, 3600, now)
        })
        .await;
        if let Ok(Err(err)) = result {
            return rate_limited_response(err.retry_after_secs);
        }
    }
    let email = params.get("email").cloned().unwrap_or_default();
    if let Ok(parsed_email) = Email::parse(&email) {
        if let Some(sessions) = state.sessions.as_ref() {
            let store = sessions.store().clone();
            let now = sessions.clock().now();
            let key = format!("reset:account:{}", parsed_email.as_str().to_lowercase());
            let result = tokio::task::spawn_blocking({
                let store = store.clone();
                let key = key.clone();
                move || RateLimiter::check(store.as_ref(), &key, 5, 900, now)
            })
            .await;
            if let Ok(Err(err)) = result {
                return rate_limited_response(err.retry_after_secs);
            }
        }
        let store = match state.sessions.as_ref() {
            Some(s) => s.store().clone(),
            None => return unavailable(),
        };
        let application_id = crate::tenant::current()
            .as_ref()
            .map(|app| app.id().clone());
        let user = tokio::task::spawn_blocking({
            let store = store.clone();
            let email = parsed_email.clone();
            let application_id = application_id.clone();
            move || UserRepository::find_by_email(store.as_ref(), application_id.as_ref(), &email)
        })
        .await
        .ok()
        .and_then(|r| r.ok().flatten());

        if let Some(user) = user {
            let token_plain = random_token();
            let pepper = state
                .sessions
                .as_ref()
                .map(|s| s.pepper().to_vec())
                .unwrap_or_default();
            let hash = hash_token(&token_plain, &pepper);
            let now = state
                .sessions
                .as_ref()
                .map(|s| s.clock().now())
                .unwrap_or_else(authkit_server_now);
            let expires = authkit_core::domain::time::Timestamp::from_millis(
                now.as_millis().saturating_add(15 * 60 * 1000),
            );
            let token = OneTimeToken::new(
                crate::session::SecureIdGenerator
                    .generate::<OneTimeTokenEntity>()
                    .expect("id"),
                user.id().clone(),
                OneTimeTokenPurpose::PasswordReset,
                hash,
                now,
                expires,
            )
            .expect("token");
            let store_clone = store.clone();
            let insert = tokio::task::spawn_blocking(move || {
                OneTimeTokenRepository::insert(store_clone.as_ref(), &token)
            })
            .await;
            if insert.ok().and_then(|r| r.ok()) == Some(WriteOutcome::Applied) {
                let link = format!("/password-reset/confirm?token={}", token_plain);
                let _ = state.email.send(
                    &parsed_email,
                    "Reset your password",
                    &format!("Use this link to reset your password: {}", link),
                );
                #[cfg(debug_assertions)]
                tracing::info!(
                    target = "authkit.dev.reset",
                    "password reset token for {} (dev only): {}",
                    email,
                    token_plain
                );
            }
        }
    }
    // Generic response to avoid account enumeration.
    html_page(
        "Reset password",
        "<p>If an account exists, a reset link has been sent.</p>",
    )
}

#[derive(Template)]
#[template(path = "pages/confirm_reset.html")]
struct ConfirmResetTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    token: &'a str,
}

pub(crate) async fn confirm_reset_page(
    State(state): State<AppState>,
    session: Option<axum::extract::Extension<crate::http::session::SessionContext>>,
    Query(q): Query<TokenQuery>,
) -> Response {
    let token = q.token.clone().unwrap_or_default();
    let csrf_value = if let Some(ext) = session {
        if let Some(sessions) = state.sessions.as_ref() {
            sessions.csrf_token(ext.0.session()).to_owned()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let template = ConfirmResetTemplate {
        title: "title_choose_new_password",
        csrf: &csrf_value,
        token: &token,
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

pub(crate) async fn confirm_reset_submit(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.into_owned(), v.into_owned());
    }
    let token_plain = params.get("token").cloned().unwrap_or_default();
    let password = params.get("password").cloned().unwrap_or_default();
    if token_plain.is_empty() || password.is_empty() {
        return bad_request();
    }
    let pepper = state
        .sessions
        .as_ref()
        .map(|s| s.pepper().to_vec())
        .unwrap_or_default();
    let hash = hash_token(&token_plain, &pepper);

    let store = match state.sessions.as_ref() {
        Some(s) => s.store().clone(),
        None => return unavailable(),
    };
    let found = tokio::task::spawn_blocking({
        let store = store.clone();
        let hash = hash.clone();
        move || {
            OneTimeTokenRepository::find_by_hash(
                store.as_ref(),
                &hash,
                OneTimeTokenPurpose::PasswordReset,
            )
        }
    })
    .await;
    let token = match found {
        Ok(Ok(Some(t))) => t,
        _ => return bad_request(),
    };

    let sessions = state.sessions.as_ref().unwrap();
    let now = sessions.clock().now();
    if !token.is_usable(now) {
        return bad_request();
    }

    // Load user
    let user_id = token.user_id().clone();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return bad_request();
    };

    // Update password credential
    let credentials = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user.id().clone();
        move || CredentialRepository::list_for_user(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();

    let password_cred = credentials
        .into_iter()
        .find(|c| c.kind() == authkit_core::domain::CredentialKind::Password && c.is_active());

    let new_verifier = match hash_password(&password) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };

    let store_clone = store.clone();
    let token_id = token.id().clone();
    let outcome = if let Some(cred) = password_cred {
        let original_version = cred.version();
        let mut updated = cred;
        if updated.replace_password(new_verifier, now).is_err() {
            return bad_request();
        }
        tokio::task::spawn_blocking(move || {
            CredentialRepository::update(store_clone.as_ref(), &updated, original_version)
        })
        .await
    } else {
        // Create new password credential
        let credential = authkit_core::domain::Credential::password(
            crate::session::SecureIdGenerator
                .generate::<authkit_core::domain::id::CredentialEntity>()
                .expect("id"),
            user.id().clone(),
            new_verifier,
            now,
        );
        let sc = store.clone();
        tokio::task::spawn_blocking(move || CredentialRepository::insert(sc.as_ref(), &credential))
            .await
    };

    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }

    // Consume token
    let store_clone = store.clone();
    let tid = token_id.clone();
    let _ = tokio::task::spawn_blocking(move || {
        OneTimeTokenRepository::consume(store_clone.as_ref(), &tid, now)
    })
    .await;

    html_page(
        "Password reset",
        "<p>Your password has been reset. You can now sign in.</p>",
    )
}

#[derive(askama::Template)]
#[template(path = "pages/request_verify.html")]
struct RequestVerifyTemplate {
    title: &'static str,
}

pub(crate) async fn request_verify_page(
    session: Option<axum::extract::Extension<crate::http::session::SessionContext>>,
) -> Response {
    if session.is_none() {
        return redirect("/login");
    }
    let template = RequestVerifyTemplate {
        title: "title_verify_email",
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

pub(crate) async fn request_verify_submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    session: Option<axum::extract::Extension<crate::http::session::SessionContext>>,
) -> Response {
    let Some(ref ext) = session else {
        return redirect("/login");
    };
    let sessions = match state.sessions.as_ref() {
        Some(s) => s,
        None => return unavailable(),
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
    let user_key = format!(
        "verify:user:{}",
        session
            .as_ref()
            .map(|s| s.0.session().user_id().as_str().to_owned())
            .unwrap_or_else(|| "unknown".to_owned())
    );
    let user_result = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_key = user_key.clone();
        move || RateLimiter::check(store.as_ref(), &user_key, 5, 3600, now)
    })
    .await;
    if let Ok(Err(err)) = user_result {
        return rate_limited_response(err.retry_after_secs);
    }
    let ip_key = format!("verify:ip:{ip}");
    let ip_result = tokio::task::spawn_blocking({
        let store = store.clone();
        let ip_key = ip_key.clone();
        move || RateLimiter::check(store.as_ref(), &ip_key, 20, 3600, now)
    })
    .await;
    if let Ok(Err(err)) = ip_result {
        return rate_limited_response(err.retry_after_secs);
    }
    let user_id = ext.0.session().user_id().clone();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return unavailable();
    };

    let token_plain = random_token();
    let pepper = sessions.pepper().to_vec();
    let hash = hash_token(&token_plain, &pepper);
    let now = sessions.clock().now();
    let expires = authkit_core::domain::time::Timestamp::from_millis(
        now.as_millis().saturating_add(24 * 60 * 60 * 1000),
    );
    let token = OneTimeToken::new(
        crate::session::SecureIdGenerator
            .generate::<OneTimeTokenEntity>()
            .expect("id"),
        user.id().clone(),
        OneTimeTokenPurpose::EmailVerification,
        hash,
        now,
        expires,
    )
    .expect("token");
    let store_clone = store.clone();
    let insert = tokio::task::spawn_blocking(move || {
        OneTimeTokenRepository::insert(store_clone.as_ref(), &token)
    })
    .await;
    if insert.ok().and_then(|r| r.ok()) == Some(WriteOutcome::Applied) {
        let link = format!("/verify-email/confirm?token={}", token_plain);
        let _ = state.email.send(
            user.email(),
            "Verify your email",
            &format!("Use this link to verify your email: {}", link),
        );
        #[cfg(debug_assertions)]
        tracing::info!(
            target = "authkit.dev.verify",
            "email verification token for {} (dev only): {}",
            user.email().as_str(),
            token_plain
        );
    }
    html_page("Verify email", "<p>A verification link has been sent.</p>")
}

#[derive(askama::Template)]
#[template(path = "pages/verify_email.html")]
struct VerifyEmailTemplate<'a> {
    title: &'a str,
    token: &'a str,
}

pub(crate) async fn verify_email_page(Query(q): Query<TokenQuery>) -> Response {
    let token = q.token.clone().unwrap_or_default();
    let template = VerifyEmailTemplate {
        title: "title_verify_email",
        token: &token,
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

pub(crate) async fn verify_email_confirm(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.into_owned(), v.into_owned());
    }
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
    if let Some(sessions) = state.sessions.as_ref() {
        let store = sessions.store().clone();
        let now = sessions.clock().now();
        let key = format!("verify:ip:{ip}");
        let result = tokio::task::spawn_blocking({
            let store = store.clone();
            let key = key.clone();
            move || RateLimiter::check(store.as_ref(), &key, 20, 300, now)
        })
        .await;
        if let Ok(Err(err)) = result {
            return rate_limited_response(err.retry_after_secs);
        }
    }
    let token_plain = params.get("token").cloned().unwrap_or_default();
    if token_plain.is_empty() {
        return bad_request();
    }
    let pepper = state
        .sessions
        .as_ref()
        .map(|s| s.pepper().to_vec())
        .unwrap_or_default();
    let hash = hash_token(&token_plain, &pepper);
    let store = match state.sessions.as_ref() {
        Some(s) => s.store().clone(),
        None => return unavailable(),
    };
    let found = tokio::task::spawn_blocking({
        let store = store.clone();
        let hash = hash.clone();
        move || {
            OneTimeTokenRepository::find_by_hash(
                store.as_ref(),
                &hash,
                OneTimeTokenPurpose::EmailVerification,
            )
        }
    })
    .await;
    let token = match found {
        Ok(Ok(Some(t))) => t,
        _ => return bad_request(),
    };
    let sessions = state.sessions.as_ref().unwrap();
    let now = sessions.clock().now();
    if !token.is_usable(now) {
        return bad_request();
    }

    let user_id = token.user_id().clone();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return bad_request();
    };
    let original_version = user.version();
    let mut user = user;
    let _ = user.verify_email(now);

    let store_clone = store.clone();
    let updated = user.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        UserRepository::update(store_clone.as_ref(), &updated, original_version)
    })
    .await;

    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }

    // Consume token
    let store_clone = store.clone();
    let tid = token.id().clone();
    let _ = tokio::task::spawn_blocking(move || {
        OneTimeTokenRepository::consume(store_clone.as_ref(), &tid, now)
    })
    .await;

    html_page("Email verified", "<p>Your email has been verified.</p>")
}

fn redirect(location: &str) -> Response {
    match axum::http::HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, location),
                (
                    header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-store"),
                ),
            ],
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

#[derive(askama::Template)]
#[template(path = "pages/message.html")]
struct MessageTemplate<'a> {
    title: &'a str,
    message: &'a str,
}

fn html_page(title: &str, body: &str) -> Response {
    let template = MessageTemplate {
        title,
        message: body,
    };
    let html = template.render().unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        html,
    )
        .into_response()
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "invalid_request"})),
    )
        .into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "temporarily_unavailable"})),
    )
        .into_response()
}

pub(crate) fn random_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn hash_token(value: &str, pepper: &[u8]) -> authkit_core::domain::SecretHash {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("hmac");
    mac.update(b"authkit.reset.v1\0");
    mac.update(value.as_bytes());
    let encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    authkit_core::domain::SecretHash::parse(format!("hmac-sha256:{encoded}")).expect("hash")
}

fn authkit_server_now() -> authkit_core::domain::time::Timestamp {
    authkit_core::domain::time::Timestamp::from_millis(
        crate::signing::unix_now().saturating_mul(1000),
    )
}

fn rate_limited_response(retry_after: u64) -> Response {
    let mut response = (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({"error": "rate_limited", "retry_after": retry_after})),
    )
        .into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, value);
    }
    response
}
