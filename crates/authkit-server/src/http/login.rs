//! Login and registration pages for the account session.

use std::sync::Arc;

use authkit_core::application::CreateUser;
use authkit_core::domain::{
    Credential, DisplayName, Email, Id, User, WriteOutcome,
};
use authkit_core::domain::id::{CredentialEntity, UserEntity};
use authkit_core::ports::{
    CredentialRepository, IdGenerator, RateLimiter, UserRepository,
};
use crate::password::verify_password;
use authkit_core::domain::SessionAudience;
use authkit_core::domain::CredentialKind;
use crate::session::{SystemClock, SecureIdGenerator};
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::http::rate_limit::client_ip;
use crate::http::routes::AppState;
use crate::http::session::SessionContext;

const PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
</head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;">
<h1>{title}</h1>
{error}
<form method="post" action="{action}">
<label>Email <input type="email" name="email" required></label><br>
<label>Password <input type="password" name="password" required minlength="12"></label><br>
{extra}
<button type="submit">{button}</button>
</form>
<p><a href="{other_href}">{other_text}</a></p>
</body>
</html>"#;

pub(crate) async fn login_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let next = query
        .as_deref()
        .and_then(|q| form_value(q, "next"))
        .unwrap_or_default();
    let mut extra = if next.is_empty() {
        String::new()
    } else {
        format!(r#"<input type="hidden" name="next" value="{}">"#, escape(&next))
    };
    if let Some(ext) = session {
        if let Some(sessions) = state.sessions.as_ref() {
            extra.push_str(&format!(
                r#"<input type="hidden" name="_csrf" value="{}">"#,
                escape(&sessions.csrf_token(ext.0.session()))
            ));
        }
    }
    html(
        StatusCode::OK,
        "Sign in",
        "/login",
        "Sign in",
        "",
        "/register",
        "Create an account",
        &extra,
    )
}

pub(crate) async fn register_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let next = query
        .as_deref()
        .and_then(|q| form_value(q, "next"))
        .unwrap_or_default();
    let mut extra = if next.is_empty() {
        String::new()
    } else {
        format!(r#"<input type="hidden" name="next" value="{}">"#, escape(&next))
    };
    if let Some(ext) = session {
        if let Some(sessions) = state.sessions.as_ref() {
            extra.push_str(&format!(
                r#"<input type="hidden" name="_csrf" value="{}">"#,
                escape(&sessions.csrf_token(ext.0.session()))
            ));
        }
    }
    html(
        StatusCode::OK,
        "Create account",
        "/register",
        "Create account",
        "",
        "/login",
        "Sign in instead",
        &extra,
    )
}

pub(crate) async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let params = match parse_form(&body) {
        Ok(params) => params,
        Err(()) => return bad_request(),
    };
    let email = params.get("email").cloned().unwrap_or_default();
    let password = params.get("password").cloned().unwrap_or_default();
    let trusted = std::env::var("AUTHKIT_TRUSTED_PROXIES").unwrap_or_default()
        .split(',')
        .filter_map(|v| v.trim().parse().ok())
        .collect::<Vec<_>>();
    // wildcard support
    let trusted = if trusted.is_empty() && std::env::var("AUTHKIT_TRUSTED_PROXIES").unwrap_or_default().contains('*') {
        vec!["0.0.0.0".parse().unwrap()]
    } else {
        trusted
    };
    let ip = client_ip(&headers, None, &trusted);
    // IP rate limit (all failed attempts tracked after auth; check baseline on every request for flood)
    if let Some(sessions) = state.sessions.as_ref() {
        let store = sessions.store().clone();
        let now = sessions.clock().now();
        let ip_key = format!("login:ip:{ip}");
        let ip_result = tokio::task::spawn_blocking({
            let store = store.clone();
            let ip_key = ip_key.clone();
            let now = now;
            move || RateLimiter::check(store.as_ref(), &ip_key, 20, 300, now)
        }).await;
        if let Ok(Err(err)) = ip_result {
            return rate_limited(err.retry_after_secs);
        }
    }
    if email.is_empty() || password.is_empty() {
        return html(
            StatusCode::BAD_REQUEST,
            "Sign in",
            "/login",
            "Sign in",
            "Email and password are required.",
            "/register",
            "Create an account",
            "",
        );
    }

    let store = sessions.store().clone();
    let email_parsed = match Email::parse(&email) {
        Ok(value) => value,
        Err(_) => {
            return html(
                StatusCode::BAD_REQUEST,
                "Sign in",
                "/login",
                "Sign in",
                "Invalid email address.",
                "/register",
                "Create an account",
                "",
            )
        }
    };

    let store_clone = store.clone();
    let email_for_lookup = email_parsed.clone();
    let user = match tokio::task::spawn_blocking(move || find_user_by_email(&store_clone, &email_for_lookup))
        .await
        .ok()
        .and_then(|result| result.ok().flatten())
    {
        Some(user) => user,
        None => {
            // Spend comparable work to avoid trivial user enumeration via timing.
            let _ = tokio::task::spawn_blocking(|| crate::password::hash_password("dummy-password-for-timing"))
                .await;
            if let Some(sessions) = state.sessions.as_ref() {
                let store = sessions.store().clone();
                let now = sessions.clock().now();
                let account_key = format!("login:account:{}", email.to_lowercase());
                let account_result = tokio::task::spawn_blocking({
                let store = store.clone();
                let account_key = account_key.clone();
                let now = now;
                move || RateLimiter::check(store.as_ref(), &account_key, 5, 300, now)
            }).await;
            if let Ok(Err(err)) = account_result {
                return rate_limited(err.retry_after_secs);
            }
                let ip_key = format!("login:ip:{ip}");
                let ip_result = tokio::task::spawn_blocking({
                let store = store.clone();
                let ip_key = ip_key.clone();
                let now = now;
                move || RateLimiter::check(store.as_ref(), &ip_key, 20, 300, now)
            }).await;
            if let Ok(Err(err)) = ip_result {
                return rate_limited(err.retry_after_secs);
            }
            }
            return html(
                StatusCode::UNAUTHORIZED,
                "Sign in",
                "/login",
                "Sign in",
                "Invalid email or password.",
                "/register",
                "Create an account",
                "",
            )
        }
    };

    let store_clone = store.clone();
    let user_id = user.id().clone();
    let credential = match tokio::task::spawn_blocking(move || find_password_credential(&store_clone, &user_id))
        .await
        .ok()
        .and_then(|result| result.ok().flatten())
    {
        Some(credential) => credential,
        None => {
            return html(
                StatusCode::UNAUTHORIZED,
                "Sign in",
                "/login",
                "Sign in",
                "Invalid email or password.",
                "/register",
                "Create an account",
                "",
            )
        }
    };

    let verifier = match credential.as_password() {
        Some(value) => value.clone(),
        None => {
            return html(
                StatusCode::UNAUTHORIZED,
                "Sign in",
                "/login",
                "Sign in",
                "Invalid email or password.",
                "/register",
                "Create an account",
                "",
            )
        }
    };

    if !verify_password(&password, &verifier) {
        if let Some(sessions) = state.sessions.as_ref() {
            let store = sessions.store().clone();
            let now = sessions.clock().now();
            let account_key = format!("login:account:{}", email.to_lowercase());
            let account_result = tokio::task::spawn_blocking({
                let store = store.clone();
                let account_key = account_key.clone();
                let now = now;
                move || RateLimiter::check(store.as_ref(), &account_key, 5, 300, now)
            }).await;
            if let Ok(Err(err)) = account_result {
                return rate_limited(err.retry_after_secs);
            }
            let ip_key = format!("login:ip:{ip}");
            let ip_result = tokio::task::spawn_blocking({
                let store = store.clone();
                let ip_key = ip_key.clone();
                let now = now;
                move || RateLimiter::check(store.as_ref(), &ip_key, 20, 300, now)
            }).await;
            if let Ok(Err(err)) = ip_result {
                return rate_limited(err.retry_after_secs);
            }
        }
        return html(
            StatusCode::UNAUTHORIZED,
            "Sign in",
            "/login",
            "Sign in",
            "Invalid email or password.",
            "/register",
            "Create an account",
            "",
        );
    }

    let redirect_to = params.get("next").cloned().unwrap_or_else(|| "/".to_owned());
    let redirect_to = safe_redirect(&redirect_to);
    let totp_cred = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user.id().clone();
        move || {
            CredentialRepository::list_for_user(store.as_ref(), &user_id)
                .unwrap_or_default()
                .into_iter()
                .find(|c| c.kind() == CredentialKind::Totp && c.is_active())
        }
    })
    .await
    .ok()
    .flatten();
    if let Some(_totp) = totp_cred {
        let pepper = sessions.pepper().to_vec();
        let challenge = crate::totp::challenge_token(user.id().as_str(), &redirect_to, &pepper);
        let body = format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MFA</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Two-factor authentication</h1><form method="post" action="/login/mfa"><input type="hidden" name="challenge" value="{}"><input type="hidden" name="next" value="{}"><label>Code <input name="code" required></label><button type="submit">Verify</button></form></body></html>"#,
            escape(&challenge),
            escape(&redirect_to)
        );
        return html(
            StatusCode::OK,
            "Two-factor authentication",
            "/login/mfa",
            "Two-factor authentication",
            "",
            "/login",
            "Back",
            &body,
        );
    }

    if crate::password::needs_rehash(&verifier) {
        if let Ok(new_verifier) = crate::password::hash_password(&password) {
            let original_version = credential.version();
            let mut updated = credential.clone();
            if updated.replace_password(new_verifier, sessions.clock().now()).is_ok() {
                let store_clone = store.clone();
                let updated_clone = updated.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    CredentialRepository::update(store_clone.as_ref(), &updated_clone, original_version)
                })
                .await;
                let _ = updated;
            }
        }
    }

    let now = sessions.clock().now();
    let store = sessions.store().clone();
    let key = format!("login:account:{}", email.to_lowercase());
    let _ = tokio::task::spawn_blocking(move || RateLimiter::reset(store.as_ref(), &key)).await;
    let created = match sessions.create(user.id().clone(), None, SessionAudience::Account, now).await
    {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };

    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let mut response = redirect(&redirect_to);

    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub(crate) async fn register_submit(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let params = match parse_form(&body) {
        Ok(params) => params,
        Err(()) => return bad_request(),
    };
    let email = params.get("email").cloned().unwrap_or_default();
    let password = params.get("password").cloned().unwrap_or_default();
    if email.is_empty() || password.is_empty() {
        return html(
            StatusCode::BAD_REQUEST,
            "Create account",
            "/register",
            "Create account",
            "Email and password are required.",
            "/login",
            "Sign in instead",
            "",
        );
    }

    let email_parsed = match Email::parse(&email) {
        Ok(value) => value,
        Err(_) => {
            return html(
                StatusCode::BAD_REQUEST,
                "Create account",
                "/register",
                "Create account",
                "Invalid email address.",
                "/login",
                "Sign in instead",
                "",
            )
        }
    };

    let verifier = match crate::password::hash_password(&password) {
        Ok(value) => value,
        Err(_) => {
            return html(
                StatusCode::BAD_REQUEST,
                "Create account",
                "/register",
                "Create account",
                "Password must be at least 12 characters.",
                "/login",
                "Sign in instead",
                "",
            )
        }
    };

    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let display_name = DisplayName::parse(email.split('@').next().unwrap_or("user"))
        .unwrap_or_else(|_| DisplayName::parse("User").expect("valid"));

    let store_clone = store.clone();
    let email_for_create = email_parsed.clone();
    let display_name_for_create = display_name.clone();
    let user_result = tokio::task::spawn_blocking(move || {
        let user = (CreateUser {
            email: email_for_create,
            display_name: display_name_for_create,
        })
        .execute(store_clone.as_ref(), &SystemClock, &SecureIdGenerator)?;
        Ok::<_, authkit_core::domain::DomainError>(user)
    })
    .await;
    let user = match user_result {
        Ok(Ok(user)) => user,
        _ => {
            return html(
                StatusCode::CONFLICT,
                "Create account",
                "/register",
                "Create account",
                "An account with that email already exists.",
                "/login",
                "Sign in instead",
                "",
            )
        }
    };

    let credential = Credential::password(
        SecureIdGenerator.generate::<CredentialEntity>().expect("id"),
        user.id().clone(),
        verifier,
        now,
    );
    let store_clone = store.clone();
    let insert_result = tokio::task::spawn_blocking(move || {
        CredentialRepository::insert(store_clone.as_ref(), &credential)
    })
    .await;
    if insert_result.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }

    let created = match sessions
        .create(user.id().clone(), None, SessionAudience::Account, now)
        .await
    {
        Ok(value) => value,
        Err(_) => return unavailable(),
    };

    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let redirect_to = params.get("next").cloned().unwrap_or_else(|| "/".to_owned());
    let redirect_to = safe_redirect(&redirect_to);
    let mut response = redirect(&redirect_to);
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn find_user_by_email(
    store: &Arc<SqlStore>,
    email: &Email,
) -> Result<Option<User>, authkit_core::domain::DomainError> {
    UserRepository::find_by_email(store.as_ref(), email)
}

fn form_value(query: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn find_password_credential(
    store: &Arc<SqlStore>,
    user_id: &Id<UserEntity>,
) -> Result<Option<Credential>, authkit_core::domain::DomainError> {
    let credentials = authkit_core::ports::CredentialRepository::list_for_user(store.as_ref(), user_id)?;
    Ok(credentials
        .into_iter()
        .find(|credential| credential.kind() == authkit_core::domain::CredentialKind::Password && credential.is_active()))
}

fn parse_form(body: &[u8]) -> Result<std::collections::HashMap<String, String>, ()> {
    if body.len() > 64 * 1024 {
        return Err(());
    }
    let mut map = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        map.insert(key.into_owned(), value.into_owned());
    }
    Ok(map)
}

pub(crate) fn safe_redirect(value: &str) -> String {
    if value.starts_with('/') && !value.starts_with("//") && !value.contains('\n') && !value.contains('\r') {
        value.to_owned()
    } else {
        "/".to_owned()
    }
}

pub(crate) fn html(
    status: StatusCode,
    title: &str,
    action: &str,
    button: &str,
    error: &str,
    other_href: &str,
    other_text: &str,
    extra: &str,
) -> Response {
    let error_html = if error.is_empty() {
        String::new()
    } else {
        format!("<p style=\"color: red;\">{}</p>", escape(error))
    };
    let body = PAGE
        .replace("{title}", title)
        .replace("{action}", action)
        .replace("{button}", button)
        .replace("{error}", &error_html)
        .replace("{extra}", extra)
        .replace("{other_href}", other_href)
        .replace("{other_text}", other_text);
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response()
}

fn redirect(location: &str) -> Response {
    match axum::http::HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, location), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": "server_error"})),
        )
            .into_response(),
    }
}

fn rate_limited(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string()), (header::CACHE_CONTROL, "no-store".to_owned())],
        axum::Json(json!({"error": "rate_limited", "retry_after": retry_after})),
    )
        .into_response()
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": "invalid_request"})),
    )
        .into_response()
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": "temporarily_unavailable"})),
    )
        .into_response()
}

use authkit_store::SqlStore;
