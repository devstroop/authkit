//! Magic Auth (passwordless email code) handlers.

use askama::Template;
use authkit_core::domain::{Email, OneTimeToken, OneTimeTokenPurpose, WriteOutcome};
use authkit_core::ports::{
    IdGenerator, MembershipRepository, OneTimeTokenRepository, RateLimiter, UserRepository,
};
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::http::login::html;
use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::session::SecureIdGenerator;
use authkit_core::domain::SessionAudience;

#[derive(Template)]
#[template(path = "pages/magic_auth_request.html")]
struct MagicAuthRequestTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
}

#[derive(Template)]
#[template(path = "pages/magic_auth_verify.html")]
struct MagicAuthVerifyTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    email: &'a str,
}

pub(crate) async fn request_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let csrf = session
        .as_ref()
        .and_then(|s| {
            state
                .sessions
                .as_ref()
                .map(|svc| svc.csrf_token(s.session()))
        })
        .unwrap_or_default();
    let template = MagicAuthRequestTemplate {
        title: "Sign in with email code",
        csrf: &csrf,
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

pub(crate) async fn request_submit(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.to_string(), v.to_string());
    }
    let email_str = params.get("email").cloned().unwrap_or_default();
    let parsed_email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => {
            return html(
                StatusCode::BAD_REQUEST,
                "Sign in with email code",
                "/magic-auth",
                "Send code",
                "Invalid email.",
                "/login",
                "Sign in with password",
                "",
            );
        }
    };

    // rate limit
    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let key = format!("magic_auth:{}", email_str.to_lowercase());
    let result = tokio::task::spawn_blocking({
        let store = store.clone();
        let key = key.clone();
        move || RateLimiter::check(store.as_ref(), &key, 5, 900, now)
    })
    .await;
    if let Ok(Err(err)) = result {
        return rate_limited(err.retry_after_secs);
    }

    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = parsed_email.clone();
        move || UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if let Some(user) = user {
        // generate 6-digit code
        use rand_core::{OsRng, RngCore};
        let code: u32 = (OsRng.next_u32() % 900000) + 100000;
        let code_str = format!("{:06}", code);
        let pepper = sessions.pepper().to_vec();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&pepper);
        hasher.update(code_str.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        let secret_hash = match authkit_core::domain::SecretHash::parse(hash) {
            Ok(v) => v,
            Err(_) => return unavailable(),
        };
        let expires = authkit_core::domain::time::Timestamp::from_millis(
            now.as_millis().saturating_add(10 * 60 * 1000),
        );
        let token = OneTimeToken::new(
            SecureIdGenerator
                .generate::<authkit_core::domain::id::OneTimeTokenEntity>()
                .expect("id"),
            user.id().clone(),
            OneTimeTokenPurpose::MagicAuth,
            secret_hash,
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
            let _ = state.email.send(
                &parsed_email,
                "Your sign-in code",
                &format!("Your sign-in code is: {}", code_str),
            );
            #[cfg(debug_assertions)]
            tracing::info!(
                target = "authkit.dev.magic_auth",
                "magic auth code for {} (dev only): {}",
                email_str,
                code_str
            );
        }
    }

    // generic response
    let body = "<p>If an account exists, a sign-in code has been sent.</p>".to_owned();
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

pub(crate) async fn verify_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let csrf = session
        .as_ref()
        .and_then(|s| {
            state
                .sessions
                .as_ref()
                .map(|svc| svc.csrf_token(s.session()))
        })
        .unwrap_or_default();
    let email = q.get("email").cloned().unwrap_or_default();
    let template = MagicAuthVerifyTemplate {
        title: "Enter your code",
        csrf: &csrf,
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

pub(crate) async fn verify_submit(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.to_string(), v.to_string());
    }
    let email_str = params.get("email").cloned().unwrap_or_default();
    let code_str = params.get("code").cloned().unwrap_or_default();
    if email_str.is_empty() || code_str.is_empty() {
        return html(
            StatusCode::BAD_REQUEST,
            "Enter your code",
            "/magic-auth/verify",
            "Verify",
            "Email and code are required.",
            "/magic-auth",
            "Request a new code",
            "",
        );
    }
    let parsed_email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => {
            return html(
                StatusCode::BAD_REQUEST,
                "Enter your code",
                "/magic-auth/verify",
                "Verify",
                "Invalid email.",
                "/magic-auth",
                "Request a new code",
                "",
            );
        }
    };
    let pepper = sessions.pepper().to_vec();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&pepper);
    hasher.update(code_str.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    let secret_hash = match authkit_core::domain::SecretHash::parse(hash) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };

    let find_result = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let hash = secret_hash.clone();
        move || {
            OneTimeTokenRepository::find_by_hash(
                store.as_ref(),
                &hash,
                OneTimeTokenPurpose::MagicAuth,
            )
        }
    })
    .await;
    let token = find_result.ok().and_then(|r| r.ok().flatten());

    let Some(token) = token else {
        return html(
            StatusCode::BAD_REQUEST,
            "Enter your code",
            "/magic-auth/verify",
            "Verify",
            "Invalid or expired code.",
            "/magic-auth",
            "Request a new code",
            "",
        );
    };
    if token.consumed_at().is_some() {
        return html(
            StatusCode::BAD_REQUEST,
            "Enter your code",
            "/magic-auth/verify",
            "Verify",
            "Code already used.",
            "/magic-auth",
            "Request a new code",
            "",
        );
    }
    if token.expires_at().is_before(sessions.clock().now()) {
        return html(
            StatusCode::BAD_REQUEST,
            "Enter your code",
            "/magic-auth/verify",
            "Verify",
            "Code expired.",
            "/magic-auth",
            "Request a new code",
            "",
        );
    }
    // verify user email matches
    let user = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let uid = token.user_id().clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return unavailable();
    };
    if user.email().as_str() != parsed_email.as_str() {
        return html(
            StatusCode::BAD_REQUEST,
            "Enter your code",
            "/magic-auth/verify",
            "Verify",
            "Invalid or expired code.",
            "/magic-auth",
            "Request a new code",
            "",
        );
    }

    // consume token
    let consumed = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let tid = token.id().clone();
        let now = sessions.clock().now();
        move || OneTimeTokenRepository::consume(store.as_ref(), &tid, now)
    })
    .await;
    if consumed.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return html(
            StatusCode::BAD_REQUEST,
            "Enter your code",
            "/magic-auth/verify",
            "Verify",
            "Code already used.",
            "/magic-auth",
            "Request a new code",
            "",
        );
    }

    // Organization selection for multi-org users.
    let memberships = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let uid = user.id().clone();
        move || MembershipRepository::list_for_user(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let active_orgs: Vec<_> = memberships.into_iter().filter(|m| m.is_active()).collect();
    if active_orgs.len() > 1 {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let token_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let pepper = sessions.pepper().to_vec();
        let hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&pepper);
            hasher.update(token_str.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let secret_hash = match authkit_core::domain::SecretHash::parse(hash) {
            Ok(v) => v,
            Err(_) => return unavailable(),
        };
        let now = sessions.clock().now();
        let expires = authkit_core::domain::time::Timestamp::from_millis(
            now.as_millis().saturating_add(5 * 60 * 1000),
        );
        let ott = authkit_core::domain::OneTimeToken::new(
            crate::session::SecureIdGenerator
                .generate::<authkit_core::domain::id::OneTimeTokenEntity>()
                .expect("id"),
            user.id().clone(),
            authkit_core::domain::OneTimeTokenPurpose::OrgSelection,
            secret_hash,
            now,
            expires,
        )
        .expect("token");
        let store_clone = sessions.store().clone();
        let _ = tokio::task::spawn_blocking(move || {
            authkit_core::ports::OneTimeTokenRepository::insert(store_clone.as_ref(), &ott)
        })
        .await;
        let location = format!("/select-organization?token={}", token_str);
        return redirect(&location);
    }

    let now = sessions.clock().now();
    let created = match sessions
        .create(user.id().clone(), None, SessionAudience::Account, now)
        .await
    {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let redirect_to = params
        .get("next")
        .cloned()
        .unwrap_or_else(|| "/".to_owned());
    let mut response = redirect(&redirect_to);
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "Service unavailable",
    )
        .into_response()
}

fn rate_limited(retry_after: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        format!("Rate limited. Retry after {} seconds.", retry_after),
    )
        .into_response()
}

fn redirect(location: &str) -> Response {
    match axum::http::HeaderValue::from_str(location) {
        Ok(value) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, value),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "Bad request",
        )
            .into_response(),
    }
}
