//! TOTP MFA pages.

use authkit_core::domain::{Credential, CredentialKind, Id, User};
use authkit_core::domain::id::{CredentialEntity, UserEntity};
use authkit_core::ports::{CredentialRepository, IdGenerator};
use authkit_core::domain::WriteOutcome;
use axum::extract::{Extension, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::password::verify_password;
use authkit_core::domain::SessionAudience;
use crate::session::SystemClock;
use crate::totp;

pub(crate) async fn account_page(
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
    let has_mfa = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || {
            let creds = CredentialRepository::list_for_user(store.as_ref(), &user_id).unwrap_or_default();
            creds.into_iter().any(|c| c.kind() == CredentialKind::Totp && c.is_active())
        }
    })
    .await
    .unwrap_or(false);

    let body = if has_mfa {
        format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MFA</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>MFA enabled</h1><form method="post" action="/account/mfa/disable"><input type="hidden" name="_csrf" value="{}"><button type="submit">Disable MFA</button></form></body></html>"#,
            escape(&csrf)
        )
    } else {
        format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MFA</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Enroll MFA</h1><form method="post" action="/account/mfa/enroll"><input type="hidden" name="_csrf" value="{}"><button type="submit">Generate secret</button></form></body></html>"#,
            escape(&csrf)
        )
    };
    html_ok(&body)
}

pub(crate) async fn enroll(
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
    let pepper = sessions.pepper().to_vec();
    let secret = totp::generate_secret();
    let encoded = totp::base32_encode(&secret);
    let encrypted = match totp::encrypt_secret(&secret, &pepper) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let now = sessions.clock().now();
    let credential = Credential::totp(
        crate::session::SecureIdGenerator.generate::<CredentialEntity>().expect("id"),
        user_id.clone(),
        encrypted,
        authkit_core::domain::credential::TotpConfig::default(),
        now,
    );
    let outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let credential = credential.clone();
        move || CredentialRepository::insert(store.as_ref(), &credential)
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>MFA enrollment</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Enroll MFA</h1><p>Secret: <code>{}</code></p><form method="post" action="/account/mfa/verify"><input type="hidden" name="_csrf" value="{}"><label>Code <input name="code" required></label><button type="submit">Verify</button></form></body></html>"#,
        escape(&encoded),
        escape(&csrf)
    );
    html_ok(&body)
}

pub(crate) async fn verify_enrollment(
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
    let mut params = parse_form(&body);
    let code = params.remove("code").unwrap_or_default();
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let pepper = sessions.pepper().to_vec();
    let now = sessions.clock().now();
    let creds = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || CredentialRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let cred = creds.into_iter().find(|c| c.kind() == CredentialKind::Totp && c.is_active());
    let Some(mut cred) = cred else {
        return bad_request();
    };
    let totp = match cred.as_totp() {
        Some(v) => v,
        None => return bad_request(),
    };
    let secret = match totp::decrypt_secret(totp.secret(), &pepper) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let step = match totp::verify_code(&secret, &code, totp.config(), cred.as_totp().unwrap().last_accepted_step()) {
        Some(v) => v,
        None => return bad_request(),
    };
    if cred.accept_totp_step(step, now).is_err() {
        return bad_request();
    }
    let original_version = cred.version();
    let updated = cred.clone();
    let outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let updated = updated.clone();
        move || CredentialRepository::update(store.as_ref(), &updated, original_version)
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }
    redirect("/account/mfa")
}

pub(crate) async fn disable(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    _body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let creds = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || CredentialRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    for cred in creds {
        if cred.kind() != CredentialKind::Totp || !cred.is_active() {
            continue;
        }
        let original_version = cred.version();
        let mut updated = cred.clone();
        updated.disable(sessions.clock().now());
        let _ = tokio::task::spawn_blocking({
            let store = store.clone();
            let updated = updated.clone();
            move || CredentialRepository::update(store.as_ref(), &updated, original_version)
        })
        .await;
    }
    redirect("/account/mfa")
}

// helpers
fn parse_form(body: &axum::body::Bytes) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(body) {
        params.insert(k.into_owned(), v.into_owned());
    }
    params
}

fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, location), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "unavailable"})),
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

fn html_ok(body: &str) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body.to_owned(),
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

pub(crate) async fn login_verify(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = parse_form(&body);
    let challenge = params.remove("challenge").unwrap_or_default();
    let code = params.remove("code").unwrap_or_default();
    let next = params.remove("next").unwrap_or_else(|| "/".to_owned());
    let next = crate::http::login::safe_redirect(&next);
    let pepper = sessions.pepper().to_vec();
    let user_id = match crate::totp::verify_challenge(&challenge, &next, &pepper) {
        Some(v) => v,
        None => return bad_request(),
    };
    let user_id = match Id::<UserEntity>::parse(&user_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let creds = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || CredentialRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let mut cred = match creds.into_iter().find(|c| c.kind() == CredentialKind::Totp && c.is_active()) {
        Some(c) => c,
        None => return bad_request(),
    };
    let totp = match cred.as_totp() {
        Some(v) => v,
        None => return bad_request(),
    };
    let secret = match crate::totp::decrypt_secret(totp.secret(), &pepper) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let step = match crate::totp::verify_code(&secret, &code, totp.config(), totp.last_accepted_step()) {
        Some(v) => v,
        None => return bad_request(),
    };
    if cred.accept_totp_step(step, now).is_err() {
        return bad_request();
    }
    let original_version = cred.version();
    let updated = cred.clone();
    let _ = tokio::task::spawn_blocking({
        let store = store.clone();
        let updated = updated.clone();
        move || CredentialRepository::update(store.as_ref(), &updated, original_version)
    })
    .await;

    let created = match sessions.create(user_id, None, SessionAudience::Account, now).await {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let mut response = redirect(&next);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}
