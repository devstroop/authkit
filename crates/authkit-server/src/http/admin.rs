//! System administration pages.

use authkit_core::domain::{Credential, CredentialKind, Email, Id, SystemAdministrator, SystemAdministratorStatus};
use authkit_core::domain::id::{CredentialEntity, SystemAdministratorEntity};
use authkit_core::ports::{CredentialRepository, IdGenerator, SystemAdministratorRepository, UserRepository};
use authkit_core::domain::WriteOutcome;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::password::verify_password;
use crate::totp;
use authkit_core::domain::SessionAudience;
use crate::config::Config;

pub(crate) async fn login_page() -> Response {
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Admin sign in</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Admin sign in</h1><form method="post" action="/admin/login"><label>Email <input type="email" name="email" required></label><br><label>Password <input type="password" name="password" required></label><br><button type="submit">Sign in</button></form></body></html>"#;
    html_ok(body)
}

pub(crate) async fn login_submit(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = parse_form(&body);
    let email_str = params.remove("email").unwrap_or_default();
    let password = params.remove("password").unwrap_or_default();
    if email_str.is_empty() || password.is_empty() {
        return bad_request();
    }
    let email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = email.clone();
        move || UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return unauthorized();
    };
    let credential = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user.id().clone();
        move || {
            let creds = CredentialRepository::list_for_user(store.as_ref(), &user_id)?;
            Ok::<_, authkit_core::domain::DomainError>(
                creds.into_iter().find(|c| c.kind() == authkit_core::domain::CredentialKind::Password && c.is_active()),
            )
        }
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(credential) = credential else {
        return unauthorized();
    };
    let verifier = match credential.as_password() {
        Some(v) => v.clone(),
        None => return unauthorized(),
    };
    if !verify_password(&password, &verifier) {
        return unauthorized();
    }
    let admin = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user.id().clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(admin) = admin else {
        return unauthorized();
    };
    if !admin.is_active() {
        return unauthorized();
    }
    let created = match sessions.create(user.id().clone(), None, SessionAudience::Admin, now).await {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let cookie = sessions.set_cookie(&created.session(), created.token(), now);
    let mut response = redirect("/admin");
    append_cookie(&mut response, cookie);
    response
}

pub(crate) async fn dashboard(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let admin = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if admin.is_none() {
        return forbidden();
    }

    let has_mfa = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || {
            CredentialRepository::list_for_user(store.as_ref(), &user_id)
                .unwrap_or_default()
                .into_iter()
                .any(|c| c.kind() == CredentialKind::Totp && c.is_active())
        }
    })
    .await
    .unwrap_or(false);

    if !has_mfa {
        let body = format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Admin MFA enrollment</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>MFA required</h1><form method="post" action="/admin/mfa/enroll"><input type="hidden" name="_csrf" value="{}"><button type="submit">Generate secret</button></form></body></html>"#,
            escape(&csrf)
        );
        return html_ok(&body);
    }

    let admins = tokio::task::spawn_blocking({
        let store = store.clone();
        move || SystemAdministratorRepository::list(store.as_ref())
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let mut admin_rows = String::new();
    for a in admins {
        let email = tokio::task::spawn_blocking({
            let store = store.clone();
            let uid = a.user_id().clone();
            move || UserRepository::find_by_id(store.as_ref(), &uid).ok().flatten().map(|u| u.email().as_str().to_owned()).unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        admin_rows.push_str(&format!(
            "<li>{} ({}) {} {}</li>",
            escape(&email),
            a.id().as_str(),
            if a.is_active() { "active" } else { "disabled" },
            if a.is_active() {
                format!(r#"<form method="post" action="/admin/administrators/{}/disable" style="display:inline"><input type="hidden" name="_csrf" value="{}"><button type="submit">Disable</button></form>"#, a.id().as_str(), escape(&csrf))
            } else {
                String::new()
            }
        ));
    }

    let keys = state.keys.clone();
    let mut key_rows = String::new();
    for k in keys.keys() {
        key_rows.push_str(&format!(
            "<li>{} {} {}</li>",
            escape(k.kid()),
            format!("{:?}", k.state()),
            if k.publish_until().is_some() { "published" } else { "" }
        ));
    }

    let events = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.list_all_audit_events(20)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let mut event_rows = String::new();
    for e in events {
        event_rows.push_str(&format!(
            "<li>{} {} {}</li>",
            e.occurred_at().as_millis(),
            escape(e.action().as_str()),
            e.organization_id().map(|o| o.as_str()).unwrap_or("-")
        ));
    }

    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>System administration</title></head><body style="font-family: system-ui, sans-serif; max-width: 48rem; margin: 4rem auto; padding: 0 1rem;">
<h1>System administration</h1>
<h2>System administrators</h2>
<ul>{admin_rows}</ul>
<form method="post" action="/admin/administrators"><input type="hidden" name="_csrf" value="{csrf}"><label>Email <input type="email" name="email" required></label><button type="submit">Grant admin</button></form>
<h2>Signing keys</h2>
<ul>{key_rows}</ul>
<form method="post" action="/admin/signing-keys/rotate"><input type="hidden" name="_csrf" value="{csrf}"><button type="submit">Rotate signing key</button></form>
<h2>Recent audit events</h2>
<ul>{event_rows}</ul>
<form method="post" action="/admin/logout"><input type="hidden" name="_csrf" value="{csrf}"><button type="submit">Sign out</button></form>
</body></html>"#,
        admin_rows = admin_rows,
        csrf = escape(&csrf),
        key_rows = key_rows,
        event_rows = event_rows
    );
    html_ok(&body)
}

pub(crate) async fn grant_admin(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if caller.map(|a| a.is_active()).unwrap_or(false) == false {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let email_str = params.remove("email").unwrap_or_default();
    let email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let target_user = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = email.clone();
        move || UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(target_user) = target_user else {
        return bad_request();
    };
    let now = sessions.clock().now();
    let created_by = session.session().user_id().clone();
    let admin = SystemAdministrator::new(
        crate::session::SecureIdGenerator.generate::<SystemAdministratorEntity>().expect("id"),
        target_user.id().clone(),
        Some(created_by),
        now,
    );
    let outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let admin = admin.clone();
        move || SystemAdministratorRepository::insert(store.as_ref(), &admin)
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        redirect("/admin")
    } else {
        unavailable()
    }
}

pub(crate) async fn disable_admin(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(id): Path<String>,
    _body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if caller.map(|a| a.is_active()).unwrap_or(false) == false {
        return forbidden();
    }
    let parsed_id = match Id::<SystemAdministratorEntity>::parse(&id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let now = sessions.clock().now();
    let outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let parsed_id = parsed_id.clone();
        let now = now;
        move || {
            let admin = SystemAdministratorRepository::find_by_id(store.as_ref(), &parsed_id)?;
            let Some(mut admin) = admin else {
                return Ok::<_, authkit_core::domain::DomainError>(WriteOutcome::NotFound);
            };
            let active_count = SystemAdministratorRepository::list(store.as_ref())?
                .into_iter()
                .filter(|a| a.is_active())
                .count() as u64;
            authkit_core::domain::ensure_system_admin_remains(active_count, admin.is_active())?;
            let expected = admin.version();
            admin.disable(now);
            SystemAdministratorRepository::update(store.as_ref(), &admin, expected)
        }
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        redirect("/admin")
    } else {
        unavailable()
    }
}

pub(crate) async fn rotate_signing_key(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    _body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if caller.map(|a| a.is_active()).unwrap_or(false) == false {
        return forbidden();
    }
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(_) => return unavailable(),
    };
    let now = crate::signing::unix_now();
    match crate::signing::KeyRing::rotate(config.signing_keys(), now) {
        Ok(_) => redirect("/admin"),
        Err(_) => unavailable(),
    }
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    _body: axum::body::Bytes,
) -> Response {
    if let Some(Extension(session)) = session {
        if let Some(sessions) = state.sessions.as_ref() {
            let store = sessions.store().clone();
            let sid = session.session().id().clone();
            let now = sessions.clock().now();
            let _ = tokio::task::spawn_blocking(move || {
                if let Some(mut s) = authkit_core::ports::SessionRepository::find_by_id(store.as_ref(), &sid)? {
                    let expected = s.version();
                    s.revoke(now);
                    let _ = authkit_core::ports::SessionRepository::update(store.as_ref(), &s, expected);
                }
                Ok::<_, authkit_core::domain::DomainError>(())
            })
            .await;
        }
    }
    redirect("/admin/login")
}


pub(crate) async fn mfa_enroll(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let pepper = sessions.pepper().to_vec();
    let secret = crate::totp::generate_secret();
    let encoded = crate::totp::base32_encode(&secret);
    let encrypted = match crate::totp::encrypt_secret(&secret, &pepper) {
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
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Admin MFA enrollment</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Enroll MFA</h1><p>Secret: <code>{}</code></p><form method="post" action="/admin/mfa/verify"><input type="hidden" name="_csrf" value="{}"><label>Code <input name="code" required></label><button type="submit">Verify</button></form></body></html>"#,
        escape(&encoded),
        escape(&csrf)
    );
    html_ok(&body)
}

pub(crate) async fn mfa_verify(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
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
    let mut cred = match creds.into_iter().find(|c| c.kind() == CredentialKind::Totp && c.is_active()) {
        Some(c) => c,
        None => return bad_request(),
    };
    let totp = match cred.as_totp() {
        Some(v) => v,
        None => return bad_request(),
    };
    let secret = match totp::decrypt_secret(totp.secret(), &pepper) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let step = match totp::verify_code(&secret, &code, totp.config(), totp.last_accepted_step()) {
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
    redirect("/admin")
}

// helpers
fn append_cookie(response: &mut Response, cookie: String) {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

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

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "forbidden"})),
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
