//! System administration pages.

use askama::Template;
use authkit_core::domain::WriteOutcome;
use authkit_core::domain::id::{CredentialEntity, SystemAdministratorEntity, UserEntity};
use authkit_core::domain::{Credential, CredentialKind, DisplayName, Email, Id, SystemAdministrator};
use authkit_core::ports::{
    CredentialRepository, IdGenerator, SystemAdministratorRepository, UserRepository,
};
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::config::Config;
use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::password::verify_password;
use crate::totp;
use authkit_core::domain::SessionAudience;

#[derive(Template)]
#[template(path = "pages/admin_login.html")]
struct AdminLoginTemplate {
    title: &'static str,
}

pub(crate) async fn login_page() -> Response {
    let template = AdminLoginTemplate {
        title: "title_admin_sign_in",
    };
    let body = template.render().unwrap_or_default();
    html_ok(&body)
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
            Ok::<_, authkit_core::domain::DomainError>(creds.into_iter().find(|c| {
                c.kind() == authkit_core::domain::CredentialKind::Password && c.is_active()
            }))
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
    let created = match sessions
        .create(user.id().clone(), None, SessionAudience::Admin, now)
        .await
    {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let mut response = redirect("/admin");
    append_cookie(&mut response, cookie);
    response
}

#[derive(Template)]
#[template(path = "pages/admin_audit.html")]
struct AdminAuditTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    action_filter: &'a str,
    limit: i64,
    offset: i64,
    total: i64,
    events: Vec<AuditView>,
}

#[derive(Template)]
#[template(path = "pages/admin.html")]
struct AdminTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    can_manage: bool,
    admins: Vec<AdminView>,
    keys: Vec<KeyView>,
    events: Vec<EventView>,
}

struct AdminView {
    email: String,
    id: String,
    status: String,
    active: bool,
}

struct KeyView {
    kid: String,
    state: String,
    published: String,
}

struct EventView {
    occurred_at: i64,
    action: String,
    org: String,
}

struct AuditView {
    occurred_at: i64,
    action: String,
    org: String,
    actor: String,
}

#[derive(Clone)]
struct UserView {
    email: String,
    id: String,
    status: String,
    verified: bool,
}

#[derive(askama::Template)]
#[template(path = "pages/admin_users.html")]
struct AdminUsersTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    can_manage: bool,
    users: Vec<UserView>,
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
        let template = AdminMfaRequiredTemplate {
            title: "title_mfa_enroll",
            csrf: &csrf,
        };
        let body = template.render().unwrap_or_default();
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
    let mut admin_views = Vec::new();
    for a in admins {
        let email = tokio::task::spawn_blocking({
            let store = store.clone();
            let uid = a.user_id().clone();
            move || {
                UserRepository::find_by_id(store.as_ref(), &uid)
                    .ok()
                    .flatten()
                    .map(|u| u.email().as_str().to_owned())
                    .unwrap_or_default()
            }
        })
        .await
        .unwrap_or_default();
        admin_views.push(AdminView {
            email,
            id: a.id().as_str().to_owned(),
            status: if a.is_active() {
                "active".to_owned()
            } else {
                "disabled".to_owned()
            },
            active: a.is_active(),
        });
    }

    let keys = state.keys.clone();
    let key_views: Vec<KeyView> = keys
        .keys()
        .iter()
        .map(|k| KeyView {
            kid: k.kid().to_owned(),
            state: format!("{:?}", k.state()),
            published: if k.publish_until().is_some() {
                "published".to_owned()
            } else {
                String::new()
            },
        })
        .collect();

    let events = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.list_all_audit_events(20)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let event_views: Vec<EventView> = events
        .into_iter()
        .map(|e| EventView {
            occurred_at: e.occurred_at().as_millis() as i64,
            action: e.action().as_str().to_owned(),
            org: e
                .organization_id()
                .map(|o| o.as_str().to_owned())
                .unwrap_or_else(|| "-".to_owned()),
        })
        .collect();

    let caller_is_super = admin.as_ref().map(|a| a.is_super_admin()).unwrap_or(false);
    let template = AdminTemplate {
        title: "title_admin",
        csrf: &csrf,
        can_manage: caller_is_super,
        admins: admin_views,
        keys: key_views,
        events: event_views,
    };
    let body = template.render().unwrap_or_default();
    html_ok(&body)
}

pub(crate) async fn audit_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let user_id = session.session().user_id().clone();
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if caller.is_none() {
        return forbidden();
    }

    let mut action_filter = String::new();
    let mut limit: i64 = 50;
    let mut offset: i64 = 0;
    let mut format = String::new();
    if let Some(q) = query.as_deref() {
        for pair in q.split('&') {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("action"), Some(v)) => action_filter = urlencoding_decode(v),
                (Some("limit"), Some(v)) => {
                    if let Ok(n) = v.parse::<i64>() {
                        limit = n.clamp(1, 200);
                    }
                }
                (Some("offset"), Some(v)) => {
                    if let Ok(n) = v.parse::<i64>() {
                        if n >= 0 {
                            offset = n;
                        }
                    }
                }
                (Some("format"), Some(v)) => format = v.to_owned(),
                _ => {}
            }
        }
    }

    let filter_opt = if action_filter.is_empty() {
        None
    } else {
        Some(action_filter.as_str())
    };

    if format == "csv" || format == "json" {
        let events = tokio::task::spawn_blocking({
            let store = store.clone();
            let filter_opt = filter_opt.map(str::to_owned);
            move || {
                store
                    .list_audit_events_filtered(filter_opt.as_deref(), 10_000, 0)
                    .unwrap_or_default()
            }
        })
        .await
        .unwrap_or_default();
        if format == "json" {
            let mut rows = Vec::new();
            for e in events {
                rows.push(serde_json::json!({
                    "id": e.id().as_str(),
                    "organization_id": e.organization_id().map(|o| o.as_str().to_owned()),
                    "actor": format!("{:?}", e.actor()),
                    "action": e.action().as_str(),
                    "target": e.target().map(|t| t.as_str().to_owned()),
                    "occurred_at": e.occurred_at().as_millis() as i64,
                    "attributes": e.attributes().iter().map(|a| (a.key().to_owned(), a.value().to_owned())).collect::<std::collections::BTreeMap<_,_>>(),
                }));
            }
            let body = serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_owned());
            let mut response = (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                body,
            )
                .into_response();
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"audit-events.json\""),
            );
            return response;
        }
        // csv
        let mut csv = String::from("id,organization_id,actor,action,target,occurred_at\n");
        for e in events {
            csv.push_str(&format!(
                "{},{},{},{},{},{}\n",
                csv_field(e.id().as_str()),
                csv_field(e.organization_id().map(|o| o.as_str()).unwrap_or("")),
                csv_field(&format!("{:?}", e.actor())),
                csv_field(e.action().as_str()),
                csv_field(e.target().map(|t| t.as_str()).unwrap_or("")),
                e.occurred_at().as_millis() as i64,
            ));
        }
        let mut response = (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            csv,
        )
            .into_response();
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"audit-events.csv\""),
        );
        return response;
    }

    let total = tokio::task::spawn_blocking({
        let store = store.clone();
        let filter_opt = filter_opt.map(str::to_owned);
        move || store.count_audit_events(filter_opt.as_deref()).unwrap_or(0)
    })
    .await
    .unwrap_or(0);

    let events = tokio::task::spawn_blocking({
        let store = store.clone();
        let filter_opt = filter_opt.map(str::to_owned);
        move || {
            store
                .list_audit_events_filtered(filter_opt.as_deref(), limit, offset)
                .unwrap_or_default()
        }
    })
    .await
    .unwrap_or_default();
    let event_views: Vec<AuditView> = events
        .into_iter()
        .map(|e| AuditView {
            occurred_at: e.occurred_at().as_millis() as i64,
            action: e.action().as_str().to_owned(),
            org: e
                .organization_id()
                .map(|o| o.as_str().to_owned())
                .unwrap_or_else(|| "-".to_owned()),
            actor: format!("{:?}", e.actor()),
        })
        .collect();
    let template = AdminAuditTemplate {
        title: "title_audit",
        csrf: &csrf,
        action_filter: &action_filter,
        limit,
        offset,
        total,
        events: event_views,
    };
    let body = template.render().unwrap_or_default();
    html_ok(&body)
}


pub(crate) async fn users_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let user_id = session.session().user_id().clone();
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if caller.is_none() {
        return forbidden();
    }
    let can_manage = caller.map(|a| a.is_super_admin()).unwrap_or(false);
    let users = tokio::task::spawn_blocking({
        let store = store.clone();
        move || UserRepository::list(store.as_ref())
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let user_views: Vec<UserView> = users
        .into_iter()
        .map(|u| UserView {
            email: u.email().as_str().to_owned(),
            id: u.id().as_str().to_owned(),
            status: format!("{:?}", u.status()),
            verified: u.email_verified_at().is_some(),
        })
        .collect();
    let template = AdminUsersTemplate {
        title: "title_users",
        csrf: &csrf,
        can_manage,
        users: user_views,
    };
    let body = template.render().unwrap_or_default();
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
    if !caller.map(|a| a.is_active()).unwrap_or(false) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let code = params.remove("code").unwrap_or_default();
    let user_id = session.session().user_id().clone();
    if !admin_totp_step_up(sessions, user_id.clone(), &code).await {
        return forbidden();
    }
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
        crate::session::SecureIdGenerator
            .generate::<SystemAdministratorEntity>()
            .expect("id"),
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
    if outcome
        .ok()
        .and_then(|r| r.ok())
        .map(|o| o.is_applied())
        .unwrap_or(false)
    {
        redirect("/admin")
    } else {
        unavailable()
    }
}

pub(crate) async fn disable_admin(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(id): Path<String>,
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
    if !caller.map(|a| a.is_active()).unwrap_or(false) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let code = params.remove("code").unwrap_or_default();
    let user_id = session.session().user_id().clone();
    if !admin_totp_step_up(sessions, user_id.clone(), &code).await {
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
    if outcome
        .ok()
        .and_then(|r| r.ok())
        .map(|o| o.is_applied())
        .unwrap_or(false)
    {
        redirect("/admin")
    } else {
        unavailable()
    }
}

pub(crate) async fn rotate_signing_key(
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
    if !caller.map(|a| a.is_active()).unwrap_or(false) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let code = params.remove("code").unwrap_or_default();
    if !admin_totp_step_up(sessions, user_id.clone(), &code).await {
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
    if let Some(Extension(session)) = session
        && let Some(sessions) = state.sessions.as_ref()
    {
        let store = sessions.store().clone();
        let sid = session.session().id().clone();
        let now = sessions.clock().now();
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(mut s) =
                authkit_core::ports::SessionRepository::find_by_id(store.as_ref(), &sid)?
            {
                let expected = s.version();
                s.revoke(now);
                let _ =
                    authkit_core::ports::SessionRepository::update(store.as_ref(), &s, expected);
            }
            Ok::<_, authkit_core::domain::DomainError>(())
        })
        .await;
    }
    redirect("/admin/login")
}

#[derive(askama::Template)]
#[template(path = "pages/admin_mfa_required.html")]
struct AdminMfaRequiredTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
}

#[derive(askama::Template)]
#[template(path = "pages/admin_mfa_enroll.html")]
struct AdminMfaEnrollTemplate<'a> {
    title: &'a str,
    secret: &'a str,
    csrf: &'a str,
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
        crate::session::SecureIdGenerator
            .generate::<CredentialEntity>()
            .expect("id"),
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
    let template = AdminMfaEnrollTemplate {
        title: "title_mfa_enroll",
        secret: &encoded,
        csrf: &csrf,
    };
    let body = template.render().unwrap_or_default();
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
    let mut cred = match creds
        .into_iter()
        .find(|c| c.kind() == CredentialKind::Totp && c.is_active())
    {
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

#[derive(askama::Template)]
#[template(path = "pages/setup.html")]
struct SetupTemplate<'a> {
    title: &'a str,
    error: &'a str,
}


#[derive(askama::Template)]
#[template(path = "pages/admin_restore.html")]
struct AdminRestoreTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    message: &'a str,
    error: &'a str,
}

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
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

pub(crate) async fn impersonate(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(_admin_session)) = session else {
        return redirect("/admin/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let uid = match Id::<UserEntity>::parse(user_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let uid = uid.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return bad_request();
    };
    let now = sessions.clock().now();
    let created = match sessions
        .create(user.id().clone(), None, SessionAudience::Account, now)
        .await
    {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let flag_cookie = "authkit_impersonating=1; Path=/; Max-Age=3600";
    let mut response = redirect("/");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    if let Ok(value) = HeaderValue::from_str(flag_cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub(crate) async fn impersonate_exit(State(state): State<AppState>) -> Response {
    let clear_account = state
        .sessions
        .as_ref()
        .map(|s| s.clear_cookie(SessionAudience::Account))
        .unwrap_or_else(|| "authkit_account=; Path=/; Max-Age=0".to_owned());
    let mut response = redirect("/admin");
    if let Ok(value) = HeaderValue::from_str(&clear_account) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    if let Ok(value) = HeaderValue::from_str("authkit_impersonating=; Path=/; Max-Age=0") {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}


fn urlencoding_decode(value: &str) -> String {
    url::form_urlencoded::parse(format!("x={value}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| value.to_owned())
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}


pub(crate) async fn setup_page(
    State(state): State<AppState>,
    _session: Option<Extension<SessionContext>>,
) -> Response {
    if let Some(sessions) = state.sessions.as_ref() {
        let store = sessions.store().clone();
        let count = tokio::task::spawn_blocking(move || {
            SystemAdministratorRepository::list(store.as_ref())
                .map(|v| v.len())
                .unwrap_or(0)
        })
        .await
        .unwrap_or(0);
        if count > 0 {
            return redirect("/admin/login");
        }
    }
    let template = SetupTemplate {
        title: "title_setup",
        error: "",
    };
    let body = template.render().unwrap_or_default();
    html_ok(&body)
}

pub(crate) async fn setup_submit(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let store = sessions.store().clone();
    let count = tokio::task::spawn_blocking({
        let store = store.clone();
        move || SystemAdministratorRepository::list(store.as_ref()).map(|v| v.len()).unwrap_or(0)
    })
    .await
    .unwrap_or(0);
    if count > 0 {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let email_str = params.remove("email").unwrap_or_default();
    let password = params.remove("password").unwrap_or_default();
    if email_str.is_empty() || password.is_empty() || password.len() < 12 {
        return bad_request();
    }
    let email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let _ = tokio::task::spawn_blocking({
        let store = store.clone();
        move || store.migrate()
    })
    .await;
    let now = sessions.clock().now();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = email.clone();
        move || UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let user = if let Some(existing) = user {
        existing
    } else {
        let display_name = DisplayName::parse(email_str.split('@').next().unwrap_or("admin"))
            .unwrap_or_else(|_| DisplayName::parse("Admin").expect("valid"));
        let new_user = authkit_core::domain::User::new(
            crate::session::SecureIdGenerator
                .generate::<authkit_core::domain::id::UserEntity>()
                .expect("id"),
            email.clone(),
            display_name,
            now,
        );
        let outcome = tokio::task::spawn_blocking({
            let store = store.clone();
            let new_user = new_user.clone();
            move || UserRepository::insert(store.as_ref(), &new_user)
        })
        .await;
        if !outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
            return unavailable();
        }
        new_user
    };
    let verifier = match crate::password::hash_password(&password) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let credential = Credential::password(
        crate::session::SecureIdGenerator
            .generate::<authkit_core::domain::id::CredentialEntity>()
            .expect("id"),
        user.id().clone(),
        verifier,
        now,
    );
    let cred_outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let credential = credential.clone();
        move || CredentialRepository::insert(store.as_ref(), &credential)
    })
    .await;
    if !cred_outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        return unavailable();
    }
    let admin = SystemAdministrator::new(
        crate::session::SecureIdGenerator
            .generate::<authkit_core::domain::id::SystemAdministratorEntity>()
            .expect("id"),
        user.id().clone(),
        None,
        now,
    );
    let admin_outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let admin = admin.clone();
        move || SystemAdministratorRepository::insert(store.as_ref(), &admin)
    })
    .await;
    if !admin_outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        return unavailable();
    }
    redirect("/admin/login")
}



pub(crate) async fn backup_download(
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
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if !caller.map(|a| a.is_super_admin()).unwrap_or(false) {
        return forbidden();
    }

    let tmp = std::env::temp_dir().join(format!(
        "authkit-backup-{}.db",
        crate::signing::unix_now()
    ));
    let tmp_str = tmp.to_string_lossy().to_string();
    let backup_result = sqlx::query("VACUUM INTO ?")
        .bind(&tmp_str)
        .execute(store.pool())
        .await;
    if backup_result.is_err() {
        return unavailable();
    }
    let bytes = match tokio::fs::read(&tmp).await {
        Ok(b) => b,
        Err(_) => return unavailable(),
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-sqlite3"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"authkit-backup.db\""),
    );
    response
}


pub(crate) async fn restore_page(
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
    let caller = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || SystemAdministratorRepository::find_by_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    if !caller.map(|a| a.is_super_admin()).unwrap_or(false) {
        return forbidden();
    }
    let csrf = sessions.csrf_token(session.session());
    let template = AdminRestoreTemplate {
        title: "title_restore",
        csrf: &csrf,
        message: "",
        error: "",
    };
    let body = template.render().unwrap_or_default();
    html_ok(&body)
}

pub(crate) async fn restore_submit(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    mut multipart: axum::extract::Multipart,
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
    if !caller.map(|a| a.is_super_admin()).unwrap_or(false) {
        return forbidden();
    }
    let csrf = sessions.csrf_token(session.session());

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut confirm = String::new();
    let mut code = String::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("backup") => {
                if let Ok(bytes) = field.bytes().await {
                    file_bytes = Some(bytes.to_vec());
                }
            }
            Some("confirm") => {
                if let Ok(text) = field.text().await {
                    confirm = text;
                }
            }
            Some("code") => {
                if let Ok(text) = field.text().await {
                    code = text;
                }
            }
            _ => {}
        }
    }

    if confirm.trim() != "RESTORE" {
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "Type RESTORE to confirm.",
        };
        return html_ok(&template.render().unwrap_or_default());
    }
    if !admin_totp_step_up(sessions, user_id.clone(), &code).await {
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "Invalid TOTP code.",
        };
        return html_ok(&template.render().unwrap_or_default());
    }

    let Some(bytes) = file_bytes else {
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "No backup file uploaded.",
        };
        return html_ok(&template.render().unwrap_or_default());
    };

    let tmp = std::env::temp_dir().join(format!("authkit-restore-{}.db", crate::signing::unix_now()));
    if tokio::fs::write(&tmp, &bytes).await.is_err() {
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "Could not store uploaded file.",
        };
        return html_ok(&template.render().unwrap_or_default());
    }

    // Validate the uploaded SQLite database.
    let tmp_url = format!("sqlite:{}", tmp.display());
    let validation = tokio::task::spawn_blocking({
        let tmp_url = tmp_url.clone();
        move || -> Result<(), String> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let store = authkit_store::SqlStore::connect(&tmp_url, 1).map_err(|e| e.to_string())?;
                let row: (String,) = sqlx::query_as("PRAGMA integrity_check")
                    .fetch_one(store.pool())
                    .await
                    .map_err(|e| e.to_string())?;
                if row.0 != "ok" {
                    return Err(format!("integrity check failed: {}", row.0));
                }
                Ok(())
            })
        }
    })
    .await;
    if validation.is_err() || validation.unwrap().is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "Uploaded file is not a valid SQLite database.",
        };
        return html_ok(&template.render().unwrap_or_default());
    }

    let config = match crate::config::Config::from_env() {
        Ok(c) => c,
        Err(_) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            let template = AdminRestoreTemplate {
                title: "title_restore",
                csrf: &csrf,
                message: "",
                error: "Server configuration is unavailable.",
            };
            return html_ok(&template.render().unwrap_or_default());
        }
    };
    if config.database().kind() != crate::config::DatabaseKind::Sqlite {
        let _ = tokio::fs::remove_file(&tmp).await;
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "Web restore supports SQLite only; use pg_restore for PostgreSQL.",
        };
        return html_ok(&template.render().unwrap_or_default());
    }
    let url = config.database().url();
    let path = url.strip_prefix("sqlite:").unwrap_or(url);
    let path = path.split('?').next().unwrap_or(path);
    let path = path.trim_start_matches("//");
    let db_path = std::path::PathBuf::from(path);

    // Preserve the current database before overwriting it.
    if db_path.exists() {
        let backup = db_path.with_extension(format!(
            "pre-restore-{}.db",
            crate::signing::unix_now()
        ));
        let _ = std::fs::copy(&db_path, &backup);
    }
    if std::fs::copy(&tmp, &db_path).is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        let template = AdminRestoreTemplate {
            title: "title_restore",
            csrf: &csrf,
            message: "",
            error: "Could not replace the database file.",
        };
        return html_ok(&template.render().unwrap_or_default());
    }
    let _ = tokio::fs::remove_file(&tmp).await;

    let template = AdminRestoreTemplate {
        title: "title_restore",
        csrf: &csrf,
        message: "Restore complete. Restart AuthKit before serving traffic.",
        error: "",
    };
    html_ok(&template.render().unwrap_or_default())
}


async fn admin_totp_step_up(
    sessions: &crate::session::SessionService,
    user_id: authkit_core::domain::id::Id<authkit_core::domain::id::UserEntity>,
    code: &str,
) -> bool {
    if code.trim().is_empty() {
        return false;
    }
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
    let mut cred = match creds
        .into_iter()
        .find(|c| c.kind() == CredentialKind::Totp && c.is_active())
    {
        Some(c) => c,
        None => return false,
    };
    let totp = match cred.as_totp() {
        Some(v) => v,
        None => return false,
    };
    let secret = match crate::totp::decrypt_secret(totp.secret(), &pepper) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let step = match crate::totp::verify_code(&secret, code, totp.config(), totp.last_accepted_step()) {
        Some(v) => v,
        None => return false,
    };
    let original_version = cred.version();
    if cred.accept_totp_step(step, now).is_err() {
        return false;
    }
    let updated = cred.clone();
    let result = tokio::task::spawn_blocking({
        let store = store.clone();
        let updated = updated.clone();
        move || CredentialRepository::update(store.as_ref(), &updated, original_version)
    })
    .await;
    result.ok().and_then(|r| r.ok()) == Some(WriteOutcome::Applied)
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
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_owned(),
    )
        .into_response()
}
