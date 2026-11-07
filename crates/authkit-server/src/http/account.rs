//! Minimal account security pages.

use askama::Template;
use authkit_core::domain::WriteOutcome;
use authkit_core::domain::id::ConsentEntity;
use authkit_core::domain::id::SessionEntity;
use authkit_core::domain::{DisplayName, TenantContext};
use authkit_core::ports::{
    ConsentRepository, CredentialRepository, OAuthClientRepository, SessionRepository,
    UserRepository,
};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

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
        title: "Account",
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

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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

    let mut rows = String::new();
    if let Ok(Ok(consents)) = listed {
        for c in consents {
            if c.revoked_at().is_some() {
                continue;
            }
            let tenant = TenantContext::new(c.organization_id().clone());
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

            rows.push_str(&format!(
                "<li>{} (scopes: {}) <form method=\"post\" action=\"/account/consents/{}/revoke\" style=\"display:inline\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Revoke</button></form></li>",
                escape(&client_name),
                escape(&c.scopes().as_slice().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")),
                c.id().as_str(),
                escape(&csrf)
            ));
        }
    }

    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Connected applications</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Connected applications</h1><ul>{rows}</ul></body></html>"#,
        rows = rows
    );
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
        let tenant = TenantContext::new(consent.organization_id().clone());
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
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Profile</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;"><h1>Profile</h1><form method="post" action="/account/profile"><input type="hidden" name="_csrf" value="{}"><label>Display name <input type="text" name="display_name" value="{}" required></label><br><button type="submit">Save</button></form></body></html>"#,
        escape(&csrf),
        escape(&display_name)
    );
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
