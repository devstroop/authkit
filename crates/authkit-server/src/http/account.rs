//! Minimal account security pages.

use authkit_core::domain::WriteOutcome;
use authkit_core::domain::id::SessionEntity;
use authkit_core::ports::{CredentialRepository, SessionRepository};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::password::verify_password;

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

    let csrf = sessions.csrf_token(session.session());
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let listed = tokio::task::spawn_blocking(move || {
        authkit_core::ports::SessionRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await;

    let mut rows = String::new();
    if let Ok(Ok(sessions_list)) = listed {
        for s in sessions_list {
            rows.push_str(&format!(
                "<li>{} - {} <form method=\"post\" action=\"/account/sessions/{}/revoke\" style=\"display:inline\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Revoke</button></form></li>",
                s.id().as_str(),
                if s.is_valid(sessions.clock().now()) { "active" } else { "inactive" },
                s.id().as_str(),
                escape(&csrf)
            ));
        }
    }

    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Account</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Sessions</h1>
<ul>{rows}</ul>
<h1>Change password</h1>
<form method="post" action="/account/password">
<input type="hidden" name="_csrf" value="{csrf}">
<label>Current password <input type="password" name="current_password" required></label><br>
<label>New password <input type="password" name="new_password" required minlength="12"></label><br>
<button type="submit">Update password</button>
</form>
</body>
</html>"#,
        rows = rows,
        csrf = escape(&csrf)
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
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
            Ok::<_, authkit_core::domain::DomainError>(
                credentials
                    .into_iter()
                    .find(|c| c.kind() == authkit_core::domain::CredentialKind::Password && c.is_active()),
            )
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
    if updated.replace_password(new_verifier, sessions.clock().now()).is_err() {
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

    redirect("/account")
}

fn redirect(location: &str) -> Response {
    match axum::http::HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, location), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
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

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error": "temporarily_unavailable"})),
    )
        .into_response()
}
