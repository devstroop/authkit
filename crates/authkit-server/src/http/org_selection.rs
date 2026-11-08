//! Organization selection at sign-in for multi-org users.

use askama::Template;
use authkit_core::domain::id::OrganizationEntity;
use authkit_core::domain::{Id, OneTimeTokenPurpose, SecretHash, WriteOutcome};
use authkit_core::ports::{MembershipRepository, OneTimeTokenRepository, OrganizationRepository};
use axum::body::Bytes;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use authkit_core::domain::SessionAudience;

struct OrgOption {
    id: String,
    name: String,
}

#[derive(Template)]
#[template(path = "pages/select_organization.html")]
struct SelectOrgTemplate<'a> {
    title: &'a str,
    csrf: &'a str,
    token: &'a str,
    orgs: Vec<OrgOption>,
}

pub(crate) async fn page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Query(q): Query<HashMap<String, String>>,
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
    let token = q.get("token").cloned().unwrap_or_default();
    if token.is_empty() {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/login",
            "sign_in",
            "error_missing_token",
            "/login",
            "sign_in",
            "",
        );
    }
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let pepper = sessions.pepper().to_vec();
    let hash = hash_token(&token, &pepper);
    let secret_hash = match SecretHash::parse(hash) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let ott = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let h = secret_hash.clone();
        move || {
            OneTimeTokenRepository::find_by_hash(
                store.as_ref(),
                &h,
                OneTimeTokenPurpose::OrgSelection,
            )
        }
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(ott) = ott else {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/login",
            "sign_in",
            "error_invalid_or_expired_token",
            "/login",
            "sign_in",
            "",
        );
    };
    if ott.consumed_at().is_some() || ott.expires_at().is_before(sessions.clock().now()) {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/login",
            "sign_in",
            "error_invalid_or_expired_token",
            "/login",
            "sign_in",
            "",
        );
    }
    let user_id = ott.user_id().clone();
    // get memberships
    let memberships = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let uid = user_id.clone();
        move || MembershipRepository::list_for_user(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let mut orgs = Vec::new();
    for m in memberships {
        if !m.is_active() {
            continue;
        }
        let org_res = tokio::task::spawn_blocking({
            let store = sessions.store().clone();
            let oid = m.organization_id().clone();
            move || OrganizationRepository::find_by_id(store.as_ref(), &oid)
        })
        .await;
        if let Ok(Ok(Some(org))) = org_res {
            orgs.push(OrgOption {
                id: m.organization_id().as_str().to_owned(),
                name: org.name().as_str().to_owned(),
            });
        }
    }
    let template = SelectOrgTemplate {
        title: "title_select_organization",
        csrf: &csrf,
        token: &token,
        orgs,
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

pub(crate) async fn submit(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(&body) {
        params.insert(k.to_string(), v.to_string());
    }
    let token = params.get("token").cloned().unwrap_or_default();
    let org_id_str = params.get("org_id").cloned().unwrap_or_default();
    if token.is_empty() || org_id_str.is_empty() {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/select-organization",
            "continue",
            "error_token_org_required",
            "/login",
            "sign_in",
            "",
        );
    }
    let pepper = sessions.pepper().to_vec();
    let hash = hash_token(&token, &pepper);
    let secret_hash = match SecretHash::parse(hash) {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let ott = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let h = secret_hash.clone();
        move || {
            OneTimeTokenRepository::find_by_hash(
                store.as_ref(),
                &h,
                OneTimeTokenPurpose::OrgSelection,
            )
        }
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(ott) = ott else {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/select-organization",
            "continue",
            "error_invalid_or_expired_token",
            "/login",
            "sign_in",
            "",
        );
    };
    if ott.consumed_at().is_some() || ott.expires_at().is_before(sessions.clock().now()) {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/select-organization",
            "continue",
            "error_invalid_or_expired_token",
            "/login",
            "sign_in",
            "",
        );
    }
    let user_id = ott.user_id().clone();
    // verify org membership
    let memberships = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let uid = user_id.clone();
        move || MembershipRepository::list_for_user(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let org_id = match Id::<OrganizationEntity>::parse(org_id_str.clone()) {
        Ok(v) => v,
        Err(_) => {
            return crate::http::login::html(
                StatusCode::BAD_REQUEST,
                "title_select_organization",
                "/select-organization",
                "continue",
                "error_invalid_organization",
                "/login",
                "sign_in",
                "",
            );
        }
    };
    let allowed = memberships
        .iter()
        .any(|m| m.organization_id() == &org_id && m.is_active());
    if !allowed {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/select-organization",
            "continue",
            "error_not_member",
            "/login",
            "sign_in",
            "",
        );
    }
    // consume token
    let consumed = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let tid = ott.id().clone();
        let now = sessions.clock().now();
        move || OneTimeTokenRepository::consume(store.as_ref(), &tid, now)
    })
    .await;
    if consumed.ok().and_then(|r| r.ok()) != Some(WriteOutcome::Applied) {
        return crate::http::login::html(
            StatusCode::BAD_REQUEST,
            "title_select_organization",
            "/select-organization",
            "continue",
            "error_token_already_used",
            "/login",
            "sign_in",
            "",
        );
    }
    let now = sessions.clock().now();
    let created = match sessions
        .create(user_id, Some(org_id), SessionAudience::Account, now)
        .await
    {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let redirect_to = params
        .get("next")
        .cloned()
        .unwrap_or_else(|| "/account".to_owned());
    let mut response = redirect(&redirect_to);
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

fn hash_token(value: &str, pepper: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pepper);
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "Service unavailable",
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
