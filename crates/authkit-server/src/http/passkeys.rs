//! Passkey (WebAuthn) enrollment and authentication.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use authkit_core::domain::Id;
use authkit_core::domain::id::UserEntity;

#[derive(Clone)]
enum Pending {
    Registration {
        user_id: Id<UserEntity>,
        state: PasskeyRegistration,
        expires_at: Instant,
    },
    Authentication {
        user_id: Id<UserEntity>,
        state: PasskeyAuthentication,
        expires_at: Instant,
    },
}

static PENDING: std::sync::LazyLock<Arc<Mutex<HashMap<String, Pending>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "Service unavailable",
    )
        .into_response()
}

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        Json(json!({"error": msg})),
    )
        .into_response()
}

// Registration begin
pub(crate) async fn register_begin(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(s)) = session else {
        return bad_request("unauthenticated");
    };
    let Some(wa) = state.webauthn.as_ref() else {
        return unavailable();
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = s.session().user_id().clone();
    let store = sessions.store().clone();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || authkit_core::ports::UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return bad_request("user not found");
    };
    let (ccr, pr) = match wa.start_passkey_registration(
        Uuid::new_v4(),
        user.email().as_str(),
        user.email().as_str(),
        None,
    ) {
        Ok(v) => v,
        Err(_) => return bad_request("registration start failed"),
    };
    let token = rand_token_hex();
    let expires_at = Instant::now() + Duration::from_secs(300);
    PENDING.lock().unwrap().insert(
        token.clone(),
        Pending::Registration {
            user_id: user_id.clone(),
            state: pr,
            expires_at,
        },
    );
    (
        StatusCode::OK,
        Json(json!({"token": token, "options": ccr})),
    )
        .into_response()
}

// Registration finish
#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub token: String,
    pub credential: RegisterPublicKeyCredential,
}

pub(crate) async fn register_finish(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Json(req): Json<RegisterFinishRequest>,
) -> Response {
    let Some(Extension(s)) = session else {
        return bad_request("unauthenticated");
    };
    let Some(wa) = state.webauthn.as_ref() else {
        return unavailable();
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let pending = PENDING.lock().unwrap().remove(&req.token);
    let (user_id, pr_state) = match pending {
        Some(Pending::Registration {
            user_id,
            state,
            expires_at,
        }) if Instant::now() <= expires_at => (user_id, state),
        _ => return bad_request("invalid or expired token"),
    };
    // ensure same user
    if user_id != s.session().user_id().clone() {
        return bad_request("user mismatch");
    }
    let passkey = match wa.finish_passkey_registration(&req.credential, &pr_state) {
        Ok(v) => v,
        Err(_) => return bad_request("registration finish failed"),
    };
    let store = sessions.store().clone();
    let uid = user_id.as_str().to_owned();
    let passkey_json = match serde_json::to_string(&passkey) {
        Ok(v) => v,
        Err(_) => return bad_request("serialize failed"),
    };
    let cred_id = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        passkey.cred_id().as_slice(),
    );
    let id = format!("pk_{}", Uuid::new_v4().simple());
    let now = sessions.clock().now().as_millis() as i64;
    let _ = tokio::task::spawn_blocking({
        let store = store.clone();
        let id = id.clone();
        let uid = uid.clone();
        let cred_id = cred_id.clone();
        let passkey_json = passkey_json.clone();
        move || store.insert_passkey(&id, &uid, &cred_id, &passkey_json, now)
    })
    .await;
    (StatusCode::OK, Json(json!({"status": "registered"}))).into_response()
}

fn rand_token_hex() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Deserialize)]
pub struct AuthBeginRequest {
    pub email: String,
}

pub(crate) async fn auth_begin(
    State(state): State<AppState>,
    Json(req): Json<AuthBeginRequest>,
) -> Response {
    let Some(wa) = state.webauthn.as_ref() else {
        return unavailable();
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let email = match authkit_core::domain::Email::parse(&req.email) {
        Ok(v) => v,
        Err(_) => return bad_request("invalid email"),
    };
    let store = sessions.store().clone();
    let user = tokio::task::spawn_blocking({
        let store = store.clone();
        let email = email.clone();
        move || authkit_core::ports::UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten());
    let Some(user) = user else {
        return bad_request("user not found");
    };
    let user_id = user.id().clone();
    let jsons = tokio::task::spawn_blocking({
        let store = sessions.store().clone();
        let uid = user_id.as_str().to_owned();
        move || store.list_passkey_jsons(&uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let mut passkeys = Vec::new();
    for j in jsons {
        if let Ok(pk) = serde_json::from_str::<Passkey>(&j) {
            passkeys.push(pk);
        }
    }
    if passkeys.is_empty() {
        return bad_request("no passkeys registered");
    }
    let (rcr, pa) = match wa.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(_) => return bad_request("auth begin failed"),
    };
    let token = rand_token_hex();
    let expires_at = Instant::now() + Duration::from_secs(300);
    PENDING.lock().unwrap().insert(
        token.clone(),
        Pending::Authentication {
            user_id: user_id.clone(),
            state: pa,
            expires_at,
        },
    );
    (
        StatusCode::OK,
        Json(json!({"token": token, "options": rcr})),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct AuthFinishRequest {
    pub token: String,
    pub credential: PublicKeyCredential,
}

pub(crate) async fn auth_finish(
    State(state): State<AppState>,
    Json(req): Json<AuthFinishRequest>,
) -> Response {
    let Some(wa) = state.webauthn.as_ref() else {
        return unavailable();
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let pending = PENDING.lock().unwrap().remove(&req.token);
    let (user_id, pa_state) = match pending {
        Some(Pending::Authentication {
            user_id,
            state,
            expires_at,
        }) if Instant::now() <= expires_at => (user_id, state),
        _ => return bad_request("invalid or expired token"),
    };
    let result = match wa.finish_passkey_authentication(&req.credential, &pa_state) {
        Ok(v) => v,
        Err(_) => return bad_request("authentication failed"),
    };
    let now = sessions.clock().now();
    let created = match sessions
        .create(
            user_id.clone(),
            None,
            authkit_core::domain::SessionAudience::Account,
            now,
        )
        .await
    {
        Ok(v) => v,
        Err(_) => return unavailable(),
    };
    let _ = result;
    let cookie = sessions.set_cookie(created.session(), created.token(), now);
    let mut response = axum::response::Redirect::to("/").into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie) {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    response
}

// Account page listing passkeys
pub(crate) async fn list_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(s)) = session else {
        return bad_request("unauthenticated");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = s.session().user_id().as_str().to_owned();
    let store = sessions.store().clone();
    let passkeys = tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || store.list_passkeys(&uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let body = format!(
        "<h1>Passkeys</h1><ul>{}</ul><button id=pk-register>Register passkey</button><script>document.getElementById('pk-register').onclick=async()=>{{const r=await fetch('/passkeys/register/begin',{{method:'POST',credentials:'same-origin'}});const d=await r.json();console.log(d);alert('begin: '+JSON.stringify(d));}};</script>",
        passkeys
            .iter()
            .map(|(id, cred)| format!("<li>{} {}</li>", id, cred))
            .collect::<Vec<_>>()
            .join("")
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}
