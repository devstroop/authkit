//! OpenID Connect UserInfo endpoint.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::http::routes::AppState;
use crate::tokens::UserInfoError;

/// Handles a GET UserInfo request.
pub(crate) async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    respond(&state, &headers).await
}

/// Handles a POST UserInfo request.
pub(crate) async fn userinfo_post(State(state): State<AppState>, headers: HeaderMap) -> Response {
    respond(&state, &headers).await
}

async fn respond(state: &AppState, headers: &HeaderMap) -> Response {
    let Some(service) = state.tokens.as_deref() else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": "not_found"})),
        )
            .into_response();
    };
    let Some(token) = bearer_token(headers) else {
        return bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", None);
    };

    match service.userinfo(token).await {
        Ok(claims) => {
            let mut response = Json(claims).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().expect("static"));
            response
                .headers_mut()
                .insert(header::PRAGMA, "no-cache".parse().expect("static"));
            response
        }
        Err(UserInfoError::InvalidToken) => {
            bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", None)
        }
        Err(UserInfoError::InsufficientScope) => {
            bearer_error(StatusCode::FORBIDDEN, "insufficient_scope", Some("openid"))
        }
        Err(UserInfoError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": "temporarily_unavailable"})),
        )
            .into_response(),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return None;
    }
    Some(token)
}

fn bearer_error(status: StatusCode, error: &str, scope: Option<&str>) -> Response {
    let mut challenge = format!("Bearer error=\"{error}\"");
    let body = if let Some(scope) = scope {
        challenge.push_str(&format!(", scope=\"{scope}\""));
        json!({"error": error, "scope": scope})
    } else {
        json!({"error": error})
    };
    (
        status,
        [
            (
                header::WWW_AUTHENTICATE,
                challenge.parse().expect("static challenge"),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        Json(body),
    )
        .into_response()
}
