//! RFC 7009 token revocation endpoint.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::http::error::OAuthError;
use crate::http::routes::AppState;
use crate::http::token::{authenticate_client, non_empty, token_form};

/// Handles a token revocation request.
pub(crate) async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(service) = state.tokens.as_deref() else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({"error": "not_found"})),
        )
            .into_response();
    };
    let params = match token_form(&headers, &body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };
    let context = match authenticate_client(&state, &headers, &params).await {
        Ok(context) => context,
        Err(error) => return error.into_response(),
    };
    let Some(token) = non_empty(&params, "token") else {
        return OAuthError::new(
            crate::http::OAuthErrorCode::InvalidRequest,
            "token is required",
        )
        .into_response();
    };
    let hint = params.get("token_type_hint");

    match service.revoke(&context, token, hint).await {
        Ok(()) => {
            let mut response = StatusCode::OK.into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().expect("static"));
            response
                .headers_mut()
                .insert(header::PRAGMA, "no-cache".parse().expect("static"));
            response
        }
        Err(error) => error.into_response(),
    }
}
