//! OIDC/OAuth discovery and JWKS documents.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::http::routes::AppState;
use crate::signing::unix_now;

const METADATA_MAX_AGE: u32 = 300;

pub(crate) async fn openid_configuration(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    discovery_response(&state, &headers)
}

pub(crate) async fn oauth_authorization_server(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    discovery_response(&state, &headers)
}

pub(crate) async fn jwks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let document = json!({
        "keys": state.keys.published_keys(unix_now()),
    });
    cacheable_json(&document, &headers, METADATA_MAX_AGE)
}

fn discovery_response(state: &AppState, headers: &HeaderMap) -> Response {
    let issuer = state.issuer.as_str();
    let document = json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/oauth2/jwks"),
        "id_token_signing_alg_values_supported": ["ES256"],
    });
    cacheable_json(&document, headers, METADATA_MAX_AGE)
}

fn cacheable_json(value: &Value, headers: &HeaderMap, max_age: u32) -> Response {
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let etag = format!("\"{}\"", URL_SAFE_NO_PAD.encode(hasher.finalize()));

    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == etag)
        })
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }

    let cache_control = format!("public, max-age={max_age}");
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, cache_control.as_str()),
            (header::ETAG, etag.as_str()),
        ],
        body,
    )
        .into_response()
}
