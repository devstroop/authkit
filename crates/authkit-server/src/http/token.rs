//! OAuth 2.0 token endpoint and client authentication.

use authkit_core::domain::{ClientId, Scope, ScopeSet};
use authkit_core::ports::RateLimiter;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde_json::json;

use crate::authorization::ClientContext;
use crate::http::authorize::Params;
use crate::http::error::{OAuthError, OAuthErrorCode};
use crate::http::request_id::RequestId;
use crate::http::rate_limit::client_ip;
use crate::http::routes::AppState;
use crate::tokens::{ClientCredentials, CodeExchange, RefreshExchange, TokenResponse};

const MAX_FORM_LEN: usize = 64 * 1024;

/// Handles token requests for all supported grants.
pub(crate) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    request_id: Option<Extension<RequestId>>,
    body: Bytes,
) -> Response {
    let Some(service) = state.tokens.as_deref() else {
        return not_available();
    };
    let trusted = std::env::var("AUTHKIT_TRUSTED_PROXIES").unwrap_or_default()
        .split(',').filter_map(|v| v.trim().parse().ok()).collect::<Vec<_>>();
    let trusted = if trusted.is_empty() && std::env::var("AUTHKIT_TRUSTED_PROXIES").unwrap_or_default().contains('*') {
        vec!["0.0.0.0".parse().unwrap()]
    } else { trusted };
    let ip = client_ip(&headers, None, &trusted);
    // IP flood protection
    if let Some(sessions) = state.sessions.as_ref() {
        let store = sessions.store().clone();
        let now = sessions.clock().now();
        let key = format!("token:ip:{ip}");
        let result = tokio::task::spawn_blocking({
            let store = store.clone();
            let key = key.clone();
            let now = now;
            move || RateLimiter::check(store.as_ref(), &key, 60, 300, now)
        }).await;
        if let Ok(Err(err)) = result {
            return rate_limited_response(err.retry_after_secs);
        }
    }
    if uri.query().is_some() {
        return OAuthError::new(
            OAuthErrorCode::InvalidRequest,
            "the token endpoint accepts form-encoded POST bodies only",
        )
        .into_response();
    }
    let params = match token_form(&headers, &body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };

    let context = match authenticate_client(&state, &headers, &params).await {
        Ok(context) => context,
        Err(error) => return error.into_response(),
    };
    if let Some(sessions) = state.sessions.as_ref() {
        let store = sessions.store().clone();
        let now = sessions.clock().now();
        let key = format!("token:client:{}:{}", context.client().client_id().as_str(), ip);
        let result = tokio::task::spawn_blocking({
            let store = store.clone();
            let key = key.clone();
            let now = now;
            move || RateLimiter::check(store.as_ref(), &key, 30, 300, now)
        }).await;
        if let Ok(Err(err)) = result {
            return rate_limited_response(err.retry_after_secs);
        }
    }

    let result = match params.get("grant_type") {
        Some("authorization_code") => {
            let (Some(code), Some(redirect_uri), Some(code_verifier)) = (
                non_empty(&params, "code"),
                non_empty(&params, "redirect_uri"),
                non_empty(&params, "code_verifier"),
            ) else {
                return invalid_request("code, redirect_uri, and code_verifier are required")
                    .into_response();
            };
            service
                .exchange_code(
                    &context,
                    CodeExchange {
                        code: code.to_owned(),
                        redirect_uri: redirect_uri.to_owned(),
                        code_verifier: code_verifier.to_owned(),
                        request_id: request_id_string(request_id.as_ref()),
                    },
                )
                .await
        }
        Some("refresh_token") => {
            let Some(refresh_token) = non_empty(&params, "refresh_token") else {
                return invalid_request("refresh_token is required").into_response();
            };
            let scope = match optional_scope(&params) {
                Ok(scope) => scope,
                Err(error) => return error.into_response(),
            };
            service
                .refresh(
                    &context,
                    RefreshExchange {
                        refresh_token: refresh_token.to_owned(),
                        scope,
                    },
                )
                .await
        }
        Some("client_credentials") => {
            let scope = match optional_scope(&params) {
                Ok(scope) => scope,
                Err(error) => return error.into_response(),
            };
            service
                .client_credentials(&context, ClientCredentials { scope })
                .await
        }
        Some(_) => {
            return OAuthError::new(
                OAuthErrorCode::UnsupportedGrantType,
                "the grant type is not supported",
            )
            .into_response();
        }
        None => return invalid_request("grant_type is required").into_response(),
    };

    match result {
        Ok(response) => token_response(response),
        Err(error) => error.into_response(),
    }
}

fn rate_limited_response(retry_after: u64) -> Response {
    let mut response = (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({"error": "temporarily_unavailable", "error_description": "the request was rate limited"})),
    )
        .into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(axum::http::header::RETRY_AFTER, value);
    }
    response
}

fn token_response(response: TokenResponse) -> Response {
    let mut response = Json(response).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().expect("static"));
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().expect("static"));
    response
}

pub(crate) fn token_form(headers: &HeaderMap, body: &[u8]) -> Result<Params, OAuthError> {
    if body.len() > MAX_FORM_LEN {
        return Err(invalid_request("the request body is too large"));
    }
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    {
        return Err(invalid_request(
            "the request must use application/x-www-form-urlencoded",
        ));
    }
    Params::from_form(body).map_err(|_| invalid_request("the form parameters are malformed"))
}

/// Authenticates the client using exactly one token-endpoint method.
pub(crate) async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    params: &Params,
) -> Result<ClientContext, OAuthError> {
    let authorization = match headers.get(header::AUTHORIZATION) {
        Some(value) => Some(value.to_str().map_err(|_| invalid_client())?.to_owned()),
        None => None,
    };
    let body_client_id = params.get("client_id");
    let body_secret = params.get("client_secret");

    if authorization.is_some() && (body_client_id.is_some() || body_secret.is_some()) {
        return Err(invalid_request(
            "multiple client authentication methods were supplied",
        ));
    }

    let (client_id, supplied_secret, method) = if let Some(authorization) = authorization {
        let (client_id, secret) = basic_credentials(&authorization)?;
        (client_id, Some(secret), TokenEndpointMethod::Basic)
    } else if let Some(secret) = body_secret {
        let Some(client_id) = body_client_id.filter(|value| !value.is_empty()) else {
            return Err(invalid_client());
        };
        let client_id = ClientId::parse(client_id).map_err(|_| invalid_client())?;
        (
            client_id,
            Some(secret.to_owned()),
            TokenEndpointMethod::Post,
        )
    } else {
        let Some(client_id) = body_client_id.filter(|value| !value.is_empty()) else {
            return Err(invalid_client());
        };
        let client_id = ClientId::parse(client_id).map_err(|_| invalid_client())?;
        (client_id, None, TokenEndpointMethod::None)
    };

    let Some(context) = state
        .authorization
        .as_deref()
        .ok_or_else(not_available_error)?
        .resolve_client(&client_id)
        .await
        .map_err(|error| OAuthError::from_domain(&error))?
    else {
        return Err(invalid_client());
    };
    let client = context.client();
    let configured = match client.token_endpoint_auth_method() {
        authkit_core::domain::TokenEndpointAuthMethod::ClientSecretBasic => {
            TokenEndpointMethod::Basic
        }
        authkit_core::domain::TokenEndpointAuthMethod::ClientSecretPost => {
            TokenEndpointMethod::Post
        }
        authkit_core::domain::TokenEndpointAuthMethod::None => TokenEndpointMethod::None,
    };
    if method != configured {
        return Err(invalid_client());
    }

    match method {
        TokenEndpointMethod::Basic | TokenEndpointMethod::Post => {
            let Some(supplied_secret) = supplied_secret else {
                return Err(invalid_client());
            };
            let Some(stored) = client.secret_hash() else {
                return Err(invalid_client());
            };
            if !state
                .tokens
                .as_deref()
                .is_some_and(|service| service.client_secret_matches(stored, &supplied_secret))
            {
                return Err(invalid_client());
            }
        }
        TokenEndpointMethod::None => {
            if client.client_type() != authkit_core::domain::ClientType::Public {
                return Err(invalid_client());
            }
        }
    }

    Ok(context)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenEndpointMethod {
    Basic,
    Post,
    None,
}

fn basic_credentials(value: &str) -> Result<(ClientId, String), OAuthError> {
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Err(invalid_client());
    };
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(invalid_client());
    }
    let raw = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| invalid_client())?;
    let decoded = String::from_utf8(raw).map_err(|_| invalid_client())?;
    let (client_id, secret) = decoded.split_once(':').ok_or_else(invalid_client)?;
    let client_id = form_decode(client_id).ok_or_else(invalid_client)?;
    let secret = form_decode(secret).ok_or_else(invalid_client)?;
    Ok((
        ClientId::parse(&client_id).map_err(|_| invalid_client())?,
        secret,
    ))
}

fn form_decode(value: &str) -> Option<String> {
    let encoded = format!("value={value}");
    let mut pairs = url::form_urlencoded::parse(encoded.as_bytes());
    let (_, value) = pairs.next()?;
    Some(value.into_owned())
}

fn optional_scope(params: &Params) -> Result<Option<ScopeSet>, OAuthError> {
    let Some(value) = params.get("scope") else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    let mut scopes = Vec::new();
    for scope in value.split_ascii_whitespace() {
        scopes.push(Scope::parse(scope).map_err(|_| invalid_scope())?);
    }
    if scopes.is_empty() {
        return Err(invalid_scope());
    }
    Ok(Some(ScopeSet::new(scopes)))
}

pub(crate) fn non_empty<'a>(params: &'a Params, name: &str) -> Option<&'a str> {
    params.get(name).filter(|value| !value.is_empty())
}

fn request_id_string(request_id: Option<&Extension<RequestId>>) -> String {
    request_id
        .map(|Extension(request_id)| request_id.as_str().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn invalid_request(description: &'static str) -> OAuthError {
    OAuthError::new(OAuthErrorCode::InvalidRequest, description)
}

fn invalid_client() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::InvalidClient,
        "client authentication failed",
    )
}

fn invalid_scope() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::InvalidScope,
        "the requested scope is invalid or exceeds the granted scope",
    )
}

fn not_available_error() -> OAuthError {
    OAuthError::new(
        OAuthErrorCode::TemporarilyUnavailable,
        "the service is temporarily unavailable",
    )
}

fn not_available() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"error": "not_found"})),
    )
        .into_response()
}
