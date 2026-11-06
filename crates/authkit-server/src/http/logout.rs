//! RP-initiated logout endpoint.

use authkit_core::domain::{ClientId, SessionAudience};
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::http::authorize::Params;
use crate::http::routes::AppState;
use crate::http::session::account_session_token;
use crate::http::token::token_form;
use crate::tokens::LogoutRequest;

const MAX_QUERY_LEN: usize = 16 * 1024;

const SIGNED_OUT_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Signed out</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Signed out</h1>
<p>Your AuthKit session has ended. You can close this window.</p>
</body>
</html>"#;

/// Handles an RP-initiated logout request sent as a query.
pub(crate) async fn logout_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let query = query.as_deref().unwrap_or_default();
    if query.len() > MAX_QUERY_LEN {
        return bad_request();
    }
    let params = match Params::from_query(Some(query)) {
        Ok(params) => params,
        Err(()) => return bad_request(),
    };
    perform(&state, &headers, &params).await
}

/// Handles an RP-initiated logout request sent as a form.
pub(crate) async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = match token_form(&headers, &body) {
        Ok(params) => params,
        Err(error) => return error.into_response(),
    };
    perform(&state, &headers, &params).await
}

async fn perform(state: &AppState, headers: &HeaderMap, params: &Params) -> Response {
    let Some(service) = state.tokens.as_deref() else {
        return (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, "no-store")]).into_response();
    };
    let request = LogoutRequest {
        id_token_hint: params.get("id_token_hint").map(str::to_owned),
        client_id: params
            .get("client_id")
            .and_then(|value| ClientId::parse(value).ok()),
        post_logout_redirect_uri: params.get("post_logout_redirect_uri").map(str::to_owned),
        state: params.get("state").map(str::to_owned),
        session_token: account_session_token(headers, service.sessions()),
    };

    match service.logout(request).await {
        Ok(outcome) => {
            let cookie = service.sessions().clear_cookie(SessionAudience::Account);
            match outcome.redirect {
                Some(location) => {
                    let Ok(location) = HeaderValue::from_str(&location) else {
                        return bad_request();
                    };
                    (
                        StatusCode::SEE_OTHER,
                        [
                            (header::LOCATION, location),
                            (
                                header::SET_COOKIE,
                                HeaderValue::from_str(&cookie).expect("cookie is a header value"),
                            ),
                            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                        ],
                    )
                        .into_response()
                }
                None => (
                    StatusCode::OK,
                    [
                        (
                            header::SET_COOKIE,
                            HeaderValue::from_str(&cookie).expect("cookie is a header value"),
                        ),
                        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                        (
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("text/html; charset=utf-8"),
                        ),
                    ],
                    SIGNED_OUT_PAGE,
                )
                    .into_response(),
            }
        }
        Err(error) => error.into_response(),
    }
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}
