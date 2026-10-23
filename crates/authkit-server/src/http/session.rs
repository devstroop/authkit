//! Session cookie resolution and CSRF enforcement.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cookie::Cookie;
use serde_json::json;
use tracing::warn;
use url::Url;

use crate::config::Issuer;
use crate::http::request_id::RequestId;
use crate::session::{SessionError, SessionService, SessionToken};
use authkit_core::domain::{ErrorCode, Session, SessionAudience};

/// The maximum accepted form body when looking for a CSRF token.
const MAX_FORM_BODY: usize = 64 * 1024;

/// The hidden form field carrying the CSRF token.
const CSRF_FORM_FIELD: &str = "_csrf";

/// The request header carrying the CSRF token.
const CSRF_HEADER: &str = "x-csrf-token";

/// The route prefix that uses the administrator session cookie.
const ADMIN_PATH_PREFIX: &str = "/admin";

/// State shared by the session middleware.
#[derive(Clone)]
pub(crate) struct SessionSecurityState {
    pub(crate) service: Arc<SessionService>,
    pub(crate) issuer: Issuer,
}

/// The session and CSRF token attached to an authenticated request.
#[derive(Clone)]
pub struct SessionContext {
    session: Session,
    csrf_token: String,
}

impl SessionContext {
    /// Returns the authenticated session.
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// Returns the session-bound CSRF token for rendering forms and HTMX headers.
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// Resolves the audience-specific session cookie and protects unsafe requests.
pub(crate) async fn session_context(
    State(state): State<SessionSecurityState>,
    mut request: Request,
    next: Next,
) -> Response {
    if !session_applies_to(request.uri().path()) {
        return next.run(request).await;
    }

    let audience = selected_audience(request.uri().path());
    let cookie_name = state.service.cookie_name(audience);
    let Some(raw_token) = cookie_value(request.headers(), cookie_name) else {
        return next.run(request).await;
    };

    let now = state.service.clock().now();
    let Some(token) = SessionToken::from_cookie(&raw_token) else {
        return invalid_session(request, next, &state.service, audience, "malformed_cookie").await;
    };

    let Some(session) = (match state.service.load(&token, now).await {
        Ok(session) => session,
        Err(error) => return unavailable(error, request_id(&request)),
    }) else {
        return invalid_session(request, next, &state.service, audience, "unknown_session").await;
    };

    if session.audience() != audience {
        return invalid_session(request, next, &state.service, audience, "wrong_audience").await;
    }
    if !session.is_valid(now) {
        return invalid_session(
            request,
            next,
            &state.service,
            audience,
            "expired_or_revoked",
        )
        .await;
    }

    if is_unsafe(request.method()) {
        if !same_origin(request.headers(), &state.issuer) {
            return csrf_rejected(
                &state.service,
                session.clone(),
                request_id(&request),
                request.method().as_str().to_owned(),
                request.uri().path().to_owned(),
                "origin_mismatch",
            )
            .await;
        }

        let (restored, supplied) = match extract_csrf(request).await {
            Ok(parts) => parts,
            Err(CsrfExtractionError::TooLarge) => {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
            }
        };
        request = restored;
        let supplied = supplied.unwrap_or_default();
        if !state.service.csrf_matches(&session, &supplied) {
            return csrf_rejected(
                &state.service,
                session.clone(),
                request_id(&request),
                request.method().as_str().to_owned(),
                request.uri().path().to_owned(),
                "invalid_csrf",
            )
            .await;
        }
    }

    let session = match state.service.touch(session, now).await {
        Ok(session) => session,
        Err(SessionError::Domain(error)) if error.code() == ErrorCode::Unauthenticated => {
            return invalid_session(
                request,
                next,
                &state.service,
                audience,
                "expired_or_revoked",
            )
            .await;
        }
        Err(error) => return unavailable(error, request_id(&request)),
    };

    request.extensions_mut().insert(SessionContext {
        session: session.clone(),
        csrf_token: state.service.csrf_token(&session),
    });
    let mut response = next.run(request).await;
    if !response_sets_cookie(&response, cookie_name) {
        append_cookie(
            &mut response,
            state.service.set_cookie(&session, &token, now),
        );
    }
    add_session_cache_headers(&mut response);
    response
}

async fn invalid_session(
    request: Request,
    next: Next,
    service: &SessionService,
    audience: SessionAudience,
    reason: &'static str,
) -> Response {
    let request_id = request_id(&request);
    warn!(
        event = "security.session_rejected",
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
        reason,
        "session cookie rejected"
    );

    let mut response = if is_unsafe(request.method()) {
        error_response(StatusCode::UNAUTHORIZED, "unauthenticated")
    } else {
        next.run(request).await
    };
    let cookie_name = service.cookie_name(audience);
    if !response_sets_cookie(&response, cookie_name) {
        append_cookie(&mut response, service.clear_cookie(audience));
    }
    add_session_cache_headers(&mut response);
    response
}

async fn csrf_rejected(
    service: &SessionService,
    session: Session,
    request_id: String,
    method: String,
    path: String,
    reason: &'static str,
) -> Response {
    if let Err(error) = service
        .audit_csrf_rejection(&session, &request_id, &method, &path, reason)
        .await
    {
        warn!(
            event = "security.audit_failed",
            request_id = %request_id,
            error = %error,
            "could not append CSRF rejection audit event"
        );
    }
    warn!(
        event = "security.csrf_rejected",
        request_id = %request_id,
        method = %method,
        path = %path,
        reason,
        session_id = %session.id(),
        "CSRF validation failed"
    );
    error_response(StatusCode::FORBIDDEN, "csrf_rejected")
}

fn unavailable(error: SessionError, request_id: String) -> Response {
    warn!(
        event = "security.session_unavailable",
        request_id = %request_id,
        error = %error,
        "session storage unavailable"
    );
    error_response(StatusCode::SERVICE_UNAVAILABLE, "session_unavailable")
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, axum::Json(json!({"error": code}))).into_response();
    add_session_cache_headers(&mut response);
    response
}

fn request_id(request: &Request) -> String {
    request
        .extensions()
        .get::<RequestId>()
        .map(RequestId::as_str)
        .unwrap_or("unknown")
        .to_owned()
}

fn selected_audience(path: &str) -> SessionAudience {
    if path == ADMIN_PATH_PREFIX || path.starts_with("/admin/") {
        SessionAudience::Admin
    } else {
        SessionAudience::Account
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for header in headers.get_all(header::COOKIE) {
        let Ok(value) = header.to_str() else {
            continue;
        };
        for cookie in Cookie::split_parse(value) {
            let Ok(cookie) = cookie else {
                continue;
            };
            if cookie.name() == name {
                return Some(cookie.value().to_owned());
            }
        }
    }
    None
}

fn is_unsafe(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

fn session_applies_to(path: &str) -> bool {
    if path.starts_with("/.well-known/") {
        return false;
    }
    !matches!(
        path,
        "/healthz"
            | "/readyz"
            | "/oauth2/token"
            | "/oauth2/introspect"
            | "/oauth2/revoke"
            | "/oauth2/device_authorization"
            | "/oauth2/jwks"
            | "/oauth2/authorize.css"
    )
}

fn same_origin(headers: &HeaderMap, issuer: &Issuer) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        match site.to_str() {
            Ok("same-origin" | "none") => {}
            _ => return false,
        }
    }

    let source = headers
        .get(header::ORIGIN)
        .or_else(|| headers.get(header::REFERER));
    let Some(source) = source.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(url) = Url::parse(source) else {
        return false;
    };
    url.origin().ascii_serialization() == issuer.as_str()
}

enum CsrfExtractionError {
    TooLarge,
}

async fn extract_csrf(request: Request) -> Result<(Request, Option<String>), CsrfExtractionError> {
    if let Some(value) = request.headers().get(CSRF_HEADER) {
        let token = value
            .to_str()
            .ok()
            .filter(|value| value.len() <= 128)
            .unwrap_or_default()
            .to_owned();
        return Ok((request, Some(token)));
    }

    if !is_form(request.headers()) {
        return Ok((request, None));
    }

    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_FORM_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(CsrfExtractionError::TooLarge),
    };
    let token = form_csrf_token(&bytes);
    let request = Request::from_parts(parts, Body::from(bytes));
    Ok((request, token))
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        })
}

fn form_csrf_token(body: &[u8]) -> Option<String> {
    url::form_urlencoded::parse(body)
        .find(|(key, _)| key == CSRF_FORM_FIELD)
        .map(|(_, value)| value.into_owned())
        .filter(|value| value.len() <= 128)
}

fn response_sets_cookie(response: &Response, name: &str) -> bool {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
                .is_some_and(|(cookie_name, _)| cookie_name.trim() == name)
        })
}

fn append_cookie(response: &mut Response, cookie: String) {
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        Err(error) => {
            warn!(error = %error, "could not encode session cookie");
        }
    }
}

fn add_session_cache_headers(response: &mut Response) {
    append_vary_cookie(response);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn append_vary_cookie(response: &mut Response) {
    let existing = response
        .headers()
        .get(header::VARY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if existing
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case("cookie"))
    {
        return;
    }
    let value = if existing.is_empty() {
        "Cookie".to_owned()
    } else {
        format!("{existing}, Cookie")
    };
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::VARY, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_routes_use_the_admin_cookie() {
        assert_eq!(selected_audience("/admin"), SessionAudience::Admin);
        assert_eq!(selected_audience("/admin/users"), SessionAudience::Admin);
        assert_eq!(
            selected_audience("/administrator"),
            SessionAudience::Account
        );
        assert_eq!(selected_audience("/account"), SessionAudience::Account);
    }

    #[test]
    fn protocol_and_health_routes_skip_session_resolution() {
        for path in [
            "/healthz",
            "/readyz",
            "/.well-known/openid-configuration",
            "/oauth2/token",
            "/oauth2/introspect",
            "/oauth2/revoke",
            "/oauth2/jwks",
            "/oauth2/authorize.css",
        ] {
            assert!(!session_applies_to(path), "{path}");
        }
        for path in [
            "/",
            "/account",
            "/admin/users",
            "/oauth2/authorize",
            "/oauth2/authorize/consent",
            "/logout",
        ] {
            assert!(session_applies_to(path), "{path}");
        }
    }

    #[test]
    fn only_safe_methods_skip_csrf() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(!is_unsafe(&method));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(is_unsafe(&method));
        }
    }

    #[test]
    fn parses_csrf_from_forms() {
        assert_eq!(
            form_csrf_token(b"_csrf=abc%2D123&other=value").as_deref(),
            Some("abc-123")
        );
        assert_eq!(form_csrf_token(b"other=value"), None);
        assert_eq!(
            form_csrf_token(b"_csrf=too-long-token").as_deref(),
            Some("too-long-token")
        );
    }

    #[test]
    fn cookie_scoping_requires_exact_names() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; authkit_session=abc; authkit_admin_session=def"),
        );
        assert_eq!(
            cookie_value(&headers, "authkit_session").as_deref(),
            Some("abc")
        );
        assert_eq!(
            cookie_value(&headers, "authkit_admin_session").as_deref(),
            Some("def")
        );
        assert_eq!(cookie_value(&headers, "missing"), None);
    }
}
