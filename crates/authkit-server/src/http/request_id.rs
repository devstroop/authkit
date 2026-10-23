//! Request correlation and structured request logging.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

const REQUEST_ID_HEADER: &str = "x-request-id";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) async fn request_context(request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid_request_id(value))
        .map(str::to_owned)
        .unwrap_or_else(generate_request_id);

    let span = tracing::info_span!(
        "http.request",
        method = %request.method(),
        path = %request.uri().path(),
        request_id = %request_id,
    );
    let response = next.run(request).instrument(span.clone()).await;
    let status = response.status().as_u16();
    tracing::info!(parent: &span, status, "request completed");

    let mut response = response;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    response
}

fn generate_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{sequence:x}")
}

fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_bounded_and_safe() {
        assert!(is_valid_request_id("client-request_1.2"));
        assert!(!is_valid_request_id(""));
        assert!(!is_valid_request_id("contains a space"));
        assert!(!is_valid_request_id(&"a".repeat(129)));
    }

    #[test]
    fn generated_request_ids_are_unique() {
        let first = generate_request_id();
        let second = generate_request_id();
        assert_ne!(first, second);
        assert!(is_valid_request_id(&first));
        assert!(is_valid_request_id(&second));
    }
}
