//! RFC 6749 error responses.

use authkit_core::domain::{DomainError, ErrorCode};
use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// The RFC 6749 error codes used by the native adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthErrorCode {
    /// The request is malformed or missing a required parameter.
    InvalidRequest,
    /// Client authentication failed.
    InvalidClient,
    /// The grant or token is invalid, expired, or already consumed.
    InvalidGrant,
    /// The client is not allowed to use this grant type.
    UnauthorizedClient,
    /// The grant type is not supported.
    UnsupportedGrantType,
    /// The authorization response type is not supported.
    UnsupportedResponseType,
    /// The requested scope is invalid or exceeds the granted scope.
    InvalidScope,
    /// The resource owner or authorization server denied the request.
    AccessDenied,
    /// The end user must sign in before the request can continue.
    LoginRequired,
    /// The end user must grant consent before the request can continue.
    ConsentRequired,
    /// The request requires interaction that cannot be completed silently.
    InteractionRequired,
    /// An unexpected server failure occurred.
    ServerError,
    /// The service is temporarily unavailable.
    TemporarilyUnavailable,
}

impl OAuthErrorCode {
    /// Returns the RFC 6749 error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::InteractionRequired => "interaction_required",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    /// Returns the HTTP status for the error.
    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidRequest
            | Self::InvalidGrant
            | Self::UnauthorizedClient
            | Self::UnsupportedGrantType
            | Self::UnsupportedResponseType
            | Self::InvalidScope => StatusCode::BAD_REQUEST,
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::AccessDenied
            | Self::LoginRequired
            | Self::ConsentRequired
            | Self::InteractionRequired => StatusCode::FORBIDDEN,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// A safe OAuth error response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    code: OAuthErrorCode,
    description: &'static str,
}

impl OAuthError {
    /// Creates an error with a fixed, non-sensitive description.
    pub const fn new(code: OAuthErrorCode, description: &'static str) -> Self {
        Self { code, description }
    }

    /// Maps a domain error to an OAuth error without exposing its message.
    pub const fn from_domain(error: &DomainError) -> Self {
        match error.code() {
            ErrorCode::InvalidInput => Self::new(
                OAuthErrorCode::InvalidRequest,
                "the request is malformed or missing a required parameter",
            ),
            ErrorCode::NotFound => Self::new(
                OAuthErrorCode::InvalidRequest,
                "the requested resource is not available",
            ),
            ErrorCode::Conflict => Self::new(
                OAuthErrorCode::InvalidGrant,
                "the request conflicts with the current state",
            ),
            ErrorCode::Forbidden => Self::new(OAuthErrorCode::AccessDenied, "access is denied"),
            ErrorCode::Unauthenticated => Self::new(
                OAuthErrorCode::InvalidClient,
                "client authentication failed",
            ),
            ErrorCode::RateLimited => Self::new(
                OAuthErrorCode::TemporarilyUnavailable,
                "the request was rate limited",
            ),
            ErrorCode::Unavailable => Self::new(
                OAuthErrorCode::TemporarilyUnavailable,
                "the service is temporarily unavailable",
            ),
            ErrorCode::Internal => {
                Self::new(OAuthErrorCode::ServerError, "an internal error occurred")
            }
        }
    }

    /// Returns the error code.
    pub const fn code(&self) -> OAuthErrorCode {
        self.code
    }

    /// Returns the safe error description.
    pub const fn description(&self) -> &'static str {
        self.description
    }
}

impl From<DomainError> for OAuthError {
    fn from(error: DomainError) -> Self {
        Self::from_domain(&error)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.code.as_str(),
            "error_description": self.description,
        }));
        (
            self.code.status(),
            [(header::CACHE_CONTROL, "no-store")],
            body,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_errors_map_to_stable_oauth_codes() {
        let cases = [
            (ErrorCode::InvalidInput, OAuthErrorCode::InvalidRequest),
            (ErrorCode::NotFound, OAuthErrorCode::InvalidRequest),
            (ErrorCode::Conflict, OAuthErrorCode::InvalidGrant),
            (ErrorCode::Forbidden, OAuthErrorCode::AccessDenied),
            (ErrorCode::Unauthenticated, OAuthErrorCode::InvalidClient),
            (
                ErrorCode::RateLimited,
                OAuthErrorCode::TemporarilyUnavailable,
            ),
            (
                ErrorCode::Unavailable,
                OAuthErrorCode::TemporarilyUnavailable,
            ),
            (ErrorCode::Internal, OAuthErrorCode::ServerError),
        ];

        for (domain, oauth) in cases {
            let error = DomainError::new(domain, "sensitive internal detail");
            assert_eq!(OAuthError::from(error).code(), oauth);
        }
    }

    #[test]
    fn internal_errors_do_not_expose_the_domain_message() {
        let error = OAuthError::from(DomainError::new(
            ErrorCode::Internal,
            "database password was rejected",
        ));
        assert_eq!(error.code(), OAuthErrorCode::ServerError);
        assert!(!error.description().contains("password"));
    }
}
