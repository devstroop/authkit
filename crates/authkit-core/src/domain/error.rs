use core::fmt;

/// Stable error category exposed to adapters.
///
/// Transport and storage adapters map these codes to their own errors and responses. The
/// code is stable; the message is not a machine-readable contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The input is malformed or violates a domain rule.
    InvalidInput,
    /// The requested resource does not exist in the caller's tenant.
    NotFound,
    /// The write lost a race or violates a uniqueness or state guard.
    Conflict,
    /// The authenticated principal may not perform this action.
    Forbidden,
    /// Authentication is required or the credential is invalid.
    Unauthenticated,
    /// The caller exceeded a rate or abuse limit.
    RateLimited,
    /// A dependency is temporarily unavailable; the caller may retry safely.
    Unavailable,
    /// An unexpected internal failure occurred. Details are not exposed.
    Internal,
}

impl ErrorCode {
    /// Returns the stable snake-case code used by adapters and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Forbidden => "forbidden",
            Self::Unauthenticated => "unauthenticated",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A domain failure with a stable code and a non-sensitive message.
///
/// Messages must never contain credentials, tokens, raw personal data, or internal storage
/// details. Adapters may log them, but should return their own safe representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    code: ErrorCode,
    message: String,
}

impl DomainError {
    /// Creates an error with an explicit code and safe message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Creates an `InvalidInput` error.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    /// Creates a `NotFound` error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// Creates a `Conflict` error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Conflict, message)
    }

    /// Creates a `Forbidden` error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Forbidden, message)
    }
    /// Creates an `Unauthenticated` error.
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unauthenticated, message)
    }

    /// Returns the stable error code.
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the safe human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(ErrorCode::InvalidInput.as_str(), "invalid_input");
        assert_eq!(ErrorCode::NotFound.as_str(), "not_found");
        assert_eq!(ErrorCode::Conflict.as_str(), "conflict");
        assert_eq!(ErrorCode::Forbidden.as_str(), "forbidden");
        assert_eq!(ErrorCode::Unauthenticated.as_str(), "unauthenticated");
        assert_eq!(ErrorCode::RateLimited.as_str(), "rate_limited");
        assert_eq!(ErrorCode::Unavailable.as_str(), "unavailable");
        assert_eq!(ErrorCode::Internal.as_str(), "internal");
    }

    #[test]
    fn error_display_includes_code_and_message() {
        let error = DomainError::conflict("membership already exists");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(error.to_string(), "conflict: membership already exists");
    }
}
