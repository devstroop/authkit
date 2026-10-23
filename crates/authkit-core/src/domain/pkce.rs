use core::fmt;

use crate::domain::value::ValueError;

const CHALLENGE_LEN: usize = 43;
const MAX_NONCE_LEN: usize = 255;

/// A PKCE S256 code challenge.
///
/// The value is the base64url encoding of the SHA-256 digest of the verifier. It is not the
/// verifier itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PkceChallenge(String);

impl PkceChallenge {
    /// Parses a base64url-encoded S256 challenge.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "pkce_challenge",
            });
        }
        if value.len() != CHALLENGE_LEN {
            return Err(ValueError::InvalidFormat {
                field: "pkce_challenge",
                reason: "must be 43 base64url characters for S256",
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ValueError::InvalidFormat {
                field: "pkce_challenge",
                reason: "must use base64url characters only",
            });
        }

        Ok(Self(value))
    }

    /// Returns the encoded challenge.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PkceChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An OIDC nonce supplied by the client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(String);

impl Nonce {
    /// Parses a printable ASCII nonce.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty { field: "nonce" });
        }
        if value.len() > MAX_NONCE_LEN {
            return Err(ValueError::TooLong {
                field: "nonce",
                max: MAX_NONCE_LEN,
                actual: value.len(),
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ValueError::InvalidFormat {
                field: "nonce",
                reason: "must contain printable ASCII characters only",
            });
        }

        Ok(Self(value))
    }

    /// Returns the nonce.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    #[test]
    fn accepts_base64url_challenges() {
        let challenge = PkceChallenge::parse(CHALLENGE).expect("valid challenge");
        assert_eq!(challenge.as_str(), CHALLENGE);
    }

    #[test]
    fn rejects_wrong_length_or_invalid_challenges() {
        assert!(PkceChallenge::parse("short").is_err());
        assert!(PkceChallenge::parse("A".repeat(44)).is_err());
        assert!(PkceChallenge::parse("!".repeat(43)).is_err());
    }

    #[test]
    fn validates_nonces() {
        let nonce = Nonce::parse("n-0S6_WzA2Mj").expect("valid nonce");
        assert_eq!(nonce.as_str(), "n-0S6_WzA2Mj");
        assert!(Nonce::parse("").is_err());
        assert!(Nonce::parse("bad nonce").is_err());
    }
}
