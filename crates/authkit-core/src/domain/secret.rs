use core::fmt;

use crate::domain::value::ValueError;

const MIN_SECRET_HASH_LEN: usize = 16;
const MAX_SECRET_HASH_LEN: usize = 512;

/// An opaque, non-reversible credential or token verifier.
///
/// The domain never sees a plaintext password, session token, refresh token, or client
/// secret. Adapters store the encoded hash in this wrapper and compare in constant time.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SecretHash(String);

impl SecretHash {
    /// Validates an encoded hash.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "secret hash",
            });
        }
        if value.len() < MIN_SECRET_HASH_LEN {
            return Err(ValueError::TooShort {
                field: "secret hash",
                min: MIN_SECRET_HASH_LEN,
                actual: value.len(),
            });
        }
        if value.len() > MAX_SECRET_HASH_LEN {
            return Err(ValueError::TooLong {
                field: "secret hash",
                max: MAX_SECRET_HASH_LEN,
                actual: value.len(),
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ValueError::InvalidFormat {
                field: "secret hash",
                reason: "must contain only printable ASCII characters",
            });
        }

        Ok(Self(value))
    }

    /// Returns the encoded hash.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretHash([redacted])")
    }
}

impl fmt::Display for SecretHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_encoded_hashes() {
        let hash = SecretHash::parse("sha256:0123456789abcdef").expect("valid hash");
        assert_eq!(hash.as_str(), "sha256:0123456789abcdef");
        assert_eq!(hash.to_string(), "[redacted]");
        assert_eq!(format!("{hash:?}"), "SecretHash([redacted])");
    }

    #[test]
    fn rejects_short_or_whitespace_hashes() {
        assert!(SecretHash::parse("short").is_err());
        assert!(SecretHash::parse("0123456789abcdef with space").is_err());
    }
}
