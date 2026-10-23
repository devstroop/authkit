use core::fmt;

use crate::domain::value::ValueError;

const MAX_REDIRECT_URI_LEN: usize = 2048;

/// A registered OAuth redirect URI.
///
/// Matching is exact string equality; there is no prefix, wildcard, or case folding.
/// V1 accepts HTTPS URIs and HTTP URIs only for loopback hosts. Custom native schemes are
/// deferred until the native-client profile is designed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// Parses a redirect URI conservatively.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "redirect_uri",
            });
        }
        if value.len() > MAX_REDIRECT_URI_LEN {
            return Err(ValueError::TooLong {
                field: "redirect_uri",
                max: MAX_REDIRECT_URI_LEN,
                actual: value.len(),
            });
        }
        if value.trim() != value {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must not have leading or trailing whitespace",
            });
        }
        if value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must not contain whitespace or control characters",
            });
        }
        if value.contains('#') {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must not contain a fragment",
            });
        }

        let (scheme, rest) = value.split_once("://").ok_or(ValueError::InvalidFormat {
            field: "redirect_uri",
            reason: "must be an absolute URI",
        })?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "https" && scheme != "http" {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must use https, or http for a loopback host",
            });
        }

        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must include a host",
            });
        }
        if authority.contains('@') {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must not include user information",
            });
        }

        let host = authority_host(authority);
        if host.is_empty() {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "must include a host",
            });
        }
        if scheme == "http" && !is_loopback_host(host) {
            return Err(ValueError::InvalidFormat {
                field: "redirect_uri",
                reason: "http is allowed only for loopback hosts",
            });
        }

        Ok(Self(value))
    }

    /// Returns the registered URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` when the candidate exactly matches this registered URI.
    pub fn matches(&self, candidate: &Self) -> bool {
        self.0 == candidate.0
    }
}

fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or("", |(host, _)| host);
    }
    authority.split(':').next().unwrap_or("")
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

impl fmt::Display for RedirectUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for RedirectUri {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_loopback_http() {
        for value in [
            "https://app.example.com/callback",
            "https://app.example.com/callback?tenant=acme",
            "http://localhost:3000/callback",
            "http://127.0.0.1:8080/callback",
            "http://[::1]:8080/callback",
        ] {
            assert!(
                RedirectUri::parse(value).is_ok(),
                "{value:?} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_uris() {
        for value in [
            "",
            "http://app.example.com/callback",
            "javascript:alert(1)",
            "https://app.example.com/callback#fragment",
            "https://user@app.example.com/callback",
            "https:///callback",
            " https://app.example.com/callback",
            "https://app.example.com/call back",
            "com.example.app:/callback",
        ] {
            assert!(
                RedirectUri::parse(value).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn matching_is_exact() {
        let registered = RedirectUri::parse("https://app.example.com/callback").expect("valid");
        let same = RedirectUri::parse("https://app.example.com/callback").expect("valid");
        let different = RedirectUri::parse("https://app.example.com/callback/").expect("valid");
        assert!(registered.matches(&same));
        assert!(!registered.matches(&different));
    }
}
