use core::fmt;

use crate::domain::value::ValueError;

const MAX_EMAIL_LEN: usize = 254;
const MAX_LOCAL_LEN: usize = 64;

/// A normalized, deployment-unique email address.
///
/// Parsing trims surrounding whitespace and lowercases ASCII characters. The local part and
/// domain are validated conservatively; internationalized addresses are not accepted in v1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Email(String);

impl Email {
    /// Parses and normalizes an email address.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into().trim().to_ascii_lowercase();

        if value.is_empty() {
            return Err(ValueError::Empty { field: "email" });
        }
        if value.len() > MAX_EMAIL_LEN {
            return Err(ValueError::TooLong {
                field: "email",
                max: MAX_EMAIL_LEN,
                actual: value.len(),
            });
        }
        if !value.is_ascii() {
            return Err(ValueError::InvalidFormat {
                field: "email",
                reason: "must use ASCII characters",
            });
        }
        if value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(ValueError::InvalidFormat {
                field: "email",
                reason: "must not contain whitespace or control characters",
            });
        }

        let (local, domain) = value.split_once('@').ok_or(ValueError::InvalidFormat {
            field: "email",
            reason: "must contain one @",
        })?;
        if domain.contains('@') {
            return Err(ValueError::InvalidFormat {
                field: "email",
                reason: "must contain one @",
            });
        }
        if local.is_empty() {
            return Err(ValueError::Empty {
                field: "email local part",
            });
        }
        if local.len() > MAX_LOCAL_LEN {
            return Err(ValueError::TooLong {
                field: "email local part",
                max: MAX_LOCAL_LEN,
                actual: local.len(),
            });
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(ValueError::InvalidFormat {
                field: "email local part",
                reason: "must not start or end with a dot or contain consecutive dots",
            });
        }
        validate_domain(domain)?;

        Ok(Self(value))
    }

    /// Returns the normalized address.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the local part before the `@`.
    pub fn local_part(&self) -> &str {
        self.0.split_once('@').map_or("", |(local, _)| local)
    }

    /// Returns the domain after the `@`.
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map_or("", |(_, domain)| domain)
    }
}

fn validate_domain(domain: &str) -> Result<(), ValueError> {
    if domain.is_empty() {
        return Err(ValueError::Empty {
            field: "email domain",
        });
    }
    if !domain.contains('.') {
        return Err(ValueError::InvalidFormat {
            field: "email domain",
            reason: "must contain a dot",
        });
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(ValueError::InvalidFormat {
            field: "email domain",
            reason: "must not start or end with a dot or contain consecutive dots",
        });
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ValueError::InvalidFormat {
                field: "email domain",
                reason: "has an invalid label length",
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ValueError::InvalidFormat {
                field: "email domain",
                reason: "labels must not start or end with a hyphen",
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ValueError::InvalidFormat {
                field: "email domain",
                reason: "labels may contain only ASCII letters, digits, and hyphens",
            });
        }
    }

    Ok(())
}

impl fmt::Display for Email {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_whitespace() {
        let email = Email::parse("  Alice@Example.COM \n").expect("valid email");
        assert_eq!(email.as_str(), "alice@example.com");
        assert_eq!(email.local_part(), "alice");
        assert_eq!(email.domain(), "example.com");
    }

    #[test]
    fn rejects_invalid_addresses() {
        for value in [
            "",
            "alice",
            "alice@@example.com",
            "alice@example",
            "@example.com",
            "alice@.example.com",
            "alice@example..com",
            "alice..bob@example.com",
            "alice@-example.com",
            "alice@exa mple.com",
        ] {
            assert!(Email::parse(value).is_err(), "{value:?} should be rejected");
        }
    }
}
