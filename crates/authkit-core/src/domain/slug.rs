use core::fmt;

use crate::domain::value::ValueError;

const MIN_SLUG_LEN: usize = 3;
const MAX_SLUG_LEN: usize = 48;

/// A URL-safe, lowercase identifier used by organizations and applications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slug(String);

impl Slug {
    /// Parses a lowercase ASCII slug.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into().trim().to_owned();

        if value.is_empty() {
            return Err(ValueError::Empty { field: "slug" });
        }
        if value.len() < MIN_SLUG_LEN {
            return Err(ValueError::TooShort {
                field: "slug",
                min: MIN_SLUG_LEN,
                actual: value.len(),
            });
        }
        if value.len() > MAX_SLUG_LEN {
            return Err(ValueError::TooLong {
                field: "slug",
                max: MAX_SLUG_LEN,
                actual: value.len(),
            });
        }
        if !value.is_ascii() {
            return Err(ValueError::InvalidFormat {
                field: "slug",
                reason: "must use ASCII characters",
            });
        }
        if value.starts_with('-') || value.ends_with('-') || value.contains("--") {
            return Err(ValueError::InvalidFormat {
                field: "slug",
                reason: "must not start or end with a hyphen or contain consecutive hyphens",
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ValueError::InvalidFormat {
                field: "slug",
                reason: "must contain only lowercase letters, digits, and hyphens",
            });
        }

        Ok(Self(value))
    }

    /// Returns the normalized slug.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for Slug {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_lowercase_slugs() {
        let slug = Slug::parse("  acme-platform  ").expect("valid slug");
        assert_eq!(slug.as_str(), "acme-platform");
    }

    #[test]
    fn rejects_unsafe_slugs() {
        for value in [
            "",
            "ab",
            "Acme",
            "acme_platform",
            "-acme",
            "acme-",
            "acme--platform",
        ] {
            assert!(Slug::parse(value).is_err(), "{value:?} should be rejected");
        }
    }
}
