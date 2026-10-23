use core::fmt;

use crate::domain::value::ValueError;

const MAX_DISPLAY_NAME_LEN: usize = 128;

/// A human-readable display name.
///
/// Display names are presentation data only; they are never used for authorization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisplayName(String);

impl DisplayName {
    /// Parses and trims a display name.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into().trim().to_owned();

        if value.is_empty() {
            return Err(ValueError::Empty {
                field: "display name",
            });
        }
        if value.chars().count() > MAX_DISPLAY_NAME_LEN {
            return Err(ValueError::TooLong {
                field: "display name",
                max: MAX_DISPLAY_NAME_LEN,
                actual: value.chars().count(),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ValueError::InvalidFormat {
                field: "display name",
                reason: "must not contain control characters",
            });
        }

        Ok(Self(value))
    }

    /// Returns the trimmed display name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for DisplayName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_accepts_unicode() {
        let name = DisplayName::parse("  Ada Lovelace  ").expect("valid name");
        assert_eq!(name.as_str(), "Ada Lovelace");
    }

    #[test]
    fn rejects_empty_and_control_characters() {
        assert!(DisplayName::parse("   ").is_err());
        assert!(DisplayName::parse("bad\u{0}name").is_err());
    }
}
