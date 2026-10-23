use core::fmt;

/// A value-object validation failure.
///
/// The field name is stable enough for adapters to map the failure to a form field. The
/// reason is a short, non-sensitive explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// The value is empty after normalization.
    Empty {
        /// The field that failed validation.
        field: &'static str,
    },
    /// The value is shorter than the allowed minimum.
    TooShort {
        /// The field that failed validation.
        field: &'static str,
        /// The minimum accepted length.
        min: usize,
        /// The observed length.
        actual: usize,
    },
    /// The value is longer than the allowed maximum.
    TooLong {
        /// The field that failed validation.
        field: &'static str,
        /// The maximum accepted length.
        max: usize,
        /// The observed length.
        actual: usize,
    },
    /// The value has an invalid shape or contains a forbidden character.
    InvalidFormat {
        /// The field that failed validation.
        field: &'static str,
        /// A short, non-sensitive reason.
        reason: &'static str,
    },
}

impl ValueError {
    /// Returns the field that failed validation.
    pub const fn field(&self) -> &'static str {
        match self {
            Self::Empty { field }
            | Self::TooShort { field, .. }
            | Self::TooLong { field, .. }
            | Self::InvalidFormat { field, .. } => field,
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(formatter, "{field} must not be empty"),
            Self::TooShort { field, min, actual } => {
                write!(
                    formatter,
                    "{field} must be at least {min} characters, found {actual}"
                )
            }
            Self::TooLong { field, max, actual } => {
                write!(
                    formatter,
                    "{field} must be at most {max} characters, found {actual}"
                )
            }
            Self::InvalidFormat { field, reason } => write!(formatter, "{field} {reason}"),
        }
    }
}

impl std::error::Error for ValueError {}
