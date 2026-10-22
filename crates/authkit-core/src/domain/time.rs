use core::fmt;

/// A UTC timestamp expressed as milliseconds since the Unix epoch.
///
/// The domain uses an injected clock; it never calls the operating system directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Creates a timestamp from non-negative epoch milliseconds.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Returns milliseconds since the Unix epoch.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Returns `true` when this timestamp is strictly before `other`.
    pub const fn is_before(self, other: Self) -> bool {
        self.0 < other.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_use_epoch_order() {
        let earlier = Timestamp::from_millis(1_000);
        let later = Timestamp::from_millis(2_000);
        assert!(earlier.is_before(later));
        assert!(!later.is_before(earlier));
        assert_eq!(later.as_millis(), 2_000);
    }
}
