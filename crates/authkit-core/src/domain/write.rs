/// The outcome of a guarded write batch.
///
/// Storage adapters execute a batch atomically and report exactly one of these outcomes.
/// A conflict or missing row is not retried blindly for one-time grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Every guard matched and the intended writes were applied.
    Applied,
    /// A compare-and-set guard failed because another write won the race.
    Conflict,
    /// A required row was absent or no longer matched the expected state.
    NotFound,
}

impl WriteOutcome {
    /// Returns `true` only when the write was applied.
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_applied_counts_as_success() {
        assert!(WriteOutcome::Applied.is_applied());
        assert!(!WriteOutcome::Conflict.is_applied());
        assert!(!WriteOutcome::NotFound.is_applied());
    }
}
