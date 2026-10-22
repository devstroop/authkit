//! Ports implemented by storage, cryptography, email, and runtime adapters.
//!
//! Ports are shaped around domain types. The core never imports a concrete adapter.

use crate::domain::Timestamp;
use crate::domain::id::{Entity, Id, IdError};

/// Supplies the current time to domain and application code.
pub trait Clock {
    /// Returns the current UTC time.
    fn now(&self) -> Timestamp;
}

/// Generates new typed entity identifiers.
///
/// Implementations must use a cryptographically secure random source and return a suffix
/// that satisfies [`Id::from_suffix`]. An unavailable or exhausted source returns an error
/// rather than a weak or duplicate identifier.
pub trait IdGenerator {
    /// Generates a new identifier for the requested entity kind.
    fn generate<E: Entity>(&self) -> Result<Id<E>, IdError>;
}
