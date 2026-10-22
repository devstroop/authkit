//! Domain types and invariants.
//!
//! Domain modules do not know about transport, storage, templates, or runtime types.

pub mod error;
pub mod id;
pub mod tenant;
pub mod time;
pub mod write;

pub use error::{DomainError, ErrorCode};
pub use id::{Entity, Id, IdError};
pub use tenant::TenantContext;
pub use time::Timestamp;
pub use write::WriteOutcome;
