//! AuthKit persistence adapters.
//!
//! SQLx implementations for SQLite and Postgres live here, with the D1 adapter behind a
//! feature gate. Repositories are added in milestone M1; this crate currently provides the
//! workspace boundary so adapters cannot leak into `authkit-core`.

#![forbid(unsafe_code)]

/// Database backends that the native runtime intends to support.
pub const NATIVE_DATABASES: &[&str] = &["sqlite", "postgres"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_database_list_is_stable() {
        assert_eq!(NATIVE_DATABASES, ["sqlite", "postgres"]);
    }
}
