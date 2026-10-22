//! Application use cases.
//!
//! Use cases load the minimum state, apply domain policy, and submit a guarded write batch.
//! They depend on ports, never on a concrete adapter. The first implementation slices land
//! with the identity, tenancy, and grant work in milestone M1.
