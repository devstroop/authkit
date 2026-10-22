//! Portable AuthKit domain model, ports, and application use cases.
//!
//! This crate must not depend on HTTP, SQL, templates, or a runtime. Adapters translate
//! their types into the types defined here; policy lives in this crate.

#![forbid(unsafe_code)]

pub mod application;
pub mod domain;
pub mod ports;
