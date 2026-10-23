//! AuthKit native server library.
//!
//! The binary is a thin wrapper around this crate. Keeping the router, configuration, and
//! startup logic in a library makes them testable without spawning a process.

#![forbid(unsafe_code)]

pub mod config;
pub mod http;
pub mod signing;
pub mod telemetry;

mod server;

pub use server::{ServerError, serve};
