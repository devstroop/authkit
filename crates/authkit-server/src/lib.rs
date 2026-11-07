//! AuthKit native server library.
//!
//! The binary is a thin wrapper around this crate. Keeping the router, configuration, and
//! startup logic in a library makes them testable without spawning a process.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod config;
pub mod email;
pub mod password;
pub mod http;
pub mod metrics;
pub mod session;
pub mod totp;
pub mod signing;
pub mod telemetry;
pub mod tokens;

mod server;

pub use server::{ServerError, serve};
