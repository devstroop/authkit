//! Tracing initialization.

use std::error::Error;

use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

/// Initializes structured tracing with a redaction-safe default filter.
///
/// `RUST_LOG` overrides the default `info` filter. Logs never include configuration
/// values or request bodies.
pub fn init_tracing(format: LogFormat) -> Result<(), Box<dyn Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    match format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.try_init(),
    }
}
