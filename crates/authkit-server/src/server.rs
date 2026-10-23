//! Server startup and shutdown.

use std::fmt;
use std::sync::Arc;

use authkit_store::{SqlStore, StoreError};
use tokio::net::TcpListener;
use tracing::info;

use crate::authorization::AuthorizationService;
use crate::config::{Config, Environment};
use crate::http::{ReadinessProbe, SqlStoreReadiness, router_with_sessions};
use crate::session::{SessionService, SystemClock};
use crate::signing::{KeyRing, KeyRingError, unix_now};

/// A server startup, bind, or shutdown failure.
#[derive(Debug)]
pub enum ServerError {
    /// The database store could not be created.
    Store(StoreError),
    /// The signing keyring could not be loaded.
    Signing(KeyRingError),
    /// The listen address could not be bound.
    Bind(std::io::Error),
    /// The HTTP server failed.
    Serve(std::io::Error),
    /// A blocking startup or shutdown task failed.
    Blocking(tokio::task::JoinError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(
                formatter,
                "database startup failed: {}",
                error.safe_message()
            ),
            Self::Signing(error) => write!(formatter, "signing key startup failed: {error}"),
            Self::Bind(error) => write!(formatter, "could not bind the listen address: {error}"),
            Self::Serve(error) => write!(formatter, "HTTP server failed: {error}"),
            Self::Blocking(error) => write!(formatter, "blocking task failed: {error}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<StoreError> for ServerError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<KeyRingError> for ServerError {
    fn from(error: KeyRingError) -> Self {
        Self::Signing(error)
    }
}

impl From<tokio::task::JoinError> for ServerError {
    fn from(error: tokio::task::JoinError) -> Self {
        Self::Blocking(error)
    }
}

/// Starts the native HTTP server.
///
/// The store is created and dropped on a blocking thread because it owns a dedicated
/// Tokio runtime. The server stops accepting new requests on `SIGINT` or `SIGTERM`.
pub async fn serve(config: Config) -> Result<(), ServerError> {
    let url = config.database().url().to_owned();
    let max_connections = config.database().max_connections();
    let store = tokio::task::spawn_blocking(move || SqlStore::connect(&url, max_connections))
        .await
        .map_err(ServerError::Blocking)??;
    let store = Arc::new(store);
    let result = serve_with_store(&config, store.clone()).await;
    shutdown_store(store).await;
    result
}

async fn serve_with_store(config: &Config, store: Arc<SqlStore>) -> Result<(), ServerError> {
    let signing_config = config.signing_keys().clone();
    let keys = tokio::task::spawn_blocking(move || {
        KeyRing::load_or_bootstrap(&signing_config, unix_now())
    })
    .await
    .map_err(ServerError::Blocking)??;
    let keys = Arc::new(keys);
    let readiness: Arc<dyn ReadinessProbe> = Arc::new(SqlStoreReadiness::new(store.clone()));
    let sessions = Arc::new(SessionService::new(
        store.clone(),
        config.session().clone(),
        config.environment(),
        Arc::new(SystemClock),
    ));
    let authorization = Arc::new(AuthorizationService::new(
        store.clone(),
        config.issuer().clone(),
        Arc::new(SystemClock),
    ));
    let app = router_with_sessions(
        readiness,
        keys,
        config.issuer().clone(),
        sessions,
        Some(authorization),
        config.environment() == Environment::Production,
    );
    let listener = TcpListener::bind(config.bind_addr())
        .await
        .map_err(ServerError::Bind)?;

    info!(
        address = %config.bind_addr(),
        issuer = %config.issuer(),
        "starting AuthKit server"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(ServerError::Serve)
}

async fn shutdown_store(store: Arc<SqlStore>) {
    match Arc::try_unwrap(store) {
        Ok(store) => {
            if let Err(error) = tokio::task::spawn_blocking(move || drop(store)).await {
                tracing::error!(error = %error, "store shutdown task failed");
            }
        }
        Err(store) => {
            tracing::error!("store still referenced during shutdown; leaking it to avoid a panic");
            std::mem::forget(store);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!("shutdown signal received");
}
