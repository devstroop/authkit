//! SQLx persistence adapters for SQLite and Postgres.
//!
//! The core ports are synchronous. Each store owns a dedicated Tokio runtime and drives
//! SQLx futures on it, so use cases and domain tests stay runtime-agnostic. Callers inside
//! an async runtime must invoke store methods from a blocking thread (for example
//! `tokio::task::spawn_blocking`) rather than on an async worker.
//!
//! Create and drop the store on a blocking thread as well. Constructing or dropping it
//! inside an async task panics because the store owns a Tokio runtime.
//!
//! The adapter uses SQLx's runtime-selected [`Any`] driver so one implementation serves both
//! SQLite and Postgres. The native SQLite and Postgres drivers still perform the actual work;
//! the store selects the migration set and placeholder style from the connection dialect.

use std::fmt;
use std::future::Future;

use authkit_core::domain::{DomainError, ErrorCode};
use sqlx::any::{AnyPoolOptions, install_default_drivers};
use sqlx::{Any, Executor, Pool};
use tokio::runtime::{Builder, Runtime};

mod commands;
mod mapping;
mod repositories;

/// The SQL dialect used to translate portable `?` placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    fn placeholders(self, query: &str) -> String {
        match self {
            Self::Sqlite => query.to_owned(),
            Self::Postgres => {
                let mut index = 0_u32;
                let mut rendered = String::with_capacity(query.len() + 8);
                for character in query.chars() {
                    if character == '?' {
                        index += 1;
                        rendered.push('$');
                        rendered.push_str(&index.to_string());
                    } else {
                        rendered.push(character);
                    }
                }
                rendered
            }
        }
    }
}

/// A synchronous SQLx-backed repository bundle.
pub struct SqlStore {
    pool: Pool<Any>,
    runtime: Runtime,
    dialect: Dialect,
}

impl SqlStore {
    /// Connects to the database selected by the URL scheme.
    ///
    /// `max_connections` must be greater than zero. In-memory SQLite URLs always use a
    /// single connection so every operation sees the same database.
    pub fn connect(url: &str, max_connections: u32) -> Result<Self, StoreError> {
        if max_connections == 0 {
            return Err(StoreError::Configuration(
                "database max connections must be greater than zero".to_owned(),
            ));
        }
        if url.starts_with("sqlite:") {
            Self::connect_sqlite_with_max_connections(url, max_connections)
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            Self::connect_postgres_with_max_connections(url, max_connections)
        } else {
            Err(StoreError::Configuration(
                "database URL must start with sqlite:, postgres://, or postgresql://".to_owned(),
            ))
        }
    }

    /// Connects to a SQLite database with the default pool limit.
    ///
    /// The URL must select a database file or `sqlite::memory:`. Use a URL with
    /// `?mode=rwc` when the file may not exist yet. In-memory URLs use a single pooled
    /// connection so every operation sees the same database.
    pub fn connect_sqlite(url: &str) -> Result<Self, StoreError> {
        Self::connect_sqlite_with_max_connections(url, 5)
    }

    fn connect_sqlite_with_max_connections(
        url: &str,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        install_default_drivers();
        let runtime = build_runtime()?;
        let max_connections = sqlite_max_connections(url).min(max_connections);
        let pool = runtime.block_on(async {
            AnyPoolOptions::new()
                .max_connections(max_connections)
                .after_connect(|connection, _metadata| {
                    Box::pin(async move {
                        connection.execute("PRAGMA foreign_keys = ON").await?;
                        Ok(())
                    })
                })
                .connect(url)
                .await
        })?;
        Ok(Self {
            pool,
            runtime,
            dialect: Dialect::Sqlite,
        })
    }

    /// Creates a single-connection in-memory SQLite store.
    pub fn sqlite_in_memory() -> Result<Self, StoreError> {
        Self::connect_sqlite_with_max_connections("sqlite::memory:", 1)
    }

    /// Connects to a Postgres database with the default pool limit.
    pub fn connect_postgres(url: &str) -> Result<Self, StoreError> {
        Self::connect_postgres_with_max_connections(url, 5)
    }

    fn connect_postgres_with_max_connections(
        url: &str,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        install_default_drivers();
        let runtime = build_runtime()?;
        let pool = runtime.block_on(async {
            AnyPoolOptions::new()
                .max_connections(max_connections)
                .connect(url)
                .await
        })?;
        Ok(Self {
            pool,
            runtime,
            dialect: Dialect::Postgres,
        })
    }

    /// Applies the migration set for this store's dialect.
    pub fn migrate(&self) -> Result<(), StoreError> {
        match self.dialect {
            Dialect::Sqlite => self
                .runtime
                .block_on(sqlx::migrate!("./migrations/sqlite").run(&self.pool))
                .map_err(StoreError::Migrate),
            Dialect::Postgres => self
                .runtime
                .block_on(sqlx::migrate!("./migrations/postgres").run(&self.pool))
                .map_err(StoreError::Migrate),
        }
    }

    /// Runs a trivial query to verify that the database is reachable.
    pub fn ping(&self) -> Result<(), StoreError> {
        self.block_on(async {
            sqlx::query("SELECT 1").execute(&self.pool).await?;
            Ok(())
        })
    }

    fn sql(&self, query: &str) -> String {
        self.dialect.placeholders(query)
    }

    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

fn sqlite_max_connections(url: &str) -> u32 {
    if url.contains(":memory:") || url.contains("mode=memory") {
        1
    } else {
        5
    }
}

fn build_runtime() -> Result<Runtime, StoreError> {
    Builder::new_multi_thread()
        .enable_all()
        .thread_name("authkit-store")
        .build()
        .map_err(StoreError::Runtime)
}

/// A store construction or migration failure.
#[derive(Debug)]
pub enum StoreError {
    /// A database operation failed.
    Sqlx(sqlx::Error),
    /// A migration failed.
    Migrate(sqlx::migrate::MigrateError),
    /// The store runtime could not be created.
    Runtime(std::io::Error),
    /// A connection URL is invalid.
    Configuration(String),
}

impl StoreError {
    /// Returns a short, redacted description safe for logs and user-facing errors.
    pub fn safe_message(&self) -> &str {
        match self {
            Self::Sqlx(_) => "database operation failed",
            Self::Migrate(_) => "migration failed",
            Self::Runtime(_) => "store runtime failed",
            Self::Configuration(error) => error,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlx(error) => write!(formatter, "database error: {error}"),
            Self::Migrate(error) => write!(formatter, "migration error: {error}"),
            Self::Runtime(error) => write!(formatter, "store runtime error: {error}"),
            Self::Configuration(error) => write!(formatter, "store configuration error: {error}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Sqlx(error)
    }
}

fn map_db_error(error: sqlx::Error) -> DomainError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return DomainError::conflict("a unique constraint was violated");
        }
        if database.is_foreign_key_violation() {
            return DomainError::not_found("a referenced record does not exist");
        }
        if database.is_check_violation() {
            return DomainError::invalid("a stored value violates a database constraint");
        }
    }
    DomainError::new(ErrorCode::Unavailable, "storage is temporarily unavailable")
}

fn invalid_stored_value() -> DomainError {
    DomainError::new(ErrorCode::Internal, "stored data is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_rejects_zero_connections() {
        assert!(matches!(
            SqlStore::connect("sqlite::memory:", 0),
            Err(StoreError::Configuration(_))
        ));
    }

    #[test]
    fn connect_rejects_unknown_schemes() {
        assert!(matches!(
            SqlStore::connect("mysql://localhost/authkit", 5),
            Err(StoreError::Configuration(_))
        ));
    }
}
