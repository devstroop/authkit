//! Typed runtime configuration.
//!
//! Configuration is read from the environment, validated before the server binds, and
//! represented without secret values in `Debug` output.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use url::Url;
use zeroize::Zeroizing;

/// The deployment environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Local development. Plain HTTP issuers are allowed.
    Development,
    /// Automated tests. Plain HTTP issuers are allowed.
    Test,
    /// Production. The issuer must use HTTPS.
    Production,
}

impl Environment {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" => Ok(Self::Production),
            _ => Err(ConfigError::invalid(
                "AUTHKIT_ENV",
                "must be development, test, or production",
            )),
        }
    }

    const fn allows_http(self) -> bool {
        matches!(self, Self::Development | Self::Test)
    }
}

/// The tracing output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Newline-delimited JSON.
    Json,
    /// Human-readable output for local development.
    Pretty,
}

impl LogFormat {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" => Ok(Self::Pretty),
            _ => Err(ConfigError::invalid(
                "AUTHKIT_LOG_FORMAT",
                "must be json or pretty",
            )),
        }
    }
}

/// A validated, canonical issuer origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer(String);

impl Issuer {
    /// Parses and validates an issuer URL.
    ///
    /// The issuer must be an absolute HTTP(S) origin with no path, query, fragment, or
    /// user information. HTTPS is required outside development and test environments.
    pub fn parse(value: &str, environment: Environment) -> Result<Self, ConfigError> {
        let url = Url::parse(value.trim()).map_err(|_| {
            ConfigError::invalid("AUTHKIT_ISSUER", "must be an absolute URL with a host")
        })?;

        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::invalid(
                "AUTHKIT_ISSUER",
                "must use the http or https scheme",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::invalid(
                "AUTHKIT_ISSUER",
                "must not contain user information",
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(ConfigError::invalid(
                "AUTHKIT_ISSUER",
                "must not contain a query or fragment",
            ));
        }
        if url.path() != "/" && !url.path().is_empty() {
            return Err(ConfigError::invalid(
                "AUTHKIT_ISSUER",
                "must be an origin without a path",
            ));
        }
        if url.scheme() == "http" && !environment.allows_http() {
            return Err(ConfigError::invalid(
                "AUTHKIT_ISSUER",
                "must use HTTPS outside development and test environments",
            ));
        }

        Ok(Self(url.origin().ascii_serialization()))
    }

    /// Returns the canonical issuer origin.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Issuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The supported native database dialects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    /// SQLite.
    Sqlite,
    /// PostgreSQL.
    Postgres,
}

/// A validated database connection configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    url: String,
    kind: DatabaseKind,
    max_connections: u32,
}

impl DatabaseConfig {
    /// Returns the connection URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the database dialect.
    pub const fn kind(&self) -> DatabaseKind {
        self.kind
    }

    /// Returns the connection pool limit.
    pub const fn max_connections(&self) -> u32 {
        self.max_connections
    }
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("url", &"<redacted>")
            .field("kind", &self.kind)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

/// Validated native signing-key configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKeyConfig {
    file: PathBuf,
    kek: Zeroizing<Vec<u8>>,
    retired_publish_secs: u64,
}

impl SigningKeyConfig {
    pub(crate) fn new(file: PathBuf, kek: Vec<u8>, retired_publish_secs: u64) -> Self {
        Self {
            file,
            kek: Zeroizing::new(kek),
            retired_publish_secs,
        }
    }

    /// Returns the encrypted keyring file path.
    pub fn file(&self) -> &std::path::Path {
        &self.file
    }

    /// Returns the 32-byte key-encryption key.
    pub fn kek(&self) -> &[u8] {
        self.kek.as_slice()
    }

    /// Returns how long retired public keys remain published.
    pub const fn retired_publish_secs(&self) -> u64 {
        self.retired_publish_secs
    }
}

impl fmt::Debug for SigningKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyConfig")
            .field("file", &self.file)
            .field("kek", &"<redacted>")
            .field("retired_publish_secs", &self.retired_publish_secs)
            .finish()
    }
}

/// Fully validated server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    environment: Environment,
    bind_addr: SocketAddr,
    issuer: Issuer,
    database: DatabaseConfig,
    signing_keys: SigningKeyConfig,
    log_format: LogFormat,
}

impl Config {
    /// Loads and validates configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(|key| std::env::var(key).ok())
    }

    fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let environment = match get("AUTHKIT_ENV") {
            Some(value) => Environment::parse(&value)?,
            None => Environment::Production,
        };

        let bind_addr = get("AUTHKIT_BIND_ADDR")
            .unwrap_or_else(|| "127.0.0.1:3000".to_owned())
            .parse()
            .map_err(|_| ConfigError::invalid("AUTHKIT_BIND_ADDR", "must be a socket address"))?;

        let issuer_value = required(&get, "AUTHKIT_ISSUER")?;
        let issuer = Issuer::parse(&issuer_value, environment)?;

        let url = get("AUTHKIT_DATABASE_URL")
            .or_else(|| get("DATABASE_URL"))
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ConfigError::missing("AUTHKIT_DATABASE_URL"))?;
        let kind = database_kind(&url)?;
        let max_connections = match get("AUTHKIT_DATABASE_MAX_CONNECTIONS") {
            Some(value) => value
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    ConfigError::invalid(
                        "AUTHKIT_DATABASE_MAX_CONNECTIONS",
                        "must be a positive integer",
                    )
                })?,
            None => 5,
        };

        let signing_key_file = get("AUTHKIT_SIGNING_KEY_FILE")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "authkit-signing-keys.json".to_owned());
        if environment == Environment::Production && PathBuf::from(&signing_key_file).is_relative()
        {
            return Err(ConfigError::invalid(
                "AUTHKIT_SIGNING_KEY_FILE",
                "must be an absolute path in production",
            ));
        }
        let kek = decode_kek(&required(&get, "AUTHKIT_SIGNING_KEY_KEK")?)?;
        let retired_publish_secs = match get("AUTHKIT_SIGNING_KEY_RETIRED_PUBLISH_SECS") {
            Some(value) => value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|value| (1..=86_400).contains(value))
                .ok_or_else(|| {
                    ConfigError::invalid(
                        "AUTHKIT_SIGNING_KEY_RETIRED_PUBLISH_SECS",
                        "must be an integer between 1 and 86400",
                    )
                })?,
            None => 900,
        };

        let log_format = match get("AUTHKIT_LOG_FORMAT") {
            Some(value) => LogFormat::parse(&value)?,
            None => {
                if environment == Environment::Production {
                    LogFormat::Json
                } else {
                    LogFormat::Pretty
                }
            }
        };

        Ok(Self {
            environment,
            bind_addr,
            issuer,
            database: DatabaseConfig {
                url,
                kind,
                max_connections,
            },
            signing_keys: SigningKeyConfig::new(
                PathBuf::from(signing_key_file),
                kek,
                retired_publish_secs,
            ),
            log_format,
        })
    }

    /// Returns the deployment environment.
    pub const fn environment(&self) -> Environment {
        self.environment
    }

    /// Returns the listen address.
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Returns the canonical issuer.
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// Returns the database configuration.
    pub fn database(&self) -> &DatabaseConfig {
        &self.database
    }

    /// Returns the signing-key configuration.
    pub fn signing_keys(&self) -> &SigningKeyConfig {
        &self.signing_keys
    }

    /// Returns the tracing output format.
    pub const fn log_format(&self) -> LogFormat {
        self.log_format
    }
}

fn required(
    get: &impl Fn(&str) -> Option<String>,
    variable: &'static str,
) -> Result<String, ConfigError> {
    get(variable)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ConfigError::missing(variable))
}

fn decode_kek(value: &str) -> Result<Vec<u8>, ConfigError> {
    let normalized = value
        .trim()
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    let key = URL_SAFE_NO_PAD.decode(normalized).map_err(|_| {
        ConfigError::invalid("AUTHKIT_SIGNING_KEY_KEK", "must be base64url-encoded")
    })?;
    if key.len() != 32 {
        return Err(ConfigError::invalid(
            "AUTHKIT_SIGNING_KEY_KEK",
            "must decode to exactly 32 bytes",
        ));
    }
    Ok(key)
}

fn database_kind(url: &str) -> Result<DatabaseKind, ConfigError> {
    if url.starts_with("sqlite:") {
        Ok(DatabaseKind::Sqlite)
    } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        Ok(DatabaseKind::Postgres)
    } else {
        Err(ConfigError::invalid(
            "AUTHKIT_DATABASE_URL",
            "must start with sqlite:, postgres://, or postgresql://",
        ))
    }
}

/// A configuration validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    variable: &'static str,
    message: String,
}

impl ConfigError {
    fn missing(variable: &'static str) -> Self {
        Self {
            variable,
            message: "is required".to_owned(),
        }
    }

    fn invalid(variable: &'static str, message: impl Into<String>) -> Self {
        Self {
            variable,
            message: message.into(),
        }
    }

    /// Returns the configuration variable that failed validation.
    pub const fn variable(&self) -> &'static str {
        self.variable
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid configuration for {}: {}",
            self.variable, self.message
        )
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_vars(|key| {
            vars.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    fn base_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            ("AUTHKIT_ENV", "production"),
            ("AUTHKIT_ISSUER", "https://auth.example.com"),
            ("AUTHKIT_DATABASE_URL", "sqlite://authkit.db?mode=rwc"),
            (
                "AUTHKIT_SIGNING_KEY_KEK",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            ),
            (
                "AUTHKIT_SIGNING_KEY_FILE",
                "/var/lib/authkit/signing-keys.json",
            ),
        ]
    }

    #[test]
    fn defaults_are_production_safe() {
        let config = config(&[
            ("AUTHKIT_ISSUER", "https://auth.example.com"),
            ("AUTHKIT_DATABASE_URL", "sqlite::memory:"),
            (
                "AUTHKIT_SIGNING_KEY_KEK",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            ),
            (
                "AUTHKIT_SIGNING_KEY_FILE",
                "/var/lib/authkit/signing-keys.json",
            ),
        ])
        .expect("valid config");
        assert_eq!(config.environment(), Environment::Production);
        assert_eq!(config.bind_addr(), "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.database().max_connections(), 5);
        assert_eq!(config.signing_keys().retired_publish_secs(), 900);
        assert_eq!(config.log_format(), LogFormat::Json);
    }

    #[test]
    fn development_allows_http_issuers() {
        let mut vars = base_vars();
        vars[0] = ("AUTHKIT_ENV", "development");
        vars[1] = ("AUTHKIT_ISSUER", "http://localhost:3000");
        let config = config(&vars).expect("valid development config");
        assert_eq!(config.issuer().as_str(), "http://localhost:3000");
        assert_eq!(config.log_format(), LogFormat::Pretty);
    }

    #[test]
    fn production_rejects_http_issuers() {
        let mut vars = base_vars();
        vars[1] = ("AUTHKIT_ISSUER", "http://auth.example.com");
        let error = config(&vars).expect_err("HTTP issuer must fail");
        assert_eq!(error.variable(), "AUTHKIT_ISSUER");
    }

    #[test]
    fn issuer_is_canonicalized_to_an_origin() {
        let mut vars = base_vars();
        vars[1] = ("AUTHKIT_ISSUER", "https://auth.example.com/");
        let config = config(&vars).expect("valid config");
        assert_eq!(config.issuer().as_str(), "https://auth.example.com");
    }

    #[test]
    fn issuer_rejects_paths_queries_fragments_and_credentials() {
        for issuer in [
            "https://auth.example.com/auth",
            "https://auth.example.com?tenant=one",
            "https://auth.example.com#fragment",
            "https://user:secret@auth.example.com",
        ] {
            let mut vars = base_vars();
            vars[1] = ("AUTHKIT_ISSUER", issuer);
            let error = config(&vars).expect_err("invalid issuer must fail");
            assert_eq!(error.variable(), "AUTHKIT_ISSUER");
        }
    }

    #[test]
    fn required_values_and_database_schemes_are_validated() {
        let error = config(&[("AUTHKIT_ENV", "production")]).expect_err("missing issuer");
        assert_eq!(error.variable(), "AUTHKIT_ISSUER");

        let mut vars = base_vars();
        vars[2] = ("AUTHKIT_DATABASE_URL", "mysql://localhost/authkit");
        let error = config(&vars).expect_err("unsupported database scheme");
        assert_eq!(error.variable(), "AUTHKIT_DATABASE_URL");

        let mut vars = base_vars();
        vars[2] = ("AUTHKIT_DATABASE_URL", "postgresql://localhost/authkit");
        let config = config(&vars).expect("valid Postgres config");
        assert_eq!(config.database().kind(), DatabaseKind::Postgres);
    }

    #[test]
    fn max_connections_must_be_positive() {
        let mut vars = base_vars();
        vars.push(("AUTHKIT_DATABASE_MAX_CONNECTIONS", "0"));
        let error = config(&vars).expect_err("zero connections must fail");
        assert_eq!(error.variable(), "AUTHKIT_DATABASE_MAX_CONNECTIONS");
    }

    #[test]
    fn database_debug_output_is_redacted() {
        let mut vars = base_vars();
        vars[2] = (
            "AUTHKIT_DATABASE_URL",
            "postgres://authkit:super-secret@localhost/authkit",
        );
        let config = config(&vars).expect("valid Postgres config");
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn signing_key_kek_is_required_and_must_be_32_bytes() {
        let mut vars = base_vars();
        vars.retain(|(name, _)| *name != "AUTHKIT_SIGNING_KEY_KEK");
        let error = config(&vars).expect_err("missing KEK");
        assert_eq!(error.variable(), "AUTHKIT_SIGNING_KEY_KEK");

        let mut vars = base_vars();
        vars.retain(|(name, _)| *name != "AUTHKIT_SIGNING_KEY_KEK");
        vars.push(("AUTHKIT_SIGNING_KEY_KEK", "too-short"));
        let error = config(&vars).expect_err("short KEK");
        assert_eq!(error.variable(), "AUTHKIT_SIGNING_KEY_KEK");
    }

    #[test]
    fn production_requires_an_absolute_signing_key_file() {
        let mut vars = base_vars();
        let index = vars
            .iter()
            .position(|(name, _)| *name == "AUTHKIT_SIGNING_KEY_FILE")
            .expect("base signing key file");
        vars[index] = ("AUTHKIT_SIGNING_KEY_FILE", "authkit-signing-keys.json");
        let error = config(&vars).expect_err("relative production keyring path");
        assert_eq!(error.variable(), "AUTHKIT_SIGNING_KEY_FILE");

        let mut vars = base_vars();
        vars.push((
            "AUTHKIT_SIGNING_KEY_FILE",
            "/var/lib/authkit/signing-keys.json",
        ));
        config(&vars).expect("absolute production keyring path");
    }

    #[test]
    fn retired_publish_window_is_bounded() {
        let mut vars = base_vars();
        vars.push(("AUTHKIT_SIGNING_KEY_RETIRED_PUBLISH_SECS", "0"));
        let error = config(&vars).expect_err("zero publish window");
        assert_eq!(error.variable(), "AUTHKIT_SIGNING_KEY_RETIRED_PUBLISH_SECS");
    }

    #[test]
    fn unknown_environment_and_log_format_fail() {
        let mut vars = base_vars();
        vars[0] = ("AUTHKIT_ENV", "staging");
        assert_eq!(
            config(&vars).expect_err("unknown environment").variable(),
            "AUTHKIT_ENV"
        );

        let mut vars = base_vars();
        vars.push(("AUTHKIT_LOG_FORMAT", "xml"));
        assert_eq!(
            config(&vars).expect_err("unknown log format").variable(),
            "AUTHKIT_LOG_FORMAT"
        );
    }
}
