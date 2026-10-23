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

/// The idle and absolute lifetime policy for one session audience.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLifetime {
    idle_secs: u64,
    absolute_secs: u64,
}

impl SessionLifetime {
    pub const fn new(idle_secs: u64, absolute_secs: u64) -> Self {
        Self {
            idle_secs,
            absolute_secs,
        }
    }

    /// Returns the idle timeout in seconds.
    pub const fn idle_secs(self) -> u64 {
        self.idle_secs
    }

    /// Returns the absolute timeout in seconds.
    pub const fn absolute_secs(self) -> u64 {
        self.absolute_secs
    }
}

/// Validated session, cookie, and CSRF configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pepper: Zeroizing<Vec<u8>>,
    cookie_secure: bool,
    account: SessionLifetime,
    admin: SessionLifetime,
}

impl SessionConfig {
    /// Creates a session configuration from its parts.
    ///
    /// Production callers should load [`Config`] from the environment so the pepper,
    /// cookie, and lifetime settings are validated together. This constructor is public
    /// for integration tests and alternate embedders.
    pub fn new(
        pepper: Vec<u8>,
        cookie_secure: bool,
        account: SessionLifetime,
        admin: SessionLifetime,
    ) -> Self {
        Self {
            pepper: Zeroizing::new(pepper),
            cookie_secure,
            account,
            admin,
        }
    }

    /// Returns the 32-byte session-token and CSRF pepper.
    pub fn pepper(&self) -> &[u8] {
        self.pepper.as_slice()
    }

    /// Returns whether browser cookies are marked `Secure`.
    pub const fn cookie_secure(&self) -> bool {
        self.cookie_secure
    }

    /// Returns the account-session lifetime policy.
    pub const fn account(&self) -> SessionLifetime {
        self.account
    }

    /// Returns the administrator-session lifetime policy.
    pub const fn admin(&self) -> SessionLifetime {
        self.admin
    }
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConfig")
            .field("pepper", &"<redacted>")
            .field("cookie_secure", &self.cookie_secure)
            .field("account", &self.account)
            .field("admin", &self.admin)
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
    session: SessionConfig,
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
        let kek = decode_key(
            &required(&get, "AUTHKIT_SIGNING_KEY_KEK")?,
            "AUTHKIT_SIGNING_KEY_KEK",
        )?;
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

        let session_pepper = decode_key(
            &required(&get, "AUTHKIT_SESSION_PEPPER")?,
            "AUTHKIT_SESSION_PEPPER",
        )?;
        let cookie_secure = match get("AUTHKIT_COOKIE_SECURE") {
            Some(value) => parse_bool("AUTHKIT_COOKIE_SECURE", &value)?,
            None => environment == Environment::Production,
        };
        if environment == Environment::Production && !cookie_secure {
            return Err(ConfigError::invalid(
                "AUTHKIT_COOKIE_SECURE",
                "must be true in production",
            ));
        }
        let account = SessionLifetime::new(
            session_secs(&get, "AUTHKIT_SESSION_IDLE_SECS", 1_800, 60..=86_400)?,
            session_secs(
                &get,
                "AUTHKIT_SESSION_ABSOLUTE_SECS",
                43_200,
                300..=2_592_000,
            )?,
        );
        let admin = SessionLifetime::new(
            session_secs(&get, "AUTHKIT_ADMIN_SESSION_IDLE_SECS", 900, 60..=86_400)?,
            session_secs(
                &get,
                "AUTHKIT_ADMIN_SESSION_ABSOLUTE_SECS",
                28_800,
                300..=2_592_000,
            )?,
        );
        if account.idle_secs >= account.absolute_secs {
            return Err(ConfigError::invalid(
                "AUTHKIT_SESSION_IDLE_SECS",
                "must be less than AUTHKIT_SESSION_ABSOLUTE_SECS",
            ));
        }
        if admin.idle_secs >= admin.absolute_secs {
            return Err(ConfigError::invalid(
                "AUTHKIT_ADMIN_SESSION_IDLE_SECS",
                "must be less than AUTHKIT_ADMIN_SESSION_ABSOLUTE_SECS",
            ));
        }
        if admin.idle_secs > account.idle_secs {
            return Err(ConfigError::invalid(
                "AUTHKIT_ADMIN_SESSION_IDLE_SECS",
                "must not exceed AUTHKIT_SESSION_IDLE_SECS",
            ));
        }
        if admin.absolute_secs > account.absolute_secs {
            return Err(ConfigError::invalid(
                "AUTHKIT_ADMIN_SESSION_ABSOLUTE_SECS",
                "must not exceed AUTHKIT_SESSION_ABSOLUTE_SECS",
            ));
        }

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
            session: SessionConfig::new(session_pepper, cookie_secure, account, admin),
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

    /// Returns the session, cookie, and CSRF configuration.
    pub fn session(&self) -> &SessionConfig {
        &self.session
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

fn decode_key(value: &str, variable: &'static str) -> Result<Vec<u8>, ConfigError> {
    let normalized = value
        .trim()
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    let key = URL_SAFE_NO_PAD
        .decode(normalized)
        .map_err(|_| ConfigError::invalid(variable, "must be base64url-encoded"))?;
    if key.len() != 32 {
        return Err(ConfigError::invalid(
            variable,
            "must decode to exactly 32 bytes",
        ));
    }
    Ok(key)
}

fn parse_bool(variable: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ConfigError::invalid(variable, "must be true or false")),
    }
}

fn session_secs(
    get: &impl Fn(&str) -> Option<String>,
    variable: &'static str,
    default: u64,
    range: std::ops::RangeInclusive<u64>,
) -> Result<u64, ConfigError> {
    match get(variable) {
        Some(value) => value
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|value| range.contains(value))
            .ok_or_else(|| {
                ConfigError::invalid(
                    variable,
                    format!(
                        "must be an integer between {} and {}",
                        range.start(),
                        range.end()
                    ),
                )
            }),
        None => Ok(default),
    }
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
            (
                "AUTHKIT_SESSION_PEPPER",
                "g431h2m7ij_HA19vccPPRkGAcw0RTkFCxrkBiXDeyaw",
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
            (
                "AUTHKIT_SESSION_PEPPER",
                "g431h2m7ij_HA19vccPPRkGAcw0RTkFCxrkBiXDeyaw",
            ),
        ])
        .expect("valid config");
        assert_eq!(config.environment(), Environment::Production);
        assert_eq!(config.bind_addr(), "127.0.0.1:3000".parse().unwrap());
        assert_eq!(config.database().max_connections(), 5);
        assert_eq!(config.signing_keys().retired_publish_secs(), 900);
        assert!(config.session().cookie_secure());
        assert_eq!(config.session().account().idle_secs(), 1_800);
        assert_eq!(config.session().account().absolute_secs(), 43_200);
        assert_eq!(config.session().admin().idle_secs(), 900);
        assert_eq!(config.session().admin().absolute_secs(), 28_800);
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

    #[test]
    fn session_pepper_is_required_and_must_be_32_bytes() {
        let mut vars = base_vars();
        vars.retain(|(name, _)| *name != "AUTHKIT_SESSION_PEPPER");
        let error = config(&vars).expect_err("missing session pepper");
        assert_eq!(error.variable(), "AUTHKIT_SESSION_PEPPER");

        let mut vars = base_vars();
        vars.retain(|(name, _)| *name != "AUTHKIT_SESSION_PEPPER");
        vars.push(("AUTHKIT_SESSION_PEPPER", "too-short"));
        let error = config(&vars).expect_err("short session pepper");
        assert_eq!(error.variable(), "AUTHKIT_SESSION_PEPPER");
    }

    #[test]
    fn session_pepper_is_redacted() {
        let config = config(&base_vars()).expect("valid config");
        let debug = format!("{config:?}");
        assert!(!debug.contains("g431h2m7ij_HA19vccPPRkGAcw0RTkFCxrkBiXDeyaw"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn production_rejects_insecure_cookies() {
        let mut vars = base_vars();
        vars.push(("AUTHKIT_COOKIE_SECURE", "false"));
        let error = config(&vars).expect_err("insecure production cookie");
        assert_eq!(error.variable(), "AUTHKIT_COOKIE_SECURE");
    }

    #[test]
    fn development_allows_secure_cookie_override() {
        let mut vars = base_vars();
        vars[0] = ("AUTHKIT_ENV", "development");
        vars[1] = ("AUTHKIT_ISSUER", "http://localhost:3000");
        vars.push(("AUTHKIT_COOKIE_SECURE", "true"));
        let config = config(&vars).expect("secure development cookie");
        assert!(config.session().cookie_secure());
    }

    #[test]
    fn session_lifetimes_are_bounded_and_admin_is_shorter() {
        let mut vars = base_vars();
        vars.push(("AUTHKIT_SESSION_IDLE_SECS", "0"));
        let error = config(&vars).expect_err("zero idle timeout");
        assert_eq!(error.variable(), "AUTHKIT_SESSION_IDLE_SECS");

        let mut vars = base_vars();
        vars.push(("AUTHKIT_SESSION_IDLE_SECS", "43200"));
        let error = config(&vars).expect_err("idle must be less than absolute");
        assert_eq!(error.variable(), "AUTHKIT_SESSION_IDLE_SECS");

        let mut vars = base_vars();
        vars.push(("AUTHKIT_ADMIN_SESSION_IDLE_SECS", "3600"));
        let error = config(&vars).expect_err("admin idle cannot exceed account idle");
        assert_eq!(error.variable(), "AUTHKIT_ADMIN_SESSION_IDLE_SECS");

        let mut vars = base_vars();
        vars.push(("AUTHKIT_ADMIN_SESSION_ABSOLUTE_SECS", "50000"));
        let error = config(&vars).expect_err("admin absolute cannot exceed account absolute");
        assert_eq!(error.variable(), "AUTHKIT_ADMIN_SESSION_ABSOLUTE_SECS");
    }

    #[test]
    fn cookie_secure_must_be_boolean() {
        let mut vars = base_vars();
        vars.push(("AUTHKIT_COOKIE_SECURE", "yes"));
        let error = config(&vars).expect_err("invalid boolean");
        assert_eq!(error.variable(), "AUTHKIT_COOKIE_SECURE");
    }
}
