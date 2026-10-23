//! ES256 signing-key ring with encrypted-at-rest private material.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::SigningKeyConfig;

const KEYRING_VERSION: u32 = 1;
const ES256: &str = "ES256";
const P256: &str = "P-256";

/// The publication and signing state of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// Published for verification but not yet used for signing.
    Next,
    /// The only key used for signing.
    Active,
    /// Published for verification until its publication deadline.
    Retired,
    /// Not published and never used for signing.
    Compromised,
}

/// A public ES256 JWK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJwk {
    /// Key type.
    pub kty: String,
    /// Curve.
    pub crv: String,
    /// Base64url-encoded x coordinate.
    pub x: String,
    /// Base64url-encoded y coordinate.
    pub y: String,
    /// Key identifier.
    pub kid: String,
    /// Public key use.
    #[serde(rename = "use")]
    pub key_use: String,
    /// Signing algorithm.
    pub alg: String,
}

impl PublicJwk {
    fn validate(&self) -> Result<(), KeyRingError> {
        if self.kty != "EC" || self.crv != P256 || self.key_use != "sig" || self.alg != ES256 {
            return Err(KeyRingError::Invalid(
                "signing keys must be ES256 public signing keys",
            ));
        }
        if self.kid.is_empty() || self.kid.len() > 128 {
            return Err(KeyRingError::Invalid("signing key id is invalid"));
        }
        for coordinate in [&self.x, &self.y] {
            let decoded = URL_SAFE_NO_PAD
                .decode(coordinate)
                .map_err(|_| KeyRingError::Invalid("signing key coordinates are invalid"))?;
            if decoded.len() != 32 {
                return Err(KeyRingError::Invalid("signing key coordinates are invalid"));
            }
        }
        Ok(())
    }
}

/// A signing key and its lifecycle metadata.
pub struct SigningKey {
    kid: String,
    state: KeyState,
    public_jwk: PublicJwk,
    secret: Option<SecretKey>,
    created_at: u64,
    activated_at: Option<u64>,
    retired_at: Option<u64>,
    publish_until: Option<u64>,
}

impl SigningKey {
    /// Generates a new ES256 key in the requested state.
    pub fn generate(state: KeyState, now: u64) -> Result<Self, KeyRingError> {
        let secret = SecretKey::random(&mut OsRng);
        let kid = generate_kid();
        let public_jwk = public_jwk(&secret, &kid)?;
        Ok(Self {
            kid,
            state,
            public_jwk,
            secret: Some(secret),
            created_at: now,
            activated_at: (state == KeyState::Active).then_some(now),
            retired_at: None,
            publish_until: None,
        })
    }

    /// Sets the publication deadline for a retired key.
    pub fn with_publish_until(mut self, publish_until: Option<u64>) -> Self {
        self.publish_until = publish_until;
        self
    }

    /// Returns the key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the lifecycle state.
    pub const fn state(&self) -> KeyState {
        self.state
    }

    /// Returns the public JWK.
    pub fn public_jwk(&self) -> &PublicJwk {
        &self.public_jwk
    }

    /// Returns the publication deadline for a retired key.
    pub const fn publish_until(&self) -> Option<u64> {
        self.publish_until
    }

    fn validate(&self) -> Result<(), KeyRingError> {
        self.public_jwk.validate()?;
        if self.public_jwk.kid != self.kid {
            return Err(KeyRingError::Invalid(
                "signing key id does not match its public JWK",
            ));
        }
        match self.state {
            KeyState::Active | KeyState::Next => {
                let secret = self.secret.as_ref().ok_or(KeyRingError::Invalid(
                    "active and next signing keys require private material",
                ))?;
                let expected = public_jwk(secret, &self.kid)?;
                if expected != self.public_jwk {
                    return Err(KeyRingError::Invalid(
                        "signing key public material does not match its private key",
                    ));
                }
            }
            KeyState::Retired => {
                if self.publish_until.is_none() {
                    return Err(KeyRingError::Invalid(
                        "retired signing keys require a publication deadline",
                    ));
                }
            }
            KeyState::Compromised => {}
        }
        Ok(())
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKey")
            .field("kid", &self.kid)
            .field("state", &self.state)
            .field("has_private_key", &self.secret.is_some())
            .field("publish_until", &self.publish_until)
            .finish()
    }
}

/// A validated set of signing keys with exactly one active key.
#[derive(Debug)]
pub struct KeyRing {
    keys: Vec<SigningKey>,
    active_index: usize,
}

impl KeyRing {
    /// Builds a key ring and validates its lifecycle invariants.
    pub fn new(mut keys: Vec<SigningKey>) -> Result<Self, KeyRingError> {
        if keys.is_empty() {
            return Err(KeyRingError::Invalid("the signing keyring is empty"));
        }

        let mut kids = HashSet::new();
        let mut active_index = None;
        for (index, key) in keys.iter_mut().enumerate() {
            if matches!(key.state(), KeyState::Retired | KeyState::Compromised) {
                key.secret = None;
            }
            key.validate()?;
            if !kids.insert(key.kid.clone()) {
                return Err(KeyRingError::Invalid("signing key ids must be unique"));
            }
            if key.state() == KeyState::Active && active_index.replace(index).is_some() {
                return Err(KeyRingError::Invalid(
                    "the signing keyring must contain exactly one active key",
                ));
            }
        }

        let active_index = active_index.ok_or(KeyRingError::Invalid(
            "the signing keyring has no active key",
        ))?;
        Ok(Self { keys, active_index })
    }

    /// Loads the encrypted keyring or creates and persists a bootstrap key.
    pub fn load_or_bootstrap(config: &SigningKeyConfig, now: u64) -> Result<Self, KeyRingError> {
        if !config.file().exists() {
            let key = SigningKey::generate(KeyState::Active, now)?;
            let file = KeyRingFile {
                version: KEYRING_VERSION,
                keys: vec![KeyEntry::from_signing_key(&key, config.kek())?],
            };
            write_keyring(config.file(), &file)?;
        }

        let file = read_keyring(config.file())?;
        if file.version != KEYRING_VERSION {
            return Err(KeyRingError::Invalid(
                "unsupported signing keyring file version",
            ));
        }
        let keys = file
            .keys
            .into_iter()
            .map(|entry| entry.into_signing_key(config.kek(), now, config.retired_publish_secs()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(keys)
    }

    /// Returns the only key used for signing.
    pub fn active(&self) -> &SigningKey {
        &self.keys[self.active_index]
    }

    /// Returns the public keys that may be published at the given time.
    pub fn published_keys(&self, now: u64) -> Vec<&PublicJwk> {
        self.keys
            .iter()
            .filter(|key| match key.state() {
                KeyState::Active | KeyState::Next => true,
                KeyState::Retired => key.publish_until().is_some_and(|until| until > now),
                KeyState::Compromised => false,
            })
            .map(SigningKey::public_jwk)
            .collect()
    }
}

/// Returns the current Unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// A signing-keyring failure with redacted error messages.
#[derive(Debug)]
pub enum KeyRingError {
    /// The keyring file could not be read or written.
    Io(std::io::Error),
    /// The keyring is structurally invalid.
    Invalid(&'static str),
    /// Private-key encryption or decryption failed.
    Crypto,
}

impl fmt::Display for KeyRingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "signing keyring I/O failed: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid signing keyring: {message}"),
            Self::Crypto => formatter.write_str("signing key encryption failed"),
        }
    }
}

impl std::error::Error for KeyRingError {}

impl From<std::io::Error> for KeyRingError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for KeyRingError {
    fn from(_: serde_json::Error) -> Self {
        Self::Invalid("the keyring file is not valid JSON")
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingFile {
    version: u32,
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    kid: String,
    alg: String,
    state: KeyState,
    public_jwk: PublicJwk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_private_key: Option<String>,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publish_until: Option<u64>,
}

impl KeyEntry {
    fn from_signing_key(key: &SigningKey, kek: &[u8]) -> Result<Self, KeyRingError> {
        let encrypted_private_key = key
            .secret
            .as_ref()
            .map(|secret| encrypt_private(secret, &key.kid, kek))
            .transpose()?;
        Ok(Self {
            kid: key.kid.clone(),
            alg: ES256.to_owned(),
            state: key.state,
            public_jwk: key.public_jwk.clone(),
            encrypted_private_key,
            created_at: key.created_at,
            activated_at: key.activated_at,
            retired_at: key.retired_at,
            publish_until: key.publish_until,
        })
    }

    fn into_signing_key(
        mut self,
        kek: &[u8],
        now: u64,
        retired_publish_secs: u64,
    ) -> Result<SigningKey, KeyRingError> {
        if self.state == KeyState::Retired && self.publish_until.is_none() {
            self.publish_until = Some(now.saturating_add(retired_publish_secs));
        }
        if self.alg != ES256 {
            return Err(KeyRingError::Invalid("signing keys must use ES256"));
        }
        let decrypted = self
            .encrypted_private_key
            .as_deref()
            .map(|encoded| decrypt_private(encoded, &self.kid, kek))
            .transpose()?;
        let secret = matches!(self.state, KeyState::Active | KeyState::Next)
            .then_some(decrypted)
            .flatten();
        let key = SigningKey {
            kid: self.kid,
            state: self.state,
            public_jwk: self.public_jwk,
            secret,
            created_at: self.created_at,
            activated_at: self.activated_at,
            retired_at: self.retired_at,
            publish_until: self.publish_until,
        };
        key.validate()?;
        Ok(key)
    }
}

fn public_jwk(secret: &SecretKey, kid: &str) -> Result<PublicJwk, KeyRingError> {
    let public = secret.public_key();
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or(KeyRingError::Invalid("signing key has no x coordinate"))?;
    let y = point
        .y()
        .ok_or(KeyRingError::Invalid("signing key has no y coordinate"))?;
    let jwk = PublicJwk {
        kty: "EC".to_owned(),
        crv: P256.to_owned(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
        kid: kid.to_owned(),
        key_use: "sig".to_owned(),
        alg: ES256.to_owned(),
    };
    jwk.validate()?;
    Ok(jwk)
}

fn generate_kid() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn encrypt_private(secret: &SecretKey, kid: &str, kek: &[u8]) -> Result<String, KeyRingError> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| KeyRingError::Crypto)?;
    let der = secret.to_pkcs8_der().map_err(|_| KeyRingError::Crypto)?;
    let der = Zeroizing::new(der.as_bytes().to_vec());
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: der.as_slice(),
                aad: kid.as_bytes(),
            },
        )
        .map_err(|_| KeyRingError::Crypto)?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(blob))
}

fn decrypt_private(encoded: &str, kid: &str, kek: &[u8]) -> Result<SecretKey, KeyRingError> {
    let blob = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| KeyRingError::Crypto)?;
    if blob.len() <= 12 {
        return Err(KeyRingError::Crypto);
    }
    let (nonce, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| KeyRingError::Crypto)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: kid.as_bytes(),
            },
        )
        .map_err(|_| KeyRingError::Crypto)?;
    let plaintext = Zeroizing::new(plaintext);
    SecretKey::from_pkcs8_der(plaintext.as_slice()).map_err(|_| KeyRingError::Crypto)
}

fn read_keyring(path: &Path) -> Result<KeyRingFile, KeyRingError> {
    ensure_private_permissions(path)?;
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_keyring(path: &Path, keyring: &KeyRingFile) -> Result<(), KeyRingError> {
    let bytes = serde_json::to_vec_pretty(keyring)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("authkit-signing-keys"),
        generate_kid()
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<(), KeyRingError> {
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    let linked = match fs::hard_link(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    };
    let _ = fs::remove_file(&temporary);
    linked
}

fn ensure_private_permissions(path: &Path) -> Result<(), KeyRingError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(KeyRingError::Invalid(
                "the signing keyring file must not be accessible by group or others",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "authkit-keyring-{}-{nanos}.json",
            std::process::id()
        ))
    }

    fn config(path: PathBuf, kek: Vec<u8>) -> SigningKeyConfig {
        SigningKeyConfig::new(path, kek, 900)
    }

    #[test]
    fn bootstrap_writes_encrypted_material_and_reloads() {
        let path = temporary_path();
        let kek = vec![7_u8; 32];
        let config = config(path.clone(), kek.clone());
        let first = KeyRing::load_or_bootstrap(&config, 1_000).expect("bootstrap keyring");
        assert!(path.exists());

        let json = fs::read_to_string(&path).expect("read keyring");
        assert!(!json.contains("\"d\""));
        assert!(json.contains("encrypted_private_key"));

        let second = KeyRing::load_or_bootstrap(&config, 2_000).expect("reload keyring");
        assert_eq!(first.active().kid(), second.active().kid());
        assert_eq!(second.active().state(), KeyState::Active);

        fs::remove_file(path).expect("remove keyring");
    }

    #[test]
    fn wrong_kek_cannot_decrypt_the_keyring() {
        let path = temporary_path();
        let correct = config(path.clone(), vec![1_u8; 32]);
        KeyRing::load_or_bootstrap(&correct, 1_000).expect("bootstrap keyring");

        let wrong = config(path.clone(), vec![2_u8; 32]);
        assert!(matches!(
            KeyRing::load_or_bootstrap(&wrong, 2_000),
            Err(KeyRingError::Crypto)
        ));

        fs::remove_file(path).expect("remove keyring");
    }

    #[test]
    fn lifecycle_states_control_publication() {
        let now = 1_000;
        let active = SigningKey::generate(KeyState::Active, now).expect("active key");
        let next = SigningKey::generate(KeyState::Next, now).expect("next key");
        let retired = SigningKey::generate(KeyState::Retired, now)
            .expect("retired key")
            .with_publish_until(Some(now + 900));
        let expired = SigningKey::generate(KeyState::Retired, now)
            .expect("expired key")
            .with_publish_until(Some(now - 1));
        let compromised =
            SigningKey::generate(KeyState::Compromised, now).expect("compromised key");

        let expired_kid = expired.public_jwk().kid.clone();
        let compromised_kid = compromised.public_jwk().kid.clone();
        let ring =
            KeyRing::new(vec![active, next, retired, expired, compromised]).expect("valid keyring");
        let published = ring.published_keys(now);
        assert_eq!(published.len(), 3);
        assert!(!published.iter().any(|key| key.kid == expired_kid));
        assert!(!published.iter().any(|key| key.kid == compromised_kid));
        assert_eq!(ring.active().state(), KeyState::Active);
    }

    #[test]
    fn keyring_requires_exactly_one_active_key() {
        let now = 1_000;
        let first = SigningKey::generate(KeyState::Active, now).expect("active key");
        let second = SigningKey::generate(KeyState::Active, now).expect("active key");
        assert!(matches!(
            KeyRing::new(vec![first, second]),
            Err(KeyRingError::Invalid(_))
        ));

        let next = SigningKey::generate(KeyState::Next, now).expect("next key");
        assert!(matches!(
            KeyRing::new(vec![next]),
            Err(KeyRingError::Invalid(_))
        ));
    }

    #[test]
    fn retired_keys_require_a_publication_deadline() {
        let now = 1_000;
        let active = SigningKey::generate(KeyState::Active, now).expect("active key");
        let retired = SigningKey::generate(KeyState::Retired, now).expect("retired key");
        assert!(matches!(
            KeyRing::new(vec![active, retired]),
            Err(KeyRingError::Invalid(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn keyring_file_must_not_be_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let path = temporary_path();
        let config = config(path.clone(), vec![7_u8; 32]);
        KeyRing::load_or_bootstrap(&config, 1_000).expect("bootstrap keyring");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            KeyRing::load_or_bootstrap(&config, 2_000),
            Err(KeyRingError::Invalid(_))
        ));
        fs::remove_file(path).expect("remove keyring");
    }
}
