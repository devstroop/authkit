use core::fmt;

use crate::domain::DomainError;
use crate::domain::id::{CredentialEntity, Id, UserEntity};
use crate::domain::time::Timestamp;
use crate::domain::value::ValueError;

const MAX_PHC_LEN: usize = 512;
const MIN_ARGON2ID_MEMORY_KIB: u32 = 19 * 1024;
const MAX_ARGON2ID_MEMORY_KIB: u32 = 1024 * 1024;
const MIN_ARGON2ID_TIME_COST: u32 = 2;
const MAX_ARGON2ID_TIME_COST: u32 = 16;
const MIN_ARGON2ID_PARALLELISM: u32 = 1;
const MAX_ARGON2ID_PARALLELISM: u32 = 16;
const MIN_PASSWORD_SALT_BYTES: usize = 16;
const MAX_PASSWORD_SALT_BYTES: usize = 64;
const PASSWORD_HASH_BYTES: usize = 32;
const MIN_ENCRYPTED_NONCE_BYTES: usize = 12;
const MAX_ENCRYPTED_NONCE_BYTES: usize = 24;
const MIN_CIPHERTEXT_BYTES: usize = 16;
const MAX_CIPHERTEXT_BYTES: usize = 4096;
const MAX_KEY_ID_LEN: usize = 64;
const MAX_PASSKEY_CREDENTIAL_ID_BYTES: usize = 1023;
const MAX_PASSKEY_PUBLIC_KEY_BYTES: usize = 4096;
const MAX_PASSKEY_TRANSPORTS: usize = 7;
const AAGUID_BYTES: usize = 16;

/// The type of an authentication credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// An Argon2id password verifier.
    Password,
    /// A WebAuthn/passkey credential.
    Passkey,
    /// A TOTP shared-secret credential.
    Totp,
}

/// The lifecycle state of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The credential may be used to authenticate.
    Active,
    /// The credential is temporarily disabled.
    Disabled,
    /// The credential is permanently revoked.
    Revoked,
}

/// The Argon2id work factors recorded in a password verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParameters {
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Argon2idParameters {
    /// Validates and creates a parameter set.
    ///
    /// The minimums follow current Argon2id guidance: at least 19 MiB of memory, two
    /// passes, and one lane. Values outside the supported range are rejected rather than
    /// silently accepted.
    pub fn new(memory_kib: u32, time_cost: u32, parallelism: u32) -> Result<Self, ValueError> {
        let parameters = Self {
            memory_kib,
            time_cost,
            parallelism,
        };
        parameters.validate()?;
        Ok(parameters)
    }

    /// Returns the memory cost in kibibytes.
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Returns the number of passes.
    pub const fn time_cost(&self) -> u32 {
        self.time_cost
    }

    /// Returns the degree of parallelism.
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    fn validate(&self) -> Result<(), ValueError> {
        if !(MIN_ARGON2ID_MEMORY_KIB..=MAX_ARGON2ID_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(ValueError::InvalidFormat {
                field: "password verifier memory cost",
                reason: "is outside the supported Argon2id range",
            });
        }
        if !(MIN_ARGON2ID_TIME_COST..=MAX_ARGON2ID_TIME_COST).contains(&self.time_cost) {
            return Err(ValueError::InvalidFormat {
                field: "password verifier time cost",
                reason: "is outside the supported Argon2id range",
            });
        }
        if !(MIN_ARGON2ID_PARALLELISM..=MAX_ARGON2ID_PARALLELISM).contains(&self.parallelism) {
            return Err(ValueError::InvalidFormat {
                field: "password verifier parallelism",
                reason: "is outside the supported Argon2id range",
            });
        }
        Ok(())
    }
}

/// A validated Argon2id PHC verifier for a password credential.
///
/// Plaintext passwords never enter the domain. Adapters hash and verify them; this value
/// object accepts only a well-formed Argon2id PHC string whose work factors meet the
/// supported minimums. A generic hash or an unsupported algorithm cannot be represented.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordVerifier {
    encoded: String,
    parameters: Argon2idParameters,
}

impl PasswordVerifier {
    /// Parses and validates an Argon2id PHC verifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValueError> {
        let encoded = value.into();

        if encoded.is_empty() {
            return Err(ValueError::Empty {
                field: "password verifier",
            });
        }
        if encoded.len() > MAX_PHC_LEN {
            return Err(ValueError::TooLong {
                field: "password verifier",
                max: MAX_PHC_LEN,
                actual: encoded.len(),
            });
        }

        let mut parts = encoded.split('$');
        if parts.next() != Some("") {
            return Err(invalid_verifier("must use the PHC string format"));
        }
        let algorithm = parts
            .next()
            .ok_or_else(|| invalid_verifier("is missing the algorithm"))?;
        if algorithm != "argon2id" {
            return Err(invalid_verifier("must use the Argon2id algorithm"));
        }
        let version = parts
            .next()
            .ok_or_else(|| invalid_verifier("is missing the version"))?;
        if version != "v=19" {
            return Err(invalid_verifier("uses an unsupported Argon2 version"));
        }
        let parameter_text = parts
            .next()
            .ok_or_else(|| invalid_verifier("is missing Argon2id parameters"))?;
        let salt_text = parts
            .next()
            .ok_or_else(|| invalid_verifier("is missing the salt"))?;
        let hash_text = parts
            .next()
            .ok_or_else(|| invalid_verifier("is missing the hash"))?;
        if parts.next().is_some() {
            return Err(invalid_verifier("has unexpected trailing fields"));
        }

        let parameters = parse_parameters(parameter_text)?;

        let salt =
            decode_base64(salt_text).ok_or_else(|| invalid_verifier("salt is not valid base64"))?;
        if !(MIN_PASSWORD_SALT_BYTES..=MAX_PASSWORD_SALT_BYTES).contains(&salt.len()) {
            return Err(ValueError::InvalidFormat {
                field: "password verifier salt",
                reason: "must decode to 16 to 64 bytes",
            });
        }

        let hash =
            decode_base64(hash_text).ok_or_else(|| invalid_verifier("hash is not valid base64"))?;
        if hash.len() != PASSWORD_HASH_BYTES {
            return Err(ValueError::InvalidFormat {
                field: "password verifier hash",
                reason: "must decode to exactly 32 bytes",
            });
        }

        Ok(Self {
            encoded,
            parameters,
        })
    }

    /// Returns the encoded PHC verifier. Callers must not log this value.
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    /// Returns the validated Argon2id work factors.
    pub const fn parameters(&self) -> Argon2idParameters {
        self.parameters
    }

    /// Returns `true` when the verifier uses weaker parameters than `policy`.
    pub fn needs_rehash(&self, policy: Argon2idParameters) -> bool {
        self.parameters.memory_kib() < policy.memory_kib()
            || self.parameters.time_cost() < policy.time_cost()
            || self.parameters.parallelism() < policy.parallelism()
    }
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordVerifier")
            .field("parameters", &self.parameters)
            .field("encoded", &"[redacted]")
            .finish()
    }
}

/// A TOTP hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the interoperable default.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// TOTP code-generation parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpConfig {
    algorithm: TotpAlgorithm,
    digits: u8,
    period_seconds: u64,
}

impl TotpConfig {
    /// Validates TOTP parameters.
    pub fn new(
        algorithm: TotpAlgorithm,
        digits: u8,
        period_seconds: u64,
    ) -> Result<Self, ValueError> {
        if !matches!(digits, 6 | 8) {
            return Err(ValueError::InvalidFormat {
                field: "TOTP digits",
                reason: "must be 6 or 8",
            });
        }
        if !(1..=300).contains(&period_seconds) {
            return Err(ValueError::InvalidFormat {
                field: "TOTP period",
                reason: "must be between 1 and 300 seconds",
            });
        }
        Ok(Self {
            algorithm,
            digits,
            period_seconds,
        })
    }

    /// Returns the hash algorithm.
    pub const fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// Returns the number of code digits.
    pub const fn digits(&self) -> u8 {
        self.digits
    }

    /// Returns the time-step period in seconds.
    pub const fn period_seconds(&self) -> u64 {
        self.period_seconds
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        }
    }
}

/// A TOTP shared secret encrypted by an authenticated encryption adapter.
///
/// The domain never stores a plaintext TOTP secret. An adapter encrypts the secret with a
/// key-encryption key managed outside the database and records the key identifier and
/// nonce so the secret can be decrypted and re-encrypted during key rotation.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecret {
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedSecret {
    /// Validates an encrypted secret envelope.
    pub fn new(
        key_id: impl Into<String>,
        nonce: impl Into<Vec<u8>>,
        ciphertext: impl Into<Vec<u8>>,
    ) -> Result<Self, ValueError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(ValueError::Empty {
                field: "encryption key id",
            });
        }
        if key_id.len() > MAX_KEY_ID_LEN {
            return Err(ValueError::TooLong {
                field: "encryption key id",
                max: MAX_KEY_ID_LEN,
                actual: key_id.len(),
            });
        }
        if !key_id.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(ValueError::InvalidFormat {
                field: "encryption key id",
                reason: "must contain printable ASCII characters only",
            });
        }

        let nonce = nonce.into();
        if !(MIN_ENCRYPTED_NONCE_BYTES..=MAX_ENCRYPTED_NONCE_BYTES).contains(&nonce.len()) {
            return Err(ValueError::InvalidFormat {
                field: "encryption nonce",
                reason: "must be 12 to 24 bytes",
            });
        }

        let ciphertext = ciphertext.into();
        if !(MIN_CIPHERTEXT_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&ciphertext.len()) {
            return Err(ValueError::InvalidFormat {
                field: "encrypted secret",
                reason: "must be 16 to 4096 bytes",
            });
        }

        Ok(Self {
            key_id,
            nonce,
            ciphertext,
        })
    }

    /// Returns the identifier of the key-encryption key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the AEAD nonce. Callers must not log this value.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the encrypted secret. Callers must not log this value.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedSecret")
            .field("key_id", &self.key_id)
            .field("nonce", &"[redacted]")
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

/// A TOTP credential and its replay protection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCredential {
    secret: EncryptedSecret,
    config: TotpConfig,
    last_accepted_step: Option<u64>,
}

impl TotpCredential {
    /// Creates a TOTP credential that has not accepted a time step.
    pub fn new(secret: EncryptedSecret, config: TotpConfig) -> Self {
        Self {
            secret,
            config,
            last_accepted_step: None,
        }
    }

    /// Reconstructs a TOTP credential from persisted secret and replay state.
    ///
    /// Storage adapters use this; normal callers create TOTP credentials through
    /// [`TotpCredential::new`] and accept time steps.
    pub fn restore(
        secret: EncryptedSecret,
        config: TotpConfig,
        last_accepted_step: Option<u64>,
    ) -> Self {
        Self {
            secret,
            config,
            last_accepted_step,
        }
    }

    /// Returns the encrypted shared secret.
    pub const fn secret(&self) -> &EncryptedSecret {
        &self.secret
    }

    /// Returns the TOTP parameters.
    pub const fn config(&self) -> TotpConfig {
        self.config
    }

    /// Returns the last accepted time step, if any.
    pub const fn last_accepted_step(&self) -> Option<u64> {
        self.last_accepted_step
    }

    /// Accepts a TOTP time step exactly once.
    ///
    /// The adapter computes the time step after verifying the code. This guard prevents a
    /// successfully used code from being replayed inside or across the same step.
    pub fn accept_step(&mut self, step: u64) -> Result<(), DomainError> {
        if let Some(last) = self.last_accepted_step
            && step <= last
        {
            return Err(DomainError::conflict(
                "TOTP time step has already been used",
            ));
        }
        self.last_accepted_step = Some(step);
        Ok(())
    }

    /// Replaces the encrypted secret and clears replay state.
    pub fn rotate_secret(&mut self, secret: EncryptedSecret) {
        self.secret = secret;
        self.last_accepted_step = None;
    }
}

/// A WebAuthn authenticator transport hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatorTransport {
    /// USB.
    Usb,
    /// NFC.
    Nfc,
    /// Bluetooth Low Energy.
    Ble,
    /// Smart card.
    SmartCard,
    /// Hybrid/cross-platform authenticator.
    Hybrid,
    /// Platform authenticator.
    Internal,
}

impl AuthenticatorTransport {
    /// Returns the canonical WebAuthn transport name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Nfc => "nfc",
            Self::Ble => "ble",
            Self::SmartCard => "smart-card",
            Self::Hybrid => "hybrid",
            Self::Internal => "internal",
        }
    }

    /// Parses a canonical WebAuthn transport name.
    pub fn parse(value: &str) -> Result<Self, ValueError> {
        match value {
            "usb" => Ok(Self::Usb),
            "nfc" => Ok(Self::Nfc),
            "ble" => Ok(Self::Ble),
            "smart-card" => Ok(Self::SmartCard),
            "hybrid" => Ok(Self::Hybrid),
            "internal" => Ok(Self::Internal),
            _ => Err(ValueError::InvalidFormat {
                field: "authenticator transport",
                reason: "is not a supported WebAuthn transport",
            }),
        }
    }
}

/// The registration data a passkey needs to authenticate later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegistration {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    aaguid: [u8; AAGUID_BYTES],
    transports: Vec<AuthenticatorTransport>,
    discoverable: bool,
    backup_eligible: bool,
    backup_state: bool,
}

impl PasskeyRegistration {
    /// Validates WebAuthn registration data.
    ///
    /// `credential_id` is the raw WebAuthn credential identifier, `public_key` is the
    /// serialized COSE public key, and `aaguid` identifies the authenticator model.
    pub fn new(
        credential_id: impl Into<Vec<u8>>,
        public_key: impl Into<Vec<u8>>,
        aaguid: [u8; AAGUID_BYTES],
        transports: Vec<AuthenticatorTransport>,
        discoverable: bool,
        backup_eligible: bool,
        backup_state: bool,
    ) -> Result<Self, ValueError> {
        let credential_id = credential_id.into();
        if credential_id.is_empty() {
            return Err(ValueError::Empty {
                field: "passkey credential id",
            });
        }
        if credential_id.len() > MAX_PASSKEY_CREDENTIAL_ID_BYTES {
            return Err(ValueError::TooLong {
                field: "passkey credential id",
                max: MAX_PASSKEY_CREDENTIAL_ID_BYTES,
                actual: credential_id.len(),
            });
        }

        let public_key = public_key.into();
        if public_key.is_empty() {
            return Err(ValueError::Empty {
                field: "passkey public key",
            });
        }
        if public_key.len() > MAX_PASSKEY_PUBLIC_KEY_BYTES {
            return Err(ValueError::TooLong {
                field: "passkey public key",
                max: MAX_PASSKEY_PUBLIC_KEY_BYTES,
                actual: public_key.len(),
            });
        }
        if public_key[0] & 0xe0 != 0xa0 {
            return Err(ValueError::InvalidFormat {
                field: "passkey public key",
                reason: "must be a CBOR-encoded COSE key map",
            });
        }

        if transports.len() > MAX_PASSKEY_TRANSPORTS {
            return Err(ValueError::TooLong {
                field: "passkey transports",
                max: MAX_PASSKEY_TRANSPORTS,
                actual: transports.len(),
            });
        }
        for (index, transport) in transports.iter().enumerate() {
            if transports[..index].contains(transport) {
                return Err(ValueError::InvalidFormat {
                    field: "passkey transports",
                    reason: "must not contain duplicates",
                });
            }
        }

        if backup_state && !backup_eligible {
            return Err(ValueError::InvalidFormat {
                field: "passkey backup state",
                reason: "cannot be set when the credential is not backup eligible",
            });
        }

        Ok(Self {
            credential_id,
            public_key,
            aaguid,
            transports,
            discoverable,
            backup_eligible,
            backup_state,
        })
    }

    /// Returns the raw WebAuthn credential identifier.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Returns the serialized COSE public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the authenticator AAGUID.
    pub const fn aaguid(&self) -> &[u8; AAGUID_BYTES] {
        &self.aaguid
    }

    /// Returns the transport hints.
    pub fn transports(&self) -> &[AuthenticatorTransport] {
        &self.transports
    }

    /// Returns whether the credential is discoverable.
    pub const fn discoverable(&self) -> bool {
        self.discoverable
    }

    /// Returns whether the credential is eligible for backup.
    pub const fn backup_eligible(&self) -> bool {
        self.backup_eligible
    }

    /// Returns whether the credential is currently backed up.
    pub const fn backup_state(&self) -> bool {
        self.backup_state
    }
}

/// A passkey credential and its authenticator signature counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCredential {
    registration: PasskeyRegistration,
    sign_count: u32,
}

impl PasskeyCredential {
    /// Creates a passkey credential from validated registration data.
    pub fn new(registration: PasskeyRegistration) -> Self {
        Self {
            registration,
            sign_count: 0,
        }
    }

    /// Reconstructs a passkey credential from persisted registration and counter state.
    ///
    /// Storage adapters use this; normal callers create passkeys through
    /// [`PasskeyCredential::new`] and record authentications.
    pub fn restore(registration: PasskeyRegistration, sign_count: u32) -> Self {
        Self {
            registration,
            sign_count,
        }
    }

    /// Returns the registration data.
    pub const fn registration(&self) -> &PasskeyRegistration {
        &self.registration
    }

    /// Returns the last observed authenticator signature counter.
    pub const fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Records an authentication assertion and checks the signature counter.
    ///
    /// A non-zero counter that does not increase is treated as a possible cloned
    /// authenticator. A zero counter means the authenticator does not implement clone
    /// detection and is accepted without weakening the stored value.
    pub fn record_authentication(&mut self, sign_count: u32) -> Result<(), DomainError> {
        if sign_count == 0 {
            return Ok(());
        }
        if self.sign_count != 0 && sign_count <= self.sign_count {
            return Err(DomainError::conflict(
                "passkey signature counter did not increase",
            ));
        }
        self.sign_count = sign_count;
        Ok(())
    }
}

/// Type-specific credential data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialData {
    /// An Argon2id password verifier.
    Password(PasswordVerifier),
    /// A WebAuthn/passkey credential.
    Passkey(PasskeyCredential),
    /// A TOTP credential.
    Totp(TotpCredential),
}

impl CredentialData {
    /// Returns the credential kind.
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::Password(_) => CredentialKind::Password,
            Self::Passkey(_) => CredentialKind::Passkey,
            Self::Totp(_) => CredentialKind::Totp,
        }
    }
}

/// A credential belonging to a user.
///
/// Constructors are type-specific. There is no generic "hash + kind" constructor, so an
/// adapter cannot persist an arbitrary hash as a password, passkey, or TOTP credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    id: Id<CredentialEntity>,
    user_id: Id<UserEntity>,
    data: CredentialData,
    status: CredentialStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    last_used_at: Option<Timestamp>,
    version: u64,
}

impl Credential {
    /// Creates a password credential.
    pub fn password(
        id: Id<CredentialEntity>,
        user_id: Id<UserEntity>,
        verifier: PasswordVerifier,
        now: Timestamp,
    ) -> Self {
        Self::new(id, user_id, CredentialData::Password(verifier), now)
    }

    /// Creates a passkey credential.
    pub fn passkey(
        id: Id<CredentialEntity>,
        user_id: Id<UserEntity>,
        registration: PasskeyRegistration,
        now: Timestamp,
    ) -> Self {
        Self::new(
            id,
            user_id,
            CredentialData::Passkey(PasskeyCredential::new(registration)),
            now,
        )
    }

    /// Creates a TOTP credential.
    pub fn totp(
        id: Id<CredentialEntity>,
        user_id: Id<UserEntity>,
        secret: EncryptedSecret,
        config: TotpConfig,
        now: Timestamp,
    ) -> Self {
        Self::new(
            id,
            user_id,
            CredentialData::Totp(TotpCredential::new(secret, config)),
            now,
        )
    }

    fn new(
        id: Id<CredentialEntity>,
        user_id: Id<UserEntity>,
        data: CredentialData,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            user_id,
            data,
            status: CredentialStatus::Active,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            version: 0,
        }
    }

    /// Reconstructs a credential from persisted state.
    ///
    /// Storage adapters use this; normal callers use the type-specific constructors.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<CredentialEntity>,
        user_id: Id<UserEntity>,
        data: CredentialData,
        status: CredentialStatus,
        created_at: Timestamp,
        updated_at: Timestamp,
        last_used_at: Option<Timestamp>,
        version: u64,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::invalid(
                "credential updated_at must not precede created_at",
            ));
        }
        if let Some(last_used_at) = last_used_at
            && last_used_at < created_at
        {
            return Err(DomainError::invalid(
                "credential last_used_at must not precede creation",
            ));
        }

        Ok(Self {
            id,
            user_id,
            data,
            status,
            created_at,
            updated_at,
            last_used_at,
            version,
        })
    }

    /// Returns the credential identifier.
    pub const fn id(&self) -> &Id<CredentialEntity> {
        &self.id
    }

    /// Returns the owning user.
    pub const fn user_id(&self) -> &Id<UserEntity> {
        &self.user_id
    }

    /// Returns the credential kind.
    pub const fn kind(&self) -> CredentialKind {
        self.data.kind()
    }

    /// Returns the type-specific data.
    pub const fn data(&self) -> &CredentialData {
        &self.data
    }

    /// Returns the password verifier when this is a password credential.
    pub const fn as_password(&self) -> Option<&PasswordVerifier> {
        match &self.data {
            CredentialData::Password(verifier) => Some(verifier),
            CredentialData::Passkey(_) | CredentialData::Totp(_) => None,
        }
    }

    /// Returns the passkey data when this is a passkey credential.
    pub const fn as_passkey(&self) -> Option<&PasskeyCredential> {
        match &self.data {
            CredentialData::Passkey(passkey) => Some(passkey),
            CredentialData::Password(_) | CredentialData::Totp(_) => None,
        }
    }

    /// Returns the TOTP data when this is a TOTP credential.
    pub const fn as_totp(&self) -> Option<&TotpCredential> {
        match &self.data {
            CredentialData::Totp(totp) => Some(totp),
            CredentialData::Password(_) | CredentialData::Passkey(_) => None,
        }
    }

    /// Returns the lifecycle status.
    pub const fn status(&self) -> CredentialStatus {
        self.status
    }

    /// Returns `true` when the credential may authenticate.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, CredentialStatus::Active)
    }

    /// Returns the creation time.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the last mutation time.
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// Returns the last successful use time.
    pub const fn last_used_at(&self) -> Option<Timestamp> {
        self.last_used_at
    }

    /// Returns the optimistic concurrency version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Records a successful password authentication.
    pub fn record_use(&mut self, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_active()?;
        self.last_used_at = Some(now);
        self.touch(now);
        Ok(())
    }

    /// Replaces the password verifier after a password change.
    pub fn replace_password(
        &mut self,
        verifier: PasswordVerifier,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.ensure_not_revoked()?;
        match &mut self.data {
            CredentialData::Password(current) => *current = verifier,
            CredentialData::Passkey(_) | CredentialData::Totp(_) => {
                return Err(DomainError::invalid(
                    "credential is not a password credential",
                ));
            }
        }
        self.touch(now);
        Ok(())
    }

    /// Records a passkey authentication and enforces the signature counter.
    pub fn record_passkey_authentication(
        &mut self,
        sign_count: u32,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.ensure_active()?;
        match &mut self.data {
            CredentialData::Passkey(passkey) => passkey.record_authentication(sign_count)?,
            CredentialData::Password(_) | CredentialData::Totp(_) => {
                return Err(DomainError::invalid(
                    "credential is not a passkey credential",
                ));
            }
        }
        self.last_used_at = Some(now);
        self.touch(now);
        Ok(())
    }

    /// Records a verified TOTP time step and prevents replay.
    pub fn accept_totp_step(&mut self, step: u64, now: Timestamp) -> Result<(), DomainError> {
        self.ensure_active()?;
        match &mut self.data {
            CredentialData::Totp(totp) => totp.accept_step(step)?,
            CredentialData::Password(_) | CredentialData::Passkey(_) => {
                return Err(DomainError::invalid("credential is not a TOTP credential"));
            }
        }
        self.last_used_at = Some(now);
        self.touch(now);
        Ok(())
    }

    /// Replaces the encrypted TOTP secret and clears replay protection state.
    pub fn rotate_totp_secret(
        &mut self,
        secret: EncryptedSecret,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.ensure_not_revoked()?;
        match &mut self.data {
            CredentialData::Totp(totp) => totp.rotate_secret(secret),
            CredentialData::Password(_) | CredentialData::Passkey(_) => {
                return Err(DomainError::invalid("credential is not a TOTP credential"));
            }
        }
        self.touch(now);
        Ok(())
    }

    /// Temporarily disables the credential.
    pub fn disable(&mut self, now: Timestamp) {
        if self.status == CredentialStatus::Active {
            self.status = CredentialStatus::Disabled;
            self.touch(now);
        }
    }

    /// Re-enables a disabled credential.
    pub fn enable(&mut self, now: Timestamp) -> Result<(), DomainError> {
        match self.status {
            CredentialStatus::Active => Ok(()),
            CredentialStatus::Disabled => {
                self.status = CredentialStatus::Active;
                self.touch(now);
                Ok(())
            }
            CredentialStatus::Revoked => Err(DomainError::conflict(
                "a revoked credential cannot be re-enabled",
            )),
        }
    }

    /// Permanently revokes the credential.
    ///
    /// Revocation is terminal. Revoked rows are retained so audit history and recovery
    /// investigations remain possible; deletion happens only with the owning user.
    pub fn revoke(&mut self, now: Timestamp) {
        if self.status != CredentialStatus::Revoked {
            self.status = CredentialStatus::Revoked;
            self.touch(now);
        }
    }

    fn ensure_active(&self) -> Result<(), DomainError> {
        if !self.is_active() {
            return Err(DomainError::forbidden("credential is not active"));
        }
        Ok(())
    }

    fn ensure_not_revoked(&self) -> Result<(), DomainError> {
        if matches!(self.status, CredentialStatus::Revoked) {
            return Err(DomainError::conflict(
                "a revoked credential cannot be changed",
            ));
        }
        Ok(())
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version = self.version.saturating_add(1);
    }
}

fn parse_parameters(value: &str) -> Result<Argon2idParameters, ValueError> {
    let mut memory = None;
    let mut time = None;
    let mut parallelism = None;

    for pair in value.split(',') {
        let (key, raw) = pair
            .split_once('=')
            .ok_or_else(|| invalid_verifier("has a malformed parameter list"))?;
        let parsed = raw
            .parse::<u32>()
            .map_err(|_| invalid_verifier("has a non-numeric parameter"))?;
        match key {
            "m" => {
                if memory.replace(parsed).is_some() {
                    return Err(invalid_verifier("repeats the memory parameter"));
                }
            }
            "t" => {
                if time.replace(parsed).is_some() {
                    return Err(invalid_verifier("repeats the time parameter"));
                }
            }
            "p" => {
                if parallelism.replace(parsed).is_some() {
                    return Err(invalid_verifier("repeats the parallelism parameter"));
                }
            }
            _ => return Err(invalid_verifier("has an unsupported parameter")),
        }
    }

    Argon2idParameters::new(
        memory.ok_or_else(|| invalid_verifier("is missing the memory parameter"))?,
        time.ok_or_else(|| invalid_verifier("is missing the time parameter"))?,
        parallelism.ok_or_else(|| invalid_verifier("is missing the parallelism parameter"))?,
    )
}

fn invalid_verifier(reason: &'static str) -> ValueError {
    ValueError::InvalidFormat {
        field: "password verifier",
        reason,
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || (padding > 0 && !bytes.len().is_multiple_of(4)) {
        return None;
    }
    let data = &bytes[..bytes.len() - padding];
    let mut output = Vec::with_capacity(data.len() * 6 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;

    for byte in data {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &str = "c29tZXNhbHRzb21lc2FsdA";
    const HASH: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const VALID_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn credential_id() -> Id<CredentialEntity> {
        Id::<CredentialEntity>::from_suffix("0123456789abcdef").expect("valid id")
    }

    fn user_id() -> Id<UserEntity> {
        Id::<UserEntity>::from_suffix("fedcba9876543210").expect("valid id")
    }

    fn password_verifier() -> PasswordVerifier {
        PasswordVerifier::parse(VALID_PHC).expect("valid verifier")
    }

    fn encrypted_secret() -> EncryptedSecret {
        EncryptedSecret::new("kek-2026-01", vec![0u8; 12], vec![1u8; 32]).expect("valid envelope")
    }

    fn registration() -> PasskeyRegistration {
        PasskeyRegistration::new(
            b"credential-id".to_vec(),
            vec![0xa1, 0x01, 0x02],
            [0u8; 16],
            vec![AuthenticatorTransport::Internal],
            true,
            true,
            false,
        )
        .expect("valid registration")
    }

    #[test]
    fn password_verifier_accepts_argon2id() {
        let verifier = password_verifier();
        assert_eq!(verifier.parameters().memory_kib(), 19_456);
        assert_eq!(verifier.parameters().time_cost(), 2);
        assert!(
            !verifier.needs_rehash(Argon2idParameters::new(19_456, 2, 1).expect("valid policy"))
        );
        assert!(
            verifier.needs_rehash(Argon2idParameters::new(65_536, 3, 1).expect("valid policy"))
        );
        assert!(format!("{verifier:?}").contains("redacted"));
    }

    #[test]
    fn password_verifier_rejects_other_algorithms_and_weak_parameters() {
        for value in [
            "$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$bcrypt$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=8192,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=19456,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=19456,t=2,p=1$c2hvcnQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAA",
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$extra",
        ] {
            assert!(PasswordVerifier::parse(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn password_verifier_rejects_non_base64_salt() {
        let value = format!("$argon2id$v=19$m=19456,t=2,p=1$not_base64!{SALT}${HASH}");
        assert!(PasswordVerifier::parse(value).is_err());
    }

    #[test]
    fn passkey_counter_regression_is_rejected() {
        let mut passkey = PasskeyCredential::new(registration());
        assert_eq!(passkey.sign_count(), 0);
        passkey
            .record_authentication(0)
            .expect("counterless authenticator");
        passkey
            .record_authentication(5)
            .expect("increasing counter");
        assert_eq!(passkey.sign_count(), 5);
        assert!(passkey.record_authentication(5).is_err());
        assert!(passkey.record_authentication(4).is_err());
    }

    #[test]
    fn passkey_registration_requires_a_cose_key() {
        assert!(
            PasskeyRegistration::new(
                b"id".to_vec(),
                vec![0x00],
                [0u8; 16],
                Vec::new(),
                false,
                false,
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn totp_steps_cannot_be_replayed() {
        let mut totp = TotpCredential::new(encrypted_secret(), TotpConfig::default());
        totp.accept_step(100).expect("first use");
        assert_eq!(totp.last_accepted_step(), Some(100));
        assert!(totp.accept_step(100).is_err());
        assert!(totp.accept_step(99).is_err());
        totp.accept_step(101).expect("next step");
        totp.rotate_secret(encrypted_secret());
        assert_eq!(totp.last_accepted_step(), None);
    }

    #[test]
    fn encrypted_secrets_are_redacted() {
        let secret = encrypted_secret();
        let debug = format!("{secret:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("1, 1, 1"));
    }

    #[test]
    fn credentials_enforce_type_specific_operations() {
        let now = Timestamp::from_millis(1_000);
        let mut password =
            Credential::password(credential_id(), user_id(), password_verifier(), now);
        password
            .record_use(Timestamp::from_millis(2_000))
            .expect("active password");
        assert!(
            password
                .accept_totp_step(1, Timestamp::from_millis(3_000))
                .is_err()
        );
        assert!(
            password
                .replace_password(
                    PasswordVerifier::parse(VALID_PHC).expect("valid verifier"),
                    Timestamp::from_millis(3_000),
                )
                .is_ok()
        );

        let mut totp = Credential::totp(
            credential_id(),
            user_id(),
            encrypted_secret(),
            TotpConfig::default(),
            now,
        );
        totp.accept_totp_step(10, Timestamp::from_millis(2_000))
            .expect("first step");
        assert!(
            totp.accept_totp_step(10, Timestamp::from_millis(3_000))
                .is_err()
        );
        assert!(
            totp.record_passkey_authentication(1, Timestamp::from_millis(3_000))
                .is_err()
        );
    }

    #[test]
    fn revocation_is_terminal_and_disabled_credentials_can_return() {
        let now = Timestamp::from_millis(1_000);
        let mut credential =
            Credential::password(credential_id(), user_id(), password_verifier(), now);
        credential.disable(Timestamp::from_millis(2_000));
        assert!(!credential.is_active());
        credential
            .enable(Timestamp::from_millis(3_000))
            .expect("re-enable disabled credential");
        assert!(credential.is_active());
        credential.revoke(Timestamp::from_millis(4_000));
        assert_eq!(credential.status(), CredentialStatus::Revoked);
        assert!(credential.enable(Timestamp::from_millis(5_000)).is_err());
        assert!(
            credential
                .replace_password(password_verifier(), Timestamp::from_millis(5_000))
                .is_err()
        );
        credential.revoke(Timestamp::from_millis(6_000));
        assert_eq!(credential.version(), 3);
    }
}
