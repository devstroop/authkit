//! Argon2id password hashing adapter.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Argon2, Params};
use authkit_core::domain::credential::PasswordVerifier as DomainVerifier;
use authkit_core::domain::secret::SecretHash;
use authkit_core::domain::{DomainError, ErrorCode, ValueError};

/// Argon2id work factors matching the domain minimums.
const MEMORY_KIB: u32 = 19 * 1024;
const TIME_COST: u32 = 2;
const PARALLELISM: u32 = 1;

/// Hashes a plaintext password into a validated Argon2id PHC verifier.
pub fn hash_password(password: &str) -> Result<DomainVerifier, DomainError> {
    if password.len() < 12 {
        return Err(DomainError::invalid("password is too short"));
    }
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(MEMORY_KIB, TIME_COST, PARALLELISM, Some(32))
        .map_err(|_| DomainError::new(ErrorCode::Internal, "invalid Argon2 parameters"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| DomainError::new(ErrorCode::Internal, "password hashing failed"))?;
    DomainVerifier::parse(hash.to_string()).map_err(|error: ValueError| {
        DomainError::new(
            ErrorCode::Internal,
            format!("hashed password is invalid: {error}"),
        )
    })
}

/// Verifies a plaintext password against a stored Argon2id verifier.
pub fn verify_password(password: &str, verifier: &DomainVerifier) -> bool {
    let Ok(parsed) = PasswordHash::new(verifier.as_str()) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Returns `true` when the stored verifier uses weaker or older Argon2id parameters.
pub fn needs_rehash(verifier: &DomainVerifier) -> bool {
    let Ok(parsed) = PasswordHash::new(verifier.as_str()) else {
        return true;
    };
    let params = &parsed.params;
    let memory = params
        .get("m")
        .and_then(|value| value.decimal().ok())
        .unwrap_or(0);
    let time = params
        .get("t")
        .and_then(|value| value.decimal().ok())
        .unwrap_or(0);
    let parallelism = params
        .get("p")
        .and_then(|value| value.decimal().ok())
        .unwrap_or(0);
    memory < MEMORY_KIB || time < TIME_COST || parallelism < PARALLELISM
}

/// Hashes a high-entropy recovery code.
pub fn hash_recovery_code(code: &str) -> Result<SecretHash, DomainError> {
    let verifier = hash_password(code)?;
    SecretHash::parse(verifier.as_str().to_owned())
        .map_err(|error| DomainError::new(ErrorCode::Internal, error.to_string()))
}

/// Verifies a recovery code against its stored hash.
pub fn verify_recovery_code(code: &str, hash: &SecretHash) -> bool {
    let Ok(parsed) = argon2::password_hash::PasswordHash::new(hash.as_str()) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(code.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let verifier = hash_password("correct horse battery staple").expect("hash");
        assert!(verify_password("correct horse battery staple", &verifier));
        assert!(!verify_password("wrong password", &verifier));
    }

    #[test]
    fn rejects_short_passwords() {
        assert!(hash_password("short").is_err());
    }
}
