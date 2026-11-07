//! TOTP helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use authkit_core::domain::DomainError;
use authkit_core::domain::credential::{EncryptedSecret, TotpConfig};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use sha1::Sha1;
use sha2::Sha256;

const KEY_ID: &str = "session-pepper";

pub fn generate_secret() -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut secret = vec![0u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
}

pub fn encrypt_secret(secret: &[u8], pepper: &[u8]) -> Result<EncryptedSecret, DomainError> {
    use sha2::Digest;
    let key = sha2::Sha256::digest(pepper);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| {
        DomainError::new(
            authkit_core::domain::ErrorCode::Internal,
            "invalid TOTP key",
        )
    })?;
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, secret).map_err(|_| {
        DomainError::new(
            authkit_core::domain::ErrorCode::Internal,
            "TOTP encryption failed",
        )
    })?;
    EncryptedSecret::new(KEY_ID, nonce_bytes.to_vec(), ciphertext)
        .map_err(|e| DomainError::new(authkit_core::domain::ErrorCode::Internal, e.to_string()))
}

pub fn decrypt_secret(secret: &EncryptedSecret, pepper: &[u8]) -> Result<Vec<u8>, DomainError> {
    use sha2::Digest;
    let key = sha2::Sha256::digest(pepper);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| {
        DomainError::new(
            authkit_core::domain::ErrorCode::Internal,
            "invalid TOTP key",
        )
    })?;
    let nonce = Nonce::from_slice(secret.nonce());
    cipher.decrypt(nonce, secret.ciphertext()).map_err(|_| {
        DomainError::new(
            authkit_core::domain::ErrorCode::Internal,
            "TOTP decryption failed",
        )
    })
}

pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::new();
    let mut buffer = 0u64;
    let mut bits_left = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u64::from(*byte);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            output.push(ALPHABET[((buffer >> bits_left) & 0x1f) as usize] as char);
        }
    }
    if bits_left > 0 {
        buffer <<= 5 - bits_left;
        output.push(ALPHABET[(buffer & 0x1f) as usize] as char);
    }
    output
}

pub fn current_step(period_seconds: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now / period_seconds
}

pub fn code(secret: &[u8], step: u64, config: TotpConfig) -> String {
    let mut message = [0u8; 8];
    message.copy_from_slice(&step.to_be_bytes());
    let hmac = match config.algorithm() {
        authkit_core::domain::credential::TotpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        authkit_core::domain::credential::TotpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        authkit_core::domain::credential::TotpAlgorithm::Sha512 => {
            let mut mac = <Hmac<sha2::Sha512> as Mac>::new_from_slice(secret).expect("hmac");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    let binary = ((hmac[offset] as u32 & 0x7f) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);
    let modulus = 10u32.pow(u32::from(config.digits()));
    let code = binary % modulus;
    format!("{:0width$}", code, width = config.digits() as usize)
}

pub fn verify_code(
    secret: &[u8],
    supplied: &str,
    config: TotpConfig,
    last_accepted_step: Option<u64>,
) -> Option<u64> {
    let step = current_step(config.period_seconds());
    for candidate in [step.saturating_sub(1), step, step.saturating_add(1)] {
        if Some(candidate) == last_accepted_step {
            continue;
        }
        if code(secret, candidate, config) == supplied {
            return Some(candidate);
        }
    }
    None
}

pub fn challenge_token(user_id: &str, next: &str, pepper: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let expiry = (current_step(30) + 2) * 30;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pepper).expect("hmac");
    mac.update(user_id.as_bytes());
    mac.update(b"|");
    mac.update(next.as_bytes());
    mac.update(b"|");
    mac.update(expiry.to_string().as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}.{}", user_id, expiry, sig)
}

pub fn verify_challenge(token: &str, next: &str, pepper: &[u8]) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let user_id = parts[0];
    let expiry: u64 = parts[1].parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now > expiry {
        return None;
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pepper).expect("hmac");
    mac.update(user_id.as_bytes());
    mac.update(b"|");
    mac.update(next.as_bytes());
    mac.update(b"|");
    mac.update(expiry.to_string().as_bytes());
    let expected =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    if expected != parts[2] {
        return None;
    }
    Some(user_id.to_owned())
}
