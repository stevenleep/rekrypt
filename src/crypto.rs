// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::errors::{CryptoError, ErrorCode};
use crate::i18n::I18n;

/// AES-256-GCM encryption with optional AAD
pub fn aes_encrypt_with_aad(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
    i18n: &I18n,
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::Payload;
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::new(ErrorCode::AesError, i18n.error_msg("aes_error")))?;
    
    // Create Nonce from slice - validate length first
    if iv.len() != 12 {
        return Err(CryptoError::new(ErrorCode::InvalidIV, i18n.error_msg("invalid_iv")));
    }
    let nonce = GenericArray::clone_from_slice(iv);
    
    let payload = if let Some(aad_data) = aad {
        Payload {
            msg: plaintext,
            aad: aad_data,
        }
    } else {
        Payload {
            msg: plaintext,
            aad: b"",
        }
    };
    
    cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::new(ErrorCode::AesError, i18n.error_msg("aes_error")))
}

/// AES-256-GCM encryption
pub fn aes_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], i18n: &I18n) -> Result<Vec<u8>, CryptoError> {
    aes_encrypt_with_aad(key, iv, plaintext, None, i18n)
}

/// AES-256-GCM decryption with optional AAD
pub fn aes_decrypt_with_aad(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    i18n: &I18n,
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::Payload;
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::new(ErrorCode::DecryptionError, i18n.error_msg("decryption_error")))?;
    
    // Create Nonce from slice - validate length first
    if iv.len() != 12 {
        return Err(CryptoError::new(ErrorCode::InvalidIV, i18n.error_msg("invalid_iv")));
    }
    let nonce = GenericArray::clone_from_slice(iv);
    
    let payload = if let Some(aad_data) = aad {
        Payload {
            msg: ciphertext,
            aad: aad_data,
        }
    } else {
        Payload {
            msg: ciphertext,
            aad: b"",
        }
    };
    
    cipher
        .decrypt(&nonce, payload)
        .map_err(|_| CryptoError::new(ErrorCode::DecryptionError, i18n.error_msg("decryption_error")))
}

/// AES-256-GCM decryption
pub fn aes_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], i18n: &I18n) -> Result<Vec<u8>, CryptoError> {
    aes_decrypt_with_aad(key, iv, ciphertext, None, i18n)
}

/// Computes SHA-256 hash
pub fn compute_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Constant-time comparison (prevents timing attacks)
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Computes HMAC-SHA256
pub fn compute_hmac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    
    for part in parts {
        mac.update(part);
    }
    
    mac.finalize().into_bytes().to_vec()
}

/// Verifies MAC (constant-time comparison)
pub fn verify_mac(computed: &[u8], expected: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if !constant_time_compare(computed, expected) {
        return Err(CryptoError::new(
            ErrorCode::IntegrityCheckFailed,
            i18n.error_msg("integrity_check_failed"),
        ));
    }
    Ok(())
}

/// PBKDF2-HMAC-SHA256 key derivation
pub fn derive_key_pbkdf2(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let mut key = vec![0u8; dklen];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    key
}

/// HKDF key derivation
pub fn derive_key_hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::new(ErrorCode::KeyDerivationError, "Key derivation failed"))?;
    Ok(okm)
}

/// Generates UUID v4
pub fn generate_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let uuid: [u8; 16] = rng.gen();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    )
}

/// Generates random IV (12 bytes)
pub fn generate_iv() -> [u8; 12] {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// Generates random salt (16 bytes)
pub fn generate_salt() -> [u8; 16] {
    use rand::Rng;
    rand::thread_rng().gen()
}
