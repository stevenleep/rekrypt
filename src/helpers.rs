// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

//! Helper utilities for validation, serialization, and data conversion

use crate::crypto;
use crate::errors::CryptoError;
use crate::i18n::I18n;
use crate::types::Capsule;
use crate::validation;
use rand::Rng;
use recrypt::api::{KeyGenOps, PrivateKey, PublicKey, SigningKeypair};
use wasm_bindgen::prelude::*;

/// Serializes capsule to bytes
pub fn serialize_capsule(capsule: JsValue) -> Result<Vec<u8>, CryptoError> {
    let capsule: Capsule =
        serde_wasm_bindgen::from_value(capsule).map_err(|_| CryptoError::InvalidCapsule)?;

    postcard::to_allocvec(&capsule).map_err(|e| {
        CryptoError::new(
            crate::errors::ErrorCode::SerdeError,
            format!("Failed to serialize capsule: {:?}", e),
        )
    })
}

/// Deserializes bytes to capsule
pub fn deserialize_capsule(bytes: &[u8]) -> Result<JsValue, CryptoError> {
    let capsule: Capsule = postcard::from_bytes(bytes).map_err(|e| {
        CryptoError::new(
            crate::errors::ErrorCode::SerdeError,
            format!("Failed to deserialize capsule: {:?}", e),
        )
    })?;

    serde_wasm_bindgen::to_value(&capsule).map_err(CryptoError::SerdeWasmError)
}

/// Reconstructs signing keypair from bytes
#[allow(dead_code)]
pub fn signing_keypair_from_bytes(bytes: &[u8]) -> Result<SigningKeypair, CryptoError> {
    SigningKeypair::from_byte_slice(bytes).map_err(|_| CryptoError::Ed25519Error)
}

// ==================== Utility Functions ====================

/// Validates password strength
pub fn validate_password_strength(password: &str, i18n: &I18n) -> Result<(), CryptoError> {
    validation::validate_password_strength(password, i18n)
}

/// Computes SHA-256 hash
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    crypto::compute_hash(data)
}

/// Generates random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.gen()).collect()
}

/// Validates public key
pub fn validate_public_key(public_key: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    validation::validate_public_key(public_key, i18n)?;
    let key_tuple: ([u8; 32], [u8; 32]) = postcard::from_bytes(public_key)?;
    let pk = PublicKey::new(key_tuple)?;
    let tuple = pk.bytes_x_y();
    if *tuple.0 == [0u8; 32] && *tuple.1 == [0u8; 32] {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok(())
}

/// Validates private key
pub fn validate_private_key(private_key: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    validation::validate_private_key(private_key, i18n)?;
    PrivateKey::new_from_slice(private_key)?;
    Ok(())
}

/// Verifies keypair match
pub fn verify_keypair_match<R: KeyGenOps>(
    private_key: &[u8],
    public_key: &[u8],
    recrypt: &R,
) -> Result<bool, CryptoError> {
    let priv_key = PrivateKey::new_from_slice(private_key)?;
    let derived = recrypt.compute_public_key(&priv_key)?;
    let provided: ([u8; 32], [u8; 32]) = postcard::from_bytes(public_key)?;
    let provided_pk = PublicKey::new(provided)?;
    Ok(derived.bytes_x_y() == provided_pk.bytes_x_y())
}

/// Derives public key from private key
pub fn derive_public_key<R: KeyGenOps>(
    private_key: &[u8],
    recrypt: &R,
) -> Result<Vec<u8>, CryptoError> {
    let priv_key = PrivateKey::new_from_slice(private_key)?;
    let pub_key = recrypt.compute_public_key(&priv_key)?;
    postcard::to_allocvec(&pub_key.bytes_x_y()).map_err(Into::into)
}

/// Computes HMAC-SHA256
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    crypto::compute_hmac(key, &[data])
}

/// Verifies HMAC tag
pub fn verify_hmac(key: &[u8], data: &[u8], expected_mac: &[u8]) -> bool {
    let mac = crypto::compute_hmac(key, &[data]);
    crypto::constant_time_compare(&mac, expected_mac)
}

/// Generates UUID v4
pub fn generate_uuid() -> String {
    crypto::generate_uuid()
}

/// Bytes to hex
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, CryptoError> {
    let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
    if !hex.len().is_multiple_of(2) {
        return Err(CryptoError::new(
            crate::errors::ErrorCode::InvalidInput,
            "Hex must have even length",
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| {
                CryptoError::new(crate::errors::ErrorCode::InvalidInput, "Invalid hex")
            })
        })
        .collect()
}
