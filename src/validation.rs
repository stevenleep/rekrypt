// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use crate::errors::{CryptoError, ErrorCode};
use crate::i18n::I18n;

/// Validates password strength (12-128 chars, 3+ char types)
pub fn validate_password_strength(password: &str, i18n: &I18n) -> Result<(), CryptoError> {
    const MIN_PASSWORD_LENGTH: usize = 12;
    const MAX_PASSWORD_LENGTH: usize = 128;
    
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(CryptoError::new(
            ErrorCode::WeakPassword,
            i18n.error_msg("password_too_short"),
        ));
    }
    
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(CryptoError::new(
            ErrorCode::WeakPassword,
            i18n.error_msg("password_too_long"),
        ));
    }

    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    let complexity = [has_lowercase, has_uppercase, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    
    if complexity < 3 {
        return Err(CryptoError::new(
            ErrorCode::WeakPassword,
            i18n.error_msg("password_complexity"),
        ));
    }
    
    Ok(())
}

/// Checks and normalizes mnemonic (lowercase, trim)
pub fn check_and_normalize(mnemonic: &str, i18n: &I18n) -> Result<String, CryptoError> {
    let normalized = mnemonic.trim().to_lowercase();
    if !normalized.chars().all(|c| c.is_alphabetic() || c.is_whitespace()) {
        return Err(CryptoError::new(
            ErrorCode::InvalidMnemonic,
            i18n.error_msg("invalid_mnemonic"),
        ));
    }
    
    Ok(normalized)
}

/// Validates public key format (64 bytes, not all zeros/0xFF)
pub fn validate_public_key(public_key: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if public_key.len() != 64 {
        return Err(CryptoError::new(
            ErrorCode::InvalidPublicKey,
            i18n.error_msg("invalid_public_key"),
        ));
    }

    if public_key.iter().all(|&b| b == 0) {
        return Err(CryptoError::new(
            ErrorCode::InvalidPublicKey,
            i18n.error_msg("invalid_public_key"),
        ));
    }
    
    if public_key.iter().all(|&b| b == 0xFF) {
        return Err(CryptoError::new(
            ErrorCode::InvalidPublicKey,
            i18n.error_msg("invalid_public_key"),
        ));
    }
    
    Ok(())
}

/// Validates private key (32 bytes)
pub fn validate_private_key(private_key: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if private_key.len() != 32 {
        return Err(CryptoError::new(
            ErrorCode::InvalidPrivateKey,
            i18n.error_msg("invalid_private_key"),
        ));
    }
    Ok(())
}

/// Validates data is not empty
pub fn validate_data_not_empty(data: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::new(
            ErrorCode::InvalidInput,
            i18n.error_msg("data_empty"),
        ));
    }
    Ok(())
}

/// Validates version
pub fn validate_version(version: u8, expected: u8, i18n: &I18n) -> Result<(), CryptoError> {
    if version != expected {
        return Err(CryptoError::new(
            ErrorCode::UnsupportedVersion,
            i18n.format("unsupported_version", &[("version", &version.to_string())]),
        ));
    }
    Ok(())
}

/// Validates IV length (12 bytes)
pub fn validate_iv(iv: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if iv.len() != 12 {
        return Err(CryptoError::new(
            ErrorCode::InvalidIV,
            i18n.error_msg("invalid_iv"),
        ));
    }
    Ok(())
}

/// Validates KDF iterations (100k-10M)
pub fn validate_kdf_iterations(iterations: u32, i18n: &I18n) -> Result<(), CryptoError> {
    const MIN_ITERATIONS: u32 = 100_000;
    const MAX_ITERATIONS: u32 = 10_000_000;
    
    if iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS {
        return Err(CryptoError::new(
            ErrorCode::InvalidKdfParams,
            i18n.format(
                "invalid_kdf_params",
                &[
                    ("min", &MIN_ITERATIONS.to_string()),
                    ("max", &MAX_ITERATIONS.to_string()),
                ],
            ),
        ));
    }
    Ok(())
}

/// Validates timestamp (replay attack prevention)
pub fn validate_timestamp(
    client_timestamp: u64,
    max_age_seconds: u64,
    i18n: &I18n,
) -> Result<(), CryptoError> {
    let current_time_ms = js_sys::Date::now() as u64;
    const CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
    
    if client_timestamp > current_time_ms + CLOCK_SKEW_MS {
        return Err(CryptoError::new(
            ErrorCode::InvalidInput,
            i18n.error_msg("timestamp_future"),
        ));
    }
    
    let max_age_ms = max_age_seconds * 1000;
    if current_time_ms > client_timestamp + max_age_ms {
        return Err(CryptoError::new(
            ErrorCode::InvalidInput,
            i18n.error_msg("timestamp_too_old"),
        ));
    }
    
    Ok(())
}

/// Validates request ID (UUID v4 format)
pub fn validate_request_id(request_id: &str, i18n: &I18n) -> Result<(), CryptoError> {
    if request_id.len() != 36 {
        return Err(CryptoError::new(
            ErrorCode::InvalidInput,
            i18n.error_msg("invalid_request_id"),
        ));
    }
    
    if request_id.chars().nth(8) != Some('-')
        || request_id.chars().nth(13) != Some('-')
        || request_id.chars().nth(18) != Some('-')
        || request_id.chars().nth(23) != Some('-')
    {
        return Err(CryptoError::new(
            ErrorCode::InvalidInput,
            i18n.error_msg("invalid_request_id"),
        ));
    }
    
    for (i, c) in request_id.chars().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return Err(CryptoError::new(
                ErrorCode::InvalidInput,
                i18n.error_msg("invalid_request_id"),
            ));
        }
    }
    
    Ok(())
}

