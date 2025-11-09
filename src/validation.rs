use crate::errors::{CryptoError, ErrorCode};
use crate::i18n::I18n;

/// 验证密码强度
pub fn validate_password_strength(password: &str, i18n: &I18n) -> Result<(), CryptoError> {
    if password.len() < 8 {
        return Err(CryptoError::new(
            ErrorCode::WeakPassword,
            i18n.error_msg("password_too_short"),
        ));
    }
    
    if password.len() > 128 {
        return Err(CryptoError::new(
            ErrorCode::WeakPassword,
            i18n.error_msg("password_too_long"),
        ));
    }

    // 检查密码复杂度：至少包含 3 种类型
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

/// 检查并标准化助记词
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

/// 验证公钥
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
    
    Ok(())
}

/// 验证私钥
pub fn validate_private_key(private_key: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if private_key.len() != 32 {
        return Err(CryptoError::new(
            ErrorCode::InvalidPrivateKey,
            i18n.error_msg("invalid_private_key"),
        ));
    }
    Ok(())
}

/// 验证数据不为空
pub fn validate_data_not_empty(data: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::new(
            ErrorCode::InvalidInput,
            i18n.error_msg("data_empty"),
        ));
    }
    Ok(())
}

/// 验证版本号
pub fn validate_version(version: u8, expected: u8, i18n: &I18n) -> Result<(), CryptoError> {
    if version != expected {
        return Err(CryptoError::new(
            ErrorCode::UnsupportedVersion,
            i18n.format("unsupported_version", &[("version", &version.to_string())]),
        ));
    }
    Ok(())
}

/// 验证 IV 长度
pub fn validate_iv(iv: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if iv.len() != 12 {
        return Err(CryptoError::new(
            ErrorCode::InvalidIV,
            i18n.error_msg("invalid_iv"),
        ));
    }
    Ok(())
}

/// 验证 KDF 迭代次数（防止 DoS 攻击，确保安全性）
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

