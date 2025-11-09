use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::errors::{CryptoError, ErrorCode};
use crate::i18n::I18n;

/// AES-256-GCM 加密
pub fn aes_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8], i18n: &I18n) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::new(ErrorCode::AesError, i18n.error_msg("aes_error")))?;
    
    let nonce = Nonce::from_slice(iv);
    
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::new(ErrorCode::AesError, i18n.error_msg("aes_error")))
}

/// AES-256-GCM 解密
pub fn aes_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8], i18n: &I18n) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::new(ErrorCode::DecryptionError, i18n.error_msg("decryption_error")))?;
    
    let nonce = Nonce::from_slice(iv);
    
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::new(ErrorCode::DecryptionError, i18n.error_msg("decryption_error")))
}

/// 计算 SHA-256 哈希
pub fn compute_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// 常数时间比较（防止时间攻击）
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// 生成 MAC（消息认证码）
pub fn compute_mac(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

/// 验证 MAC（使用常数时间比较）
pub fn verify_mac(computed: &[u8], expected: &[u8], i18n: &I18n) -> Result<(), CryptoError> {
    if !constant_time_compare(computed, expected) {
        return Err(CryptoError::new(
            ErrorCode::IntegrityCheckFailed,
            i18n.error_msg("integrity_check_failed"),
        ));
    }
    Ok(())
}

/// 安全的密钥派生（PBKDF2-HMAC-SHA256）
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dklen: usize,
) -> Vec<u8> {
    let mut key = vec![0u8; dklen];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    key
}

/// 安全的密钥派生（HKDF-SHA256）
pub fn derive_key_hkdf(
    ikm: &[u8],  // Input Key Material
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, CryptoError> {
    use hkdf::Hkdf;
    
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::new(ErrorCode::KeyDerivationError, "Key derivation failed"))?;
    
    Ok(okm)
}

/// 生成安全随机 UUID（用于防重放攻击）
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

/// 生成安全随机 IV
pub fn generate_iv() -> [u8; 12] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}

/// 生成安全随机 salt
pub fn generate_salt() -> [u8; 16] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}
