// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use crate::crypto::{aes_decrypt, aes_encrypt, compute_hmac, derive_key_pbkdf2, generate_iv, generate_salt, verify_mac};
use crate::errors::{CryptoError, ErrorCode};
use crate::i18n::I18n;
use crate::types::{CipherParams, Keystore, KeystoreCrypto, KdfParams};
use crate::validation::{validate_kdf_iterations, validate_password_strength, validate_private_key, validate_iv};
use zeroize::Zeroize;

/// Creates encrypted keystore
pub fn create_keystore(
    private_key: &[u8],
    password: &str,
    i18n: &I18n,
) -> Result<Keystore, CryptoError> {
    validate_private_key(private_key, i18n)?;

    validate_password_strength(password, i18n)?;

    let salt = generate_salt();
    let iv = generate_iv();
    let iterations = 600_000u32;
    let dklen = 32;

    let mut key = derive_key_pbkdf2(password.as_bytes(), &salt, iterations, dklen);
    let ciphertext = aes_encrypt(&key, &iv, private_key, i18n)?;

    let version_bytes = [1u8];
    let iterations_bytes = iterations.to_le_bytes();
    let dklen_bytes = (dklen as u32).to_le_bytes();
    let cipher_name = b"aes-256-gcm";
    let kdf_name = b"pbkdf2-hmac-sha256";
    
    let mut mac_data = compute_hmac(&key, &[
        &ciphertext,
        &salt,
        &iv,
        &iterations_bytes,
        &dklen_bytes,
        &version_bytes,
        cipher_name,
        kdf_name,
    ]);

    key.zeroize();
    
    let keystore = Keystore {
        version: 1,
        crypto: KeystoreCrypto {
            cipher: "aes-256-gcm".to_string(),
            ciphertext,
            cipherparams: CipherParams { iv: iv.to_vec() },
            kdf: "pbkdf2-hmac-sha256".to_string(),
            kdfparams: KdfParams {
                dklen: dklen as u32,
                n: iterations,
                p: 1,
                r: 8,
                salt,
            },
            mac: mac_data.clone(),
        },
    };

    mac_data.zeroize();
    
    Ok(keystore)
}

/// Recovers private key from keystore
pub fn recover_from_keystore(
    keystore: &Keystore,
    password: &str,
    i18n: &I18n,
) -> Result<Vec<u8>, CryptoError> {
    if keystore.version != 1 {
        return Err(CryptoError::new(
            ErrorCode::UnsupportedVersion,
            i18n.format("unsupported_version", &[("version", &keystore.version.to_string())]),
        ));
    }

    validate_kdf_iterations(keystore.crypto.kdfparams.n, i18n)?;
    validate_iv(&keystore.crypto.cipherparams.iv, i18n)?;

    let mut key = derive_key_pbkdf2(
        password.as_bytes(),
        &keystore.crypto.kdfparams.salt,
        keystore.crypto.kdfparams.n,
        keystore.crypto.kdfparams.dklen as usize,
    );

    let version_bytes = [keystore.version];
    let iterations_bytes = keystore.crypto.kdfparams.n.to_le_bytes();
    let dklen_bytes = keystore.crypto.kdfparams.dklen.to_le_bytes();
    let cipher_name = keystore.crypto.cipher.as_bytes();
    let kdf_name = keystore.crypto.kdf.as_bytes();
    
    let computed_mac = compute_hmac(&key, &[
        &keystore.crypto.ciphertext,
        &keystore.crypto.kdfparams.salt,
        &keystore.crypto.cipherparams.iv,
        &iterations_bytes,
        &dklen_bytes,
        &version_bytes,
        cipher_name,
        kdf_name,
    ]);

    if let Err(e) = verify_mac(&computed_mac, &keystore.crypto.mac, i18n) {
        key.zeroize();
        return Err(e);
    }
    
    let private_key = aes_decrypt(
        &key,
        &keystore.crypto.cipherparams.iv,
        &keystore.crypto.ciphertext,
        i18n,
    );

    key.zeroize();
    
    match private_key {
        Ok(pk) => Ok(pk),
        Err(e) => Err(e),
    }
}
