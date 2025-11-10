// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use bip39::{Language, Mnemonic};
use recrypt::api::{KeyGenOps, PrivateKey, Recrypt};
use zeroize::Zeroize;

use crate::crypto::derive_key_hkdf;
use crate::errors::CryptoError;
use crate::i18n::I18n;
use crate::types::{ExportWarning, KeypairResult};
use crate::validation::check_and_normalize;

/// Generates keypair from 24-word BIP39 mnemonic
pub fn generate_keypair(passphrase: &str, _i18n: &I18n) -> Result<KeypairResult, CryptoError> {
    let mnemonic = Mnemonic::generate(24)?;
    let mnemonic_phrase = mnemonic.to_string();
    let seed = mnemonic.to_seed(passphrase);

    let mut private_key_bytes = derive_key_hkdf(&seed, None, b"recrypt-key-v1", 32)?;

    let api = Recrypt::new();
    let private_key = PrivateKey::new_from_slice(&private_key_bytes)?;
    let public_key = api.compute_public_key(&private_key)?;

    private_key_bytes.zeroize();

    let public_key_bytes = {
        let bytes = public_key.bytes_x_y();
        postcard::to_allocvec(&bytes)?
    };

    Ok(KeypairResult {
        private_key: private_key.bytes().to_vec(),
        public_key: public_key_bytes,
        mnemonic: mnemonic_phrase.to_string(),
    })
}

/// Recovers keypair from BIP39 mnemonic
pub fn recover_keypair(
    mnemonic: &str,
    passphrase: &str,
    i18n: &I18n,
) -> Result<KeypairResult, CryptoError> {
    let normalized = check_and_normalize(mnemonic, i18n)?;
    let mnemonic = Mnemonic::parse_in(Language::English, &normalized)?;
    let seed = mnemonic.to_seed(passphrase);

    let mut private_key_bytes = derive_key_hkdf(&seed, None, b"recrypt-key-v1", 32)?;

    let api = Recrypt::new();
    let private_key = PrivateKey::new_from_slice(&private_key_bytes)?;
    let public_key = api.compute_public_key(&private_key)?;

    private_key_bytes.zeroize();

    let public_key_bytes = {
        let bytes = public_key.bytes_x_y();
        postcard::to_allocvec(&bytes)?
    };

    Ok(KeypairResult {
        private_key: private_key.bytes().to_vec(),
        public_key: public_key_bytes,
        mnemonic: mnemonic.to_string(),
    })
}

/// Exports private key with security warnings
pub fn export_private_key_with_warning(keypair: &KeypairResult, i18n: &I18n) -> ExportWarning {
    ExportWarning {
        warning: i18n.error_msg("export_warning").to_string(),
        private_key: keypair.private_key.clone(),
        safety_tips: vec![
            i18n.error_msg("safety_tip_offline").to_string(),
            i18n.error_msg("safety_tip_no_network").to_string(),
            i18n.error_msg("safety_tip_no_screenshot").to_string(),
            i18n.error_msg("safety_tip_encrypt").to_string(),
            i18n.error_msg("safety_tip_clear").to_string(),
        ],
    }
}
