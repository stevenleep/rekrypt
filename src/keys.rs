use bip39::{Language, Mnemonic, MnemonicType, Seed};
use recrypt::api::{KeyGenOps, PrivateKey, Recrypt};
use zeroize::Zeroize;

use crate::crypto::derive_key_hkdf;
use crate::errors::CryptoError;
use crate::i18n::I18n;
use crate::types::{ExportWarning, KeypairResult};
use crate::validation::check_and_normalize;

/// 生成密钥对（使用 BIP39 助记词）
pub fn generate_keypair(passphrase: &str, _i18n: &I18n) -> Result<KeypairResult, CryptoError> {
    // 生成 24 词助记词
    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    let mnemonic_phrase = mnemonic.phrase();
    let seed = Seed::new(&mnemonic, passphrase);
    let mut private_key_bytes = derive_key_hkdf(
        seed.as_bytes(),
        None,
        b"recrypt-key-v1",
        32,
    )?;

    let api = Recrypt::new();
    let private_key = PrivateKey::new_from_slice(&private_key_bytes)
        .map_err(|e| CryptoError::RecryptError(e))?;
    let public_key = api.compute_public_key(&private_key)?;
    
    // 清零临时敏感数据
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

/// 从助记词恢复密钥对
pub fn recover_keypair(mnemonic: &str, passphrase: &str, i18n: &I18n) -> Result<KeypairResult, CryptoError> {
    let normalized = check_and_normalize(mnemonic, i18n)?;
    let mnemonic = Mnemonic::from_phrase(&normalized, Language::English)
        .map_err(|e| CryptoError::BIP39Error(e))?;

    let seed = Seed::new(&mnemonic, passphrase);
    
    let mut private_key_bytes = derive_key_hkdf(
        seed.as_bytes(),
        None,
        b"recrypt-key-v1",
        32,
    )?;

    let api = Recrypt::new();
    let private_key = PrivateKey::new_from_slice(&private_key_bytes)
        .map_err(|e| CryptoError::RecryptError(e))?;
    let public_key = api.compute_public_key(&private_key)?;

    private_key_bytes.zeroize();

    let public_key_bytes = {
        let bytes = public_key.bytes_x_y();
        postcard::to_allocvec(&bytes)?
    };
    
    Ok(KeypairResult {
        private_key: private_key.bytes().to_vec(),
        public_key: public_key_bytes,
        mnemonic: mnemonic.phrase().to_string(),
    })
}

/// 导出私钥（带安全警告）
pub fn export_private_key_with_warning(
    keypair: &KeypairResult,
    i18n: &I18n,
) -> ExportWarning {
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

