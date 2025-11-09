mod crypto;
mod errors;
mod i18n;
mod keys;
mod keystore;
mod types;
mod validation;

use bip39::{Language, Mnemonic};
use i18n::{I18n, Language as I18nLanguage};
use rand::Rng;
use recrypt::api::{
    CryptoOps, DefaultRng, Ed25519, Ed25519Ops, EncryptedValue, KeyGenOps, PrivateKey, PublicKey,
    RandomBytes, Recrypt, Sha256, SigningKeypair, TransformKey,
};
use serde_wasm_bindgen;
use std::cell::Cell;
use wasm_bindgen::prelude::*;

pub use errors::CryptoError;
pub use types::{Capsule, CryptoFunctionResult, ExportWarning, Keystore, KeypairResult};

#[wasm_bindgen]
pub struct EncryptSDK {
    recrypt: Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
    iv_counter: Cell<u64>,
    sequence_counter: Cell<u64>,
    i18n: I18n,
}

#[wasm_bindgen]
impl EncryptSDK {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();

        let mut rng = rand::thread_rng();
        let initial_sequence: u64 = rng.gen();
        
        Self {
            recrypt: Recrypt::new(),
            iv_counter: Cell::new(0),
            sequence_counter: Cell::new(initial_sequence),
            i18n: I18n::new(I18nLanguage::EnUS),
        }
    }

    #[wasm_bindgen(js_name = setLanguage)]
    pub fn set_language(&mut self, lang: &str) {
        self.i18n = I18n::new(match lang {
            "zh-CN" | "zh" => I18nLanguage::ZhCN,
            _ => I18nLanguage::EnUS,
        });
    }
    
    /// 生成唯一 IV
    fn next_iv(&self) -> [u8; 12] {
        let counter = self.iv_counter.get();
        self.iv_counter.set(counter.wrapping_add(1));
        
        let mut rng = rand::thread_rng();
        let random_part: u32 = rng.gen();
        
        let mut iv = [0u8; 12];
        iv[0..8].copy_from_slice(&counter.to_le_bytes());
        iv[8..12].copy_from_slice(&random_part.to_le_bytes());
        iv
    }

    fn next_sequence(&self) -> u64 {
        let seq = self.sequence_counter.get();
        self.sequence_counter.set(seq.wrapping_add(1));
        seq
    }

    /// 生成密钥对（无密码短语）
    pub fn gen(&self) -> Result<JsValue, CryptoError> {
        self.gen_with_passphrase("")
    }

    /// 生成密钥对（支持密码短语）
    #[wasm_bindgen(js_name = genWithPassphrase)]
    pub fn gen_with_passphrase(&self, passphrase: &str) -> Result<JsValue, CryptoError> {
        let keypair = keys::generate_keypair(passphrase, &self.i18n)?;
        serde_wasm_bindgen::to_value(&keypair).map_err(CryptoError::SerdeWasmError)
    }

    /// 加密数据
    pub fn put(&self, data: &[u8], public_key: &[u8]) -> Result<JsValue, CryptoError> {

        validation::validate_data_not_empty(data, &self.i18n)?;
        validation::validate_public_key(public_key, &self.i18n)?;

        let public_key_tuple: ([u8; 32], [u8; 32]) = postcard::from_bytes(public_key)
            .map_err(|e| CryptoError::new(
                crate::errors::ErrorCode::SerdeError,
                &format!("Failed to deserialize public key (len={}): {:?}", public_key.len(), e)
            ))?;
        let public_key = PublicKey::new(public_key_tuple)?;

        let verified_tuple = public_key.bytes_x_y();
        if *verified_tuple.0 == [0u8; 32] && *verified_tuple.1 == [0u8; 32] {
            return Err(CryptoError::InvalidPublicKey);
        }

        let (_ephemeral_private_key, _ephemeral_public_key) = self.recrypt.generate_key_pair()?;
        let signing_key_pair = self.recrypt.generate_ed25519_key_pair();
        let plaintext = self.recrypt.gen_plaintext();
        let encrypted_val = self.recrypt.encrypt(&plaintext, &public_key, &signing_key_pair)?;
        let symmetric_key = self.recrypt.derive_symmetric_key(&plaintext);

        let nonce = self.next_iv();

        // AES 加密
        let c_data = crypto::aes_encrypt(symmetric_key.bytes(), &nonce, data, &self.i18n)?;

        let data_hash = crypto::compute_hash(&c_data);

        let encrypted_data = postcard::to_allocvec(&encrypted_val)?;
        let capsule = Capsule {
            version: 1,
            nonce: nonce.to_vec(),
            signing_key_pair: signing_key_pair.bytes().to_vec(),
            encrypted_data,
            data_hash,
            sequence: self.next_sequence(),
            request_id: crypto::generate_uuid(),
            client_timestamp: js_sys::Date::now() as u64,
        };

        let c_hash = crypto::compute_hash(&postcard::to_allocvec(&capsule)?);

        // 手动构造返回对象，避免 serde_wasm_bindgen 序列化问题
        let obj = js_sys::Object::new();

        let capsule_value = serde_wasm_bindgen::to_value(&capsule)
            .map_err(|e| CryptoError::new(
                crate::errors::ErrorCode::SerdeError,
                &format!("Failed to serialize capsule: {:?}", e)
            ))?;
        js_sys::Reflect::set(&obj, &JsValue::from_str("capsule"), &capsule_value)
            .map_err(|_| CryptoError::new(crate::errors::ErrorCode::SerdeError, "Failed to set capsule"))?;

        let c_data_array = js_sys::Uint8Array::from(&c_data[..]);
        js_sys::Reflect::set(&obj, &JsValue::from_str("c_data"), &c_data_array)
            .map_err(|_| CryptoError::new(crate::errors::ErrorCode::SerdeError, "Failed to set c_data"))?;

        let c_hash_array = js_sys::Uint8Array::from(&c_hash[..]);
        js_sys::Reflect::set(&obj, &JsValue::from_str("c_hash"), &c_hash_array)
            .map_err(|_| CryptoError::new(crate::errors::ErrorCode::SerdeError, "Failed to set c_hash"))?;
        
        Ok(obj.into())
    }

    /// 解密数据
    pub fn get(
        &self,
        capsule: JsValue,
        private_key: &[u8],
        c_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        validation::validate_private_key(private_key, &self.i18n)?;

        let capsule =
            serde_wasm_bindgen::from_value::<Capsule>(capsule).map_err(|_| CryptoError::InvalidCapsule)?;

        validation::validate_version(capsule.version, 1, &self.i18n)?;

        let computed_hash = crypto::compute_hash(c_data);
        crypto::verify_mac(&computed_hash, &capsule.data_hash, &self.i18n)?;

        let private_key = PrivateKey::new_from_slice(private_key)?;
        let encrypted_values: EncryptedValue = postcard::from_bytes(&capsule.encrypted_data)?;

        let pt = self.recrypt.decrypt(encrypted_values, &private_key)?;
        let key = self.recrypt.derive_symmetric_key(&pt);
        let data = crypto::aes_decrypt(key.bytes(), &capsule.nonce, c_data, &self.i18n)?;

        Ok(data)
    }

    /// 恢复密钥对（无密码短语）
    pub fn recover(&self, mnemonic: String) -> Result<JsValue, CryptoError> {
        self.recover_with_passphrase(mnemonic, "")
    }

    /// 恢复密钥对（支持密码短语）
    #[wasm_bindgen(js_name = recoverWithPassphrase)]
    pub fn recover_with_passphrase(
        &self,
        mnemonic: String,
        passphrase: &str,
    ) -> Result<JsValue, CryptoError> {
        let keypair = keys::recover_keypair(&mnemonic, passphrase, &self.i18n)?;
        serde_wasm_bindgen::to_value(&keypair).map_err(CryptoError::SerdeWasmError)
    }

    /// 校验助记词
    pub fn check(&self, mnemonic: String) -> bool {
        Mnemonic::validate(&mnemonic, Language::English).is_ok()
    }

    /// 校验并标准化助记词
    #[wasm_bindgen(js_name = checkAndNormalize)]
    pub fn check_and_normalize(&self, mnemonic: &str) -> Result<String, CryptoError> {
        validation::check_and_normalize(mnemonic, &self.i18n)
    }

    /// 授权数据访问
    pub fn auth(
        &self,
        init_private_key: &[u8],
        target_public_key: &[u8],
        signing_key_pair: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let private_key = PrivateKey::new_from_slice(init_private_key)?;

        let recipient_public_key = {
            let public_key_tuple: ([u8; 32], [u8; 32]) = postcard::from_bytes(target_public_key)?;
            let pk = PublicKey::new(public_key_tuple)?;
            let verified_tuple = pk.bytes_x_y();
            if *verified_tuple.0 == [0u8; 32] && *verified_tuple.1 == [0u8; 32] {
                return Err(CryptoError::InvalidPublicKey);
            }

            pk
        };

        let signing_key_pair = SigningKeypair::from_byte_slice(signing_key_pair)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let cfrag = self.recrypt.generate_transform_key(
            &private_key,
            &recipient_public_key,
            &signing_key_pair,
        )?;
        let cfrag = postcard::to_allocvec(&cfrag)?;

        Ok(cfrag)
    }

    /// 使用授权解密数据
    #[wasm_bindgen(js_name = getByAuth)]
    pub fn get_by_auth(
        &self,
        capsule: JsValue,
        cfrag: &[u8],
        target_private_key: &[u8],
        c_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        validation::validate_private_key(target_private_key, &self.i18n)?;

        let capsule =
            serde_wasm_bindgen::from_value::<Capsule>(capsule).map_err(|_| CryptoError::InvalidCapsule)?;

        validation::validate_version(capsule.version, 1, &self.i18n)?;

        let computed_hash = crypto::compute_hash(c_data);
        crypto::verify_mac(&computed_hash, &capsule.data_hash, &self.i18n)?;

        let cfrag: TransformKey = postcard::from_bytes(cfrag)?;
        let private_key = PrivateKey::new_from_slice(target_private_key)?;

        let encrypted_values: EncryptedValue = postcard::from_bytes(&capsule.encrypted_data)?;

        let transformed = self.recrypt.transform(encrypted_values, cfrag, &signing_key_pair_from_bytes(&capsule.signing_key_pair)?)?;

        let pt = self.recrypt.decrypt(transformed, &private_key)?;
        let symmetric_key = self.recrypt.derive_symmetric_key(&pt);
        
        let data = crypto::aes_decrypt(symmetric_key.bytes(), &capsule.nonce, c_data, &self.i18n)?;

        Ok(data)
    }

    /// 创建 Keystore
    #[wasm_bindgen(js_name = createKeystore)]
    pub fn create_keystore(
        &self,
        keypair: JsValue,
        password: &str,
    ) -> Result<JsValue, CryptoError> {
        let keypair: KeypairResult =
            serde_wasm_bindgen::from_value(keypair).map_err(CryptoError::SerdeWasmError)?;

        let keystore = keystore::create_keystore(&keypair.private_key, password, &self.i18n)?;

        serde_wasm_bindgen::to_value(&keystore).map_err(CryptoError::SerdeWasmError)
    }

    /// 从 Keystore 恢复私钥
    #[wasm_bindgen(js_name = recoverFromKeystore)]
    pub fn recover_from_keystore(
        &self,
        keystore: JsValue,
        password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let keystore: Keystore =
            serde_wasm_bindgen::from_value(keystore).map_err(CryptoError::SerdeWasmError)?;

        keystore::recover_from_keystore(&keystore, password, &self.i18n)
    }

    /// 导出私钥（带警告）
    #[wasm_bindgen(js_name = exportPrivateKeyWithWarning)]
    pub fn export_private_key_with_warning(&self, keypair: JsValue) -> Result<JsValue, CryptoError> {
        let keypair: KeypairResult =
            serde_wasm_bindgen::from_value(keypair).map_err(CryptoError::SerdeWasmError)?;

        let warning = keys::export_private_key_with_warning(&keypair, &self.i18n);

        serde_wasm_bindgen::to_value(&warning).map_err(CryptoError::SerdeWasmError)
    }
}

// 辅助函数：从字节重建签名密钥对
fn signing_key_pair_from_bytes(bytes: &[u8]) -> Result<SigningKeypair, CryptoError> {
    SigningKeypair::from_byte_slice(bytes).map_err(|_| CryptoError::Ed25519Error)
}

