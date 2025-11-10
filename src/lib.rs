// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

mod crypto;
mod errors;
mod helpers;
mod i18n;
mod keys;
mod keystore;
mod serialization;
mod streaming;
mod types;
mod validation;

use bip39::{Language, Mnemonic};
use i18n::{I18n, Language as I18nLanguage};
use rand::Rng;
use recrypt::api::{
    CryptoOps, DefaultRng, Ed25519, Ed25519Ops, KeyGenOps, PrivateKey, PublicKey,
    RandomBytes, Recrypt, Sha256, SigningKeypair,
};
use serde_wasm_bindgen;
use std::cell::Cell;
use wasm_bindgen::prelude::*;

pub use errors::CryptoError;
pub use streaming::{EncryptedChunk, StreamDecryptor, StreamEncryptor, StreamMetadata};
pub use types::{Capsule, CryptoFunctionResult, ExportWarning, Keystore, KeypairResult};

#[wasm_bindgen]
pub struct EncryptSDK {
    recrypt: Recrypt<Sha256, Ed25519, RandomBytes<DefaultRng>>,
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
    
    /// Gets SDK version information
    #[wasm_bindgen(js_name = getVersion)]
    pub fn get_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    // ==================== Utility Methods ====================

    #[wasm_bindgen(js_name = validatePasswordStrength)]
    pub fn validate_password_strength(&self, password: &str) -> Result<(), CryptoError> {
        helpers::validate_password_strength(password, &self.i18n)
    }

    #[wasm_bindgen(js_name = hashData)]
    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        helpers::hash_data(data)
    }

    #[wasm_bindgen(js_name = generateRandomBytes)]
    pub fn generate_random_bytes(&self, length: usize) -> Vec<u8> {
        helpers::generate_random_bytes(length)
    }

    #[wasm_bindgen(js_name = validatePublicKey)]
    pub fn validate_public_key_js(&self, public_key: &[u8]) -> Result<(), CryptoError> {
        helpers::validate_public_key(public_key, &self.i18n)
    }

    #[wasm_bindgen(js_name = validatePrivateKey)]
    pub fn validate_private_key_js(&self, private_key: &[u8]) -> Result<(), CryptoError> {
        helpers::validate_private_key(private_key, &self.i18n)
    }

    #[wasm_bindgen(js_name = verifyKeypairMatch)]
    pub fn verify_keypair_match(&self, private_key: &[u8], public_key: &[u8]) -> Result<bool, CryptoError> {
        helpers::verify_keypair_match(private_key, public_key, &self.recrypt)
    }

    #[wasm_bindgen(js_name = derivePublicKey)]
    pub fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        helpers::derive_public_key(private_key, &self.recrypt)
    }

    #[wasm_bindgen(js_name = computeHmac)]
    pub fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        helpers::compute_hmac(key, data)
    }

    #[wasm_bindgen(js_name = verifyHmac)]
    pub fn verify_hmac(&self, key: &[u8], data: &[u8], expected_mac: &[u8]) -> bool {
        helpers::verify_hmac(key, data, expected_mac)
    }

    #[wasm_bindgen(js_name = generateUuid)]
    pub fn generate_uuid(&self) -> String {
        helpers::generate_uuid()
    }

    #[wasm_bindgen(js_name = bytesToHex)]
    pub fn bytes_to_hex(&self, bytes: &[u8]) -> String {
        helpers::bytes_to_hex(bytes)
    }

    #[wasm_bindgen(js_name = hexToBytes)]
    pub fn hex_to_bytes(&self, hex: &str) -> Result<Vec<u8>, CryptoError> {
        helpers::hex_to_bytes(hex)
    }
    
    // Private helpers
    
    fn next_iv(&self) -> [u8; 12] {
        crypto::generate_iv()
    }

    fn next_sequence(&self) -> u64 {
        let seq = self.sequence_counter.get();
        self.sequence_counter.set(seq.wrapping_add(1));
        seq
    }

    fn validate_and_parse_public_key(&self, public_key: &[u8]) -> Result<PublicKey, CryptoError> {
        validation::validate_data_not_empty(public_key, &self.i18n)?;
        validation::validate_public_key(public_key, &self.i18n)?;

        let key_tuple: ([u8; 32], [u8; 32]) = postcard::from_bytes(public_key)?;
        let pk = PublicKey::new(key_tuple)?;
        
        let tuple = pk.bytes_x_y();
        if *tuple.0 == [0u8; 32] && *tuple.1 == [0u8; 32] {
            return Err(CryptoError::InvalidPublicKey);
        }

        Ok(pk)
    }

    fn build_encrypted_result(&self, capsule: Capsule, c_data: Vec<u8>) -> Result<JsValue, CryptoError> {
        let c_hash = crypto::compute_hash(&postcard::to_allocvec(&capsule)?);
        let obj = js_sys::Object::new();

        let capsule_value = serde_wasm_bindgen::to_value(&capsule)?;
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

    // Core methods

    /// Generate new keypair with optional passphrase
    #[wasm_bindgen(js_name = generateKeypair)]
    pub fn generate_keypair(&self, passphrase: Option<String>) -> Result<JsValue, CryptoError> {
        let pass = passphrase.as_deref().unwrap_or("");
        let keypair = keys::generate_keypair(pass, &self.i18n)?;
        serde_wasm_bindgen::to_value(&keypair).map_err(CryptoError::SerdeWasmError)
    }


    /// Encrypts data using hybrid encryption (proxy re-encryption + AES-256-GCM)
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, data: &[u8], public_key: &[u8]) -> Result<JsValue, CryptoError> {
        validation::validate_data_not_empty(data, &self.i18n)?;
        let public_key = self.validate_and_parse_public_key(public_key)?;

        let signing_key_pair = self.recrypt.generate_ed25519_key_pair();
        let plaintext = self.recrypt.gen_plaintext();
        let encrypted_val = self.recrypt.encrypt(&plaintext, &public_key, &signing_key_pair)?;
        let symmetric_key = self.recrypt.derive_symmetric_key(&plaintext);

        let nonce = self.next_iv();
        let c_data = crypto::aes_encrypt(symmetric_key.bytes(), &nonce, data, &self.i18n)?;
        let data_hash = crypto::compute_hash(&c_data);

        let serializable_encrypted = serialization::SerializableEncryptedValue::from_encrypted_value(&encrypted_val)?;
        let encrypted_data = postcard::to_allocvec(&serializable_encrypted)?;
        
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

        self.build_encrypted_result(capsule, c_data)
    }

    /// Decrypts data encrypted to the user's public key
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(
        &self,
        capsule: JsValue,
        private_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        validation::validate_private_key(private_key, &self.i18n)?;

        let capsule = serde_wasm_bindgen::from_value::<Capsule>(capsule)
            .map_err(|_| CryptoError::InvalidCapsule)?;

        validation::validate_version(capsule.version, 1, &self.i18n)?;
        validation::validate_timestamp(capsule.client_timestamp, 86400, &self.i18n)?;
        validation::validate_request_id(&capsule.request_id, &self.i18n)?;
        
        let computed_hash = crypto::compute_hash(ciphertext);
        crypto::verify_mac(&computed_hash, &capsule.data_hash, &self.i18n)?;

        let private_key = PrivateKey::new_from_slice(private_key)?;
        let serializable_encrypted: serialization::SerializableEncryptedValue = 
            postcard::from_bytes(&capsule.encrypted_data)?;
        let encrypted_values = serializable_encrypted.to_encrypted_value()?;

        let pt = self.recrypt.decrypt(encrypted_values, &private_key)?;
        let key = self.recrypt.derive_symmetric_key(&pt);
        
        crypto::aes_decrypt(key.bytes(), &capsule.nonce, ciphertext, &self.i18n)
    }

    /// Recover keypair from BIP39 mnemonic phrase with optional passphrase
    #[wasm_bindgen(js_name = recoverKeypair)]
    pub fn recover_keypair(&self, mnemonic: String, passphrase: Option<String>) -> Result<JsValue, CryptoError> {
        let pass = passphrase.as_deref().unwrap_or("");
        let keypair = keys::recover_keypair(&mnemonic, pass, &self.i18n)?;
        serde_wasm_bindgen::to_value(&keypair).map_err(CryptoError::SerdeWasmError)
    }

    /// Validate BIP39 mnemonic phrase
    #[wasm_bindgen(js_name = validateMnemonic)]
    pub fn validate_mnemonic(&self, mnemonic: String) -> bool {
        Mnemonic::parse_in(Language::English, &mnemonic).is_ok()
    }

    /// Validate and normalize BIP39 mnemonic phrase (lowercase, trim whitespace)
    #[wasm_bindgen(js_name = validateAndNormalizeMnemonic)]
    pub fn validate_and_normalize_mnemonic(&self, mnemonic: &str) -> Result<String, CryptoError> {
        validation::check_and_normalize(mnemonic, &self.i18n)
    }

    // Proxy re-encryption
    
    /// Generates transform key for delegated access (placeholder - requires server)
    #[wasm_bindgen(js_name = generateTransformKey)]
    pub fn generate_transform_key(
        &self,
        delegator_private_key: &[u8],
        delegatee_public_key: &[u8],
        signing_key_pair: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let private_key = PrivateKey::new_from_slice(delegator_private_key)?;
        let recipient_public_key = self.validate_and_parse_public_key(delegatee_public_key)?;
        let signing_key_pair = SigningKeypair::from_byte_slice(signing_key_pair)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        
        let _cfrag = self.recrypt.generate_transform_key(&private_key, &recipient_public_key, &signing_key_pair)?;
        
        let placeholder = serialization::SerializableTransformKey::placeholder();
        postcard::to_allocvec(&placeholder).map_err(Into::into)
    }

    /// Decrypts with transform key (not implemented - requires server)
    #[wasm_bindgen(js_name = decryptDelegated)]
    pub fn decrypt_delegated(
        &self,
        capsule: JsValue,
        _transform_key: &[u8],
        _delegatee_private_key: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let _capsule = serde_wasm_bindgen::from_value::<Capsule>(capsule)
            .map_err(|_| CryptoError::InvalidCapsule)?;
        
        Err(CryptoError::new(
            crate::errors::ErrorCode::NotImplemented,
            "Requires server-side proxy. See service/transform/"
        ))
    }

    /// Creates encrypted keystore (PBKDF2 600k iterations + AES-256-GCM)
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

    /// Unlocks keystore and recovers private key
    #[wasm_bindgen(js_name = unlockKeystore)]
    pub fn unlock_keystore(
        &self,
        keystore: JsValue,
        password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let keystore: Keystore =
            serde_wasm_bindgen::from_value(keystore).map_err(CryptoError::SerdeWasmError)?;

        keystore::recover_from_keystore(&keystore, password, &self.i18n)
    }

    /// Recovers full keypair from keystore (mnemonic will be empty)
    #[wasm_bindgen(js_name = recoverKeypairFromKeystore)]
    pub fn recover_keypair_from_keystore(
        &self,
        keystore: JsValue,
        password: &str,
    ) -> Result<JsValue, CryptoError> {
        let private_key = self.unlock_keystore(keystore, password)?;
        let public_key = self.derive_public_key(&private_key)?;
        
        let keypair = KeypairResult {
            private_key,
            public_key,
            mnemonic: String::from(""),
        };
        
        serde_wasm_bindgen::to_value(&keypair).map_err(CryptoError::SerdeWasmError)
    }

    /// Reconstructs keypair from private key (mnemonic will be empty)
    #[wasm_bindgen(js_name = reconstructKeypair)]
    pub fn reconstruct_keypair(&self, private_key: &[u8]) -> Result<JsValue, CryptoError> {
        validation::validate_private_key(private_key, &self.i18n)?;
        let public_key = self.derive_public_key(private_key)?;
        
        let keypair = KeypairResult {
            private_key: private_key.to_vec(),
            public_key,
            mnemonic: String::from(""),
        };
        
        serde_wasm_bindgen::to_value(&keypair).map_err(CryptoError::SerdeWasmError)
    }

    /// Recover private key from keystore
    /// @deprecated Use unlockKeystore() instead
    #[wasm_bindgen(js_name = recoverFromKeystore)]
    #[deprecated(since = "0.3.0", note = "Use unlockKeystore() instead")]
    #[allow(deprecated)]
    pub fn recover_from_keystore(
        &self,
        keystore: JsValue,
        password: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        self.unlock_keystore(keystore, password)
    }

    /// Exports private key with warnings (⚠️ dangerous!)
    #[wasm_bindgen(js_name = exportPrivateKey)]
    pub fn export_private_key(&self, keypair: JsValue) -> Result<JsValue, CryptoError> {
        let keypair: KeypairResult =
            serde_wasm_bindgen::from_value(keypair).map_err(CryptoError::SerdeWasmError)?;

        let warning = keys::export_private_key_with_warning(&keypair, &self.i18n);

        serde_wasm_bindgen::to_value(&warning).map_err(CryptoError::SerdeWasmError)
    }

    /// Serializes capsule to bytes
    #[wasm_bindgen(js_name = serializeCapsule)]
    pub fn serialize_capsule(&self, capsule: JsValue) -> Result<Vec<u8>, CryptoError> {
        helpers::serialize_capsule(capsule)
    }

    /// Deserializes bytes to capsule
    #[wasm_bindgen(js_name = deserializeCapsule)]
    pub fn deserialize_capsule(&self, bytes: &[u8]) -> Result<JsValue, CryptoError> {
        helpers::deserialize_capsule(bytes)
    }
}

