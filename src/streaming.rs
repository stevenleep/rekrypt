// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

//! Streaming encryption/decryption for large files (chunked processing)

use crate::crypto;
use crate::errors::{CryptoError, ErrorCode};
use crate::i18n::I18n;
use crate::validation;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Default chunk size: 1MB
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Streaming encryption context
#[wasm_bindgen]
pub struct StreamEncryptor {
    key: Vec<u8>,
    chunk_size: usize,
    chunk_index: u64,
    i18n: I18n,
}

/// Streaming decryption context
#[wasm_bindgen]
pub struct StreamDecryptor {
    key: Vec<u8>,
    #[allow(dead_code)]
    chunk_size: usize,
    chunk_index: u64,
    i18n: I18n,
}

/// Metadata for streaming encryption
#[derive(Serialize, Deserialize, Clone)]
pub struct StreamMetadata {
    pub version: u8,
    pub chunk_size: usize,
    pub total_chunks: u64,
    pub total_size: u64,
    pub file_hash: Vec<u8>,
}

/// Result of encrypting a single chunk
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedChunk {
    pub chunk_index: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub chunk_hash: Vec<u8>,
}

#[wasm_bindgen]
impl StreamEncryptor {
    /// Creates new stream encryptor (default 1MB chunks)
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], chunk_size: Option<usize>) -> Result<StreamEncryptor, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::new(
                ErrorCode::InvalidInput,
                "Key must be 32 bytes for AES-256"
            ));
        }

        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        if chunk_size == 0 || chunk_size > 10 * 1024 * 1024 {
            return Err(CryptoError::new(
                ErrorCode::InvalidInput,
                "Chunk size must be between 1 byte and 10MB"
            ));
        }

        Ok(Self {
            key: key.to_vec(),
            chunk_size,
            chunk_index: 0,
            i18n: I18n::default(),
        })
    }

    /// Encrypts a chunk
    #[wasm_bindgen(js_name = encryptChunk)]
    pub fn encrypt_chunk(&mut self, chunk_data: &[u8]) -> Result<JsValue, CryptoError> {
        validation::validate_data_not_empty(chunk_data, &self.i18n)?;

        if chunk_data.len() > self.chunk_size {
            return Err(CryptoError::new(
                ErrorCode::InvalidInput,
                &format!("Chunk exceeds max {}", self.chunk_size)
            ));
        }

        let nonce = crypto::generate_iv();
        let ciphertext = crypto::aes_encrypt(&self.key, &nonce, chunk_data, &self.i18n)?;
        let chunk_hash = crypto::compute_hash(&ciphertext);

        let encrypted_chunk = EncryptedChunk {
            chunk_index: self.chunk_index,
            nonce: nonce.to_vec(),
            ciphertext,
            chunk_hash,
        };

        self.chunk_index += 1;

        serde_wasm_bindgen::to_value(&encrypted_chunk)
            .map_err(CryptoError::SerdeWasmError)
    }

    #[wasm_bindgen(js_name = reset)]
    pub fn reset(&mut self) {
        self.chunk_index = 0;
    }

    #[wasm_bindgen(js_name = getChunkIndex)]
    pub fn get_chunk_index(&self) -> u64 {
        self.chunk_index
    }
}

#[wasm_bindgen]
impl StreamDecryptor {
    /// Creates new stream decryptor
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], chunk_size: Option<usize>) -> Result<StreamDecryptor, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::new(
                ErrorCode::InvalidInput,
                "Key must be 32 bytes for AES-256"
            ));
        }

        let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

        Ok(Self {
            key: key.to_vec(),
            chunk_size,
            chunk_index: 0,
            i18n: I18n::default(),
        })
    }

    /// Decrypts a chunk
    #[wasm_bindgen(js_name = decryptChunk)]
    pub fn decrypt_chunk(&mut self, encrypted_chunk: JsValue) -> Result<Vec<u8>, CryptoError> {
        let chunk: EncryptedChunk = serde_wasm_bindgen::from_value(encrypted_chunk)?;

        if chunk.chunk_index != self.chunk_index {
            return Err(CryptoError::new(
                ErrorCode::InvalidInput,
                &format!("Index mismatch: expected {}, got {}", self.chunk_index, chunk.chunk_index)
            ));
        }

        let computed_hash = crypto::compute_hash(&chunk.ciphertext);
        crypto::verify_mac(&computed_hash, &chunk.chunk_hash, &self.i18n)?;
        validation::validate_iv(&chunk.nonce, &self.i18n)?;

        let plaintext = crypto::aes_decrypt(
            &self.key,
            &chunk.nonce,
            &chunk.ciphertext,
            &self.i18n
        )?;

        self.chunk_index += 1;

        Ok(plaintext)
    }

    #[wasm_bindgen(js_name = reset)]
    pub fn reset(&mut self) {
        self.chunk_index = 0;
    }

    #[wasm_bindgen(js_name = getChunkIndex)]
    pub fn get_chunk_index(&self) -> u64 {
        self.chunk_index
    }
}

