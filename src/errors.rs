// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

//! Error types and codes

use thiserror::Error;
use recrypt::api::RecryptErr;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorCode {
    RecryptError = 1000,
    AesError = 1001,
    DecryptionError = 1002,
    InvalidPrivateKey = 2000,
    InvalidPublicKey = 2001,
    KeyDerivationError = 2002,
    BIP39Error = 3000,
    InvalidMnemonic = 3001,
    PostcardError = 4000,
    SerdeWasmError = 4001,
    SerdeError = 4002,
    InvalidCapsule = 4003,
    InvalidCfrag = 4004,
    Ed25519Error = 5000,
    IntegrityCheckFailed = 6000,
    InvalidKdfParams = 7000,
    WeakPassword = 8000,
    InvalidInput = 9000,
    UnsupportedVersion = 10000,
    InvalidIV = 11000,
    NotImplemented = 12000,
    InvalidData = 13000,
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Error {code:?}: {message}")]
    WithCode {
        code: ErrorCode,
        message: String,
    },
    
    #[error("Recrypt error")]
    RecryptError(#[from] RecryptErr),
    
    #[error("BIP39 error")]
    BIP39Error(#[from] bip39::Error),
    
    #[error("Postcard error")]
    PostcardError(#[from] postcard::Error),
    
    #[error("Serde WASM error")]
    SerdeWasmError(#[from] serde_wasm_bindgen::Error),
    
    #[error("Serde JSON error")]
    SerdeError(#[from] serde_json::Error),
    
    #[error("Invalid private key")]
    InvalidPrivateKey,
    
    #[error("Invalid public key")]
    InvalidPublicKey,
    
    #[error("Invalid capsule")]
    InvalidCapsule,
    
    #[error("Invalid data format")]
    InvalidData,
    
    #[error("Ed25519 error")]
    Ed25519Error,
}

impl CryptoError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::WithCode {
            code,
            message: message.into(),
        }
    }
    
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::WithCode { code, .. } => Some(*code),
            Self::RecryptError(_) => Some(ErrorCode::RecryptError),
            Self::BIP39Error(_) => Some(ErrorCode::BIP39Error),
            Self::PostcardError(_) => Some(ErrorCode::PostcardError),
            Self::SerdeWasmError(_) => Some(ErrorCode::SerdeWasmError),
            Self::InvalidData => Some(ErrorCode::InvalidData),
            Self::SerdeError(_) => Some(ErrorCode::SerdeError),
            Self::InvalidPrivateKey => Some(ErrorCode::InvalidPrivateKey),
            Self::InvalidPublicKey => Some(ErrorCode::InvalidPublicKey),
            Self::InvalidCapsule => Some(ErrorCode::InvalidCapsule),
            Self::Ed25519Error => Some(ErrorCode::Ed25519Error),
        }
    }
}

impl From<CryptoError> for JsValue {
    fn from(error: CryptoError) -> Self {
        #[cfg(debug_assertions)]
        {
            JsValue::from_str(&format!("[DEBUG] {:?}", error))
        }
        #[cfg(not(debug_assertions))]
        {
            if let Some(code) = error.code() {
                JsValue::from_str(&format!("Error {}: {}", code as u32, error))
            } else {
                JsValue::from_str(&error.to_string())
            }
        }
    }
}

