// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use thiserror::Error;
use recrypt::api::RecryptErr;
use wasm_bindgen::prelude::*;

/// 错误码（用于国际化）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorCode {
    // 加密相关
    RecryptError = 1000,
    AesError = 1001,
    DecryptionError = 1002,
    
    // 密钥相关
    InvalidPrivateKey = 2000,
    InvalidPublicKey = 2001,
    KeyDerivationError = 2002,
    
    // 助记词相关
    BIP39Error = 3000,
    InvalidMnemonic = 3001,
    
    // 数据格式
    PostcardError = 4000,
    SerdeWasmError = 4001,
    SerdeError = 4002,
    InvalidCapsule = 4003,
    InvalidCfrag = 4004,
    
    // 签名
    Ed25519Error = 5000,
    
    // 完整性
    IntegrityCheckFailed = 6000,
    
    // KDF
    InvalidKdfParams = 7000,
    
    // 密码
    WeakPassword = 8000,
    
    // 输入验证
    InvalidInput = 9000,
    
    // 版本
    UnsupportedVersion = 10000,
    
    // IV
    InvalidIV = 11000,
}

/// 错误类型
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
            Self::SerdeError(_) => Some(ErrorCode::SerdeError),
            Self::InvalidPrivateKey => Some(ErrorCode::InvalidPrivateKey),
            Self::InvalidPublicKey => Some(ErrorCode::InvalidPublicKey),
            Self::InvalidCapsule => Some(ErrorCode::InvalidCapsule),
            Self::Ed25519Error => Some(ErrorCode::Ed25519Error),
        }
    }
}

/// 转换为 JsValue（用于 WASM）
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

