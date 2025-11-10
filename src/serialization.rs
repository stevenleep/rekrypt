// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

//! Serialization adapters for recrypt library types
//!
//! Provides safe serialization wrappers using recrypt's public API

use crate::errors::CryptoError;
use recrypt::api::{
    AuthHash, Ed25519Signature, EncryptedMessage, EncryptedValue, PublicKey, PublicSigningKey,
};
use serde::{Deserialize, Serialize};

/// Serializable representation of EncryptedValue
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableEncryptedValue {
    pub variant: u8,                     // 0 = EncryptedOnceValue, 1 = TransformedValue
    pub ephemeral_public_key_x: Vec<u8>, // 32 bytes
    pub ephemeral_public_key_y: Vec<u8>, // 32 bytes
    pub encrypted_message: Vec<u8>,      // 384 bytes
    pub auth_hash: Vec<u8>,              // 128 bytes
    pub public_signing_key: Vec<u8>,     // 32 bytes
    pub signature: Vec<u8>,              // 64 bytes
    pub transform_blocks: Option<Vec<u8>>,
}

impl SerializableEncryptedValue {
    /// Creates from EncryptedValue using public API
    pub fn from_encrypted_value(value: &EncryptedValue) -> Result<Self, CryptoError> {
        match value {
            EncryptedValue::EncryptedOnceValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
                public_signing_key,
                signature,
            } => {
                let (x, y) = ephemeral_public_key.bytes_x_y();

                Ok(Self {
                    variant: 0,
                    ephemeral_public_key_x: x.to_vec(),
                    ephemeral_public_key_y: y.to_vec(),
                    encrypted_message: encrypted_message.bytes().to_vec(),
                    auth_hash: auth_hash.bytes().to_vec(),
                    public_signing_key: public_signing_key.bytes().to_vec(),
                    signature: signature.bytes().to_vec(),
                    transform_blocks: None,
                })
            }
            EncryptedValue::TransformedValue { .. } => Err(CryptoError::InvalidData),
        }
    }

    /// Converts back to EncryptedValue
    pub fn to_encrypted_value(&self) -> Result<EncryptedValue, CryptoError> {
        if self.variant != 0 {
            return Err(CryptoError::InvalidData);
        }

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&self.ephemeral_public_key_x);
        y.copy_from_slice(&self.ephemeral_public_key_y);
        let ephemeral_public_key = PublicKey::new((x, y))?;

        if self.encrypted_message.len() != 384 {
            return Err(CryptoError::InvalidData);
        }
        let encrypted_message = EncryptedMessage::new_from_slice(&self.encrypted_message)?;

        if self.auth_hash.len() != 128 {
            return Err(CryptoError::InvalidData);
        }
        let auth_hash = AuthHash::new_from_slice(&self.auth_hash)?;

        if self.public_signing_key.len() != 32 {
            return Err(CryptoError::InvalidData);
        }
        let mut psk_bytes = [0u8; 32];
        psk_bytes.copy_from_slice(&self.public_signing_key);
        let public_signing_key = PublicSigningKey::new_from_slice(&psk_bytes)?;

        if self.signature.len() != 64 {
            return Err(CryptoError::InvalidData);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let signature = Ed25519Signature::new_from_slice(&sig_bytes)?;

        Ok(EncryptedValue::EncryptedOnceValue {
            ephemeral_public_key,
            encrypted_message,
            auth_hash,
            public_signing_key,
            signature,
        })
    }
}

use recrypt::api::{EncryptedTempKey, HashedValue, TransformKey};

/// Serializable representation of TransformKey
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableTransformKey {
    pub ephemeral_public_key_x: Vec<u8>, // 32 bytes
    pub ephemeral_public_key_y: Vec<u8>, // 32 bytes
    pub to_public_key_x: Vec<u8>,        // 32 bytes
    pub to_public_key_y: Vec<u8>,        // 32 bytes
    pub encrypted_temp_key: Vec<u8>,     // 384 bytes
    pub hashed_temp_key: Vec<u8>,        // 128 bytes
    pub public_signing_key: Vec<u8>,     // 32 bytes
    pub signature: Vec<u8>,              // 64 bytes
}

impl SerializableTransformKey {
    /// Creates from TransformKey using public API
    pub fn from_transform_key(tk: &TransformKey) -> Result<Self, CryptoError> {
        let (ephem_x, ephem_y) = tk.ephemeral_public_key().bytes_x_y();
        let (to_x, to_y) = tk.to_public_key().bytes_x_y();

        Ok(Self {
            ephemeral_public_key_x: ephem_x.to_vec(),
            ephemeral_public_key_y: ephem_y.to_vec(),
            to_public_key_x: to_x.to_vec(),
            to_public_key_y: to_y.to_vec(),
            encrypted_temp_key: tk.encrypted_temp_key().bytes().to_vec(),
            hashed_temp_key: tk.hashed_temp_key().bytes().to_vec(),
            public_signing_key: tk.public_signing_key().bytes().to_vec(),
            signature: tk.signature().bytes().to_vec(),
        })
    }

    /// Converts back to TransformKey
    pub fn to_transform_key(&self) -> Result<TransformKey, CryptoError> {
        // Reconstruct PublicKeys
        let mut ephem_x = [0u8; 32];
        let mut ephem_y = [0u8; 32];
        ephem_x.copy_from_slice(&self.ephemeral_public_key_x);
        ephem_y.copy_from_slice(&self.ephemeral_public_key_y);
        let ephemeral_public_key = PublicKey::new((ephem_x, ephem_y))?;

        let mut to_x = [0u8; 32];
        let mut to_y = [0u8; 32];
        to_x.copy_from_slice(&self.to_public_key_x);
        to_y.copy_from_slice(&self.to_public_key_y);
        let to_public_key = PublicKey::new((to_x, to_y))?;

        // Reconstruct EncryptedTempKey (384 bytes)
        if self.encrypted_temp_key.len() != 384 {
            return Err(CryptoError::InvalidData);
        }
        let mut etk_bytes = [0u8; 384];
        etk_bytes.copy_from_slice(&self.encrypted_temp_key);
        let encrypted_temp_key = EncryptedTempKey::new(etk_bytes);

        // Reconstruct HashedValue (128 bytes)
        if self.hashed_temp_key.len() != 128 {
            return Err(CryptoError::InvalidData);
        }
        let mut hv_bytes = [0u8; 128];
        hv_bytes.copy_from_slice(&self.hashed_temp_key);
        let hashed_temp_key = HashedValue::new(hv_bytes)?;

        // Reconstruct PublicSigningKey (32 bytes)
        if self.public_signing_key.len() != 32 {
            return Err(CryptoError::InvalidData);
        }
        let mut psk_bytes = [0u8; 32];
        psk_bytes.copy_from_slice(&self.public_signing_key);
        let public_signing_key = PublicSigningKey::new_from_slice(&psk_bytes)?;

        // Reconstruct Ed25519Signature (64 bytes)
        if self.signature.len() != 64 {
            return Err(CryptoError::InvalidData);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let signature = Ed25519Signature::new_from_slice(&sig_bytes)?;

        // Reconstruct TransformKey using public constructor
        Ok(TransformKey::new(
            ephemeral_public_key,
            to_public_key,
            encrypted_temp_key,
            hashed_temp_key,
            public_signing_key,
            signature,
        ))
    }

    pub fn placeholder() -> Self {
        Self {
            ephemeral_public_key_x: vec![0; 32],
            ephemeral_public_key_y: vec![0; 32],
            to_public_key_x: vec![0; 32],
            to_public_key_y: vec![0; 32],
            encrypted_temp_key: vec![0; 384],
            hashed_temp_key: vec![0; 128],
            public_signing_key: vec![0; 32],
            signature: vec![0; 64],
        }
    }
}
