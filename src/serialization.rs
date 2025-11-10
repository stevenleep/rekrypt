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
    pub variant: u8,  // 0 = EncryptedOnceValue, 1 = TransformedValue
    pub ephemeral_public_key_x: Vec<u8>,  // 32 bytes
    pub ephemeral_public_key_y: Vec<u8>,  // 32 bytes
    pub encrypted_message: Vec<u8>,       // 384 bytes
    pub auth_hash: Vec<u8>,               // 128 bytes
    pub public_signing_key: Vec<u8>,      // 32 bytes
    pub signature: Vec<u8>,               // 64 bytes
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

/// Placeholder for TransformKey (cannot be serialized)
#[derive(Serialize, Deserialize, Clone)]
pub struct SerializableTransformKey {
    pub opaque_data: Vec<u8>,
}

impl SerializableTransformKey {
    pub fn placeholder() -> Self {
        Self { opaque_data: Vec::new() }
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { opaque_data: bytes }
    }

    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.opaque_data
    }
}
