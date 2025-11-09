// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Keypair generation result containing keys and recovery mnemonic.
///
/// All sensitive fields are automatically zeroized when dropped to prevent
/// memory disclosure attacks. This is critical for security as private keys
/// and mnemonics must not remain in memory longer than necessary.
#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeypairResult {
    /// Private key bytes (32 bytes for elliptic curve)
    pub private_key: Vec<u8>,
    /// Serialized public key (64 bytes: x and y coordinates)
    pub public_key: Vec<u8>,
    /// BIP39 mnemonic phrase for key recovery
    pub mnemonic: String,
}

/// 加密函数结果
#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoFunctionResult {
    pub capsule: Capsule,
    pub c_data: Vec<u8>,
    pub c_hash: Vec<u8>,
}

/// Capsule containing metadata for proxy re-encryption.
///
/// The capsule stores all necessary information to decrypt or re-encrypt data,
/// including the encrypted plaintext value, signing keys for authentication,
/// and integrity protection via hash. This follows the proxy re-encryption
/// pattern where the capsule can be transformed without exposing the plaintext.
#[derive(Serialize, Deserialize, Clone)]
pub struct Capsule {
    /// Protocol version for forward compatibility
    pub version: u8,
    /// Nonce/IV for AES-GCM (12 bytes)
    pub nonce: Vec<u8>,
    /// Ed25519 signing keypair for authenticated encryption
    pub signing_key_pair: Vec<u8>,
    /// Serialized EncryptedValue from recrypt library
    pub encrypted_data: Vec<u8>,
    /// SHA-256 hash of ciphertext for integrity verification
    pub data_hash: Vec<u8>,
    /// Monotonic sequence number for replay protection
    #[serde(with = "u64_as_string")]
    pub sequence: u64,
    /// Unique request identifier for auditing
    pub request_id: String,
    /// Client timestamp (milliseconds since epoch)
    #[serde(with = "u64_as_string")]
    pub client_timestamp: u64,
}

/// Serialize u64 as string to prevent precision loss in JavaScript.
///
/// JavaScript's Number type can only safely represent integers up to 2^53-1.
/// Since u64 can exceed this (up to 2^64-1), we serialize as string to
/// preserve exact values when passing data to/from WebAssembly.
mod u64_as_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Keystore structure for encrypted private key storage.
///
/// Compatible with Web3 keystore format (JSON) for interoperability.
/// Uses password-based encryption with PBKDF2 and AES-256-GCM.
#[derive(Serialize, Deserialize)]
pub struct Keystore {
    /// Keystore format version
    pub version: u8,
    /// Cryptographic parameters and encrypted data
    pub crypto: KeystoreCrypto,
}

/// Cryptographic parameters for keystore encryption.
#[derive(Serialize, Deserialize)]
pub struct KeystoreCrypto {
    /// Cipher algorithm (e.g., "aes-256-gcm")
    pub cipher: String,
    /// Encrypted private key
    pub ciphertext: Vec<u8>,
    /// Cipher-specific parameters
    pub cipherparams: CipherParams,
    /// Key derivation function (e.g., "pbkdf2-hmac-sha256")
    pub kdf: String,
    /// KDF parameters
    pub kdfparams: KdfParams,
    /// Message authentication code for integrity verification
    pub mac: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct CipherParams {
    /// Initialization vector for AES
    pub iv: Vec<u8>,
}

/// Key derivation function parameters.
#[derive(Serialize, Deserialize)]
pub struct KdfParams {
    /// Derived key length in bytes
    pub dklen: u32,
    /// Number of iterations (n parameter for PBKDF2)
    pub n: u32,
    /// Parallelization parameter (unused in PBKDF2, kept for compatibility)
    pub p: u32,
    /// Block size parameter (unused in PBKDF2, kept for compatibility)
    pub r: u32,
    /// Random salt for key derivation
    pub salt: [u8; 16],
}

/// 私钥导出警告结构
#[derive(Serialize)]
pub struct ExportWarning {
    pub warning: String,
    pub private_key: Vec<u8>,
    pub safety_tips: Vec<String>,
}

