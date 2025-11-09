use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// 密钥对结果
/// 使用 Zeroize derive 自动在 drop 时清零所有敏感字段
#[derive(Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeypairResult {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub mnemonic: String,
}

/// 加密函数结果
#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoFunctionResult {
    pub capsule: Capsule,
    pub c_data: Vec<u8>,
    pub c_hash: Vec<u8>,
}

/// 封装胶囊数据
#[derive(Serialize, Deserialize, Clone)]
pub struct Capsule {
    pub version: u8,
    pub nonce: Vec<u8>,
    pub signing_key_pair: Vec<u8>,
    pub encrypted_data: Vec<u8>,
    pub data_hash: Vec<u8>,
    #[serde(with = "u64_as_string")]
    pub sequence: u64,
    pub request_id: String,
    #[serde(with = "u64_as_string")]
    pub client_timestamp: u64,
}

// u64 序列化为字符串（避免 JavaScript 精度丢失）
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

/// Keystore 结构
#[derive(Serialize, Deserialize)]
pub struct Keystore {
    pub version: u8,
    pub crypto: KeystoreCrypto,
}

#[derive(Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub cipher: String,
    pub ciphertext: Vec<u8>,
    pub cipherparams: CipherParams,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KdfParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: [u8; 16],
}

/// 私钥导出警告结构
#[derive(Serialize)]
pub struct ExportWarning {
    pub warning: String,
    pub private_key: Vec<u8>,
    pub safety_tips: Vec<String>,
}

