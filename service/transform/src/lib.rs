// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

use recrypt::api::{CryptoOps, DefaultRng, Ed25519, EncryptedValue, Recrypt, Sha256, SigningKeypair, TransformKey};
use serde::{Deserialize, Serialize};
use std::slice;

/// Capsule 结构，与客户端的 Capsule 保持一致
#[derive(Serialize, Deserialize, Clone)]
pub struct Capsule {
    pub version: u8,
    pub nonce: Vec<u8>,
    pub signing_key_pair: Vec<u8>,
    pub encrypted_data: Vec<u8>,  // 这是序列化的 EncryptedValue
    pub data_hash: Vec<u8>,
    pub sequence: String,  // 序列化为字符串以兼容 JS
    pub request_id: String,
    pub client_timestamp: String,
}

/// FFI 函数：执行代理重加密转换
/// 
/// # 参数
/// - capsule_ptr: 序列化的 **Capsule** 指针（不是 EncryptedValue！）
/// - capsule_len: capsule 长度
/// - transform_key_ptr: 序列化的 TransformKey 指针
/// - transform_key_len: transform_key 长度
/// - out_ptr: 输出缓冲区指针（用于返回转换后的 Capsule）
/// - out_len: 输出缓冲区长度
/// 
/// # 返回
/// - 成功: 转换后的数据长度
/// - 失败: 负数错误码
#[no_mangle]
pub extern "C" fn transform(
    capsule_ptr: *const u8,
    capsule_len: usize,
    transform_key_ptr: *const u8,
    transform_key_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    // 转换指针为切片
    let capsule_bytes = unsafe { slice::from_raw_parts(capsule_ptr, capsule_len) };
    let transform_key_bytes = unsafe { slice::from_raw_parts(transform_key_ptr, transform_key_len) };

    // 1. 反序列化 Capsule（客户端传来的完整 Capsule 对象）
    let mut capsule: Capsule = match postcard::from_bytes(capsule_bytes) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    // 2. 从 Capsule 中提取并反序列化 EncryptedValue
    let encrypted_value: EncryptedValue = match postcard::from_bytes(&capsule.encrypted_data) {
        Ok(v) => v,
        Err(_) => return -2,
    };

    // 3. 反序列化 TransformKey
    let transform_key: TransformKey = match postcard::from_bytes(transform_key_bytes) {
        Ok(tk) => tk,
        Err(_) => return -3,
    };

    // 4. 从 Capsule 中获取 SigningKeypair
    let signing_keypair: SigningKeypair = match SigningKeypair::from_byte_slice(&capsule.signing_key_pair) {
        Ok(sk) => sk,
        Err(_) => return -4,
    };

    // 5. 执行转换
    let recrypt = Recrypt::<Sha256, Ed25519, recrypt::api::RandomBytes<DefaultRng>>::new();
    let transformed_value = match recrypt.transform(encrypted_value, transform_key, &signing_keypair) {
        Ok(t) => t,
        Err(_) => return -5,
    };

    // 6. 序列化转换后的 EncryptedValue
    let transformed_encrypted_data = match postcard::to_allocvec(&transformed_value) {
        Ok(s) => s,
        Err(_) => return -6,
    };

    // 7. 更新 Capsule 中的 encrypted_data
    capsule.encrypted_data = transformed_encrypted_data;

    // 8. 序列化完整的 Capsule（包含转换后的 encrypted_data）
    let serialized_capsule = match postcard::to_allocvec(&capsule) {
        Ok(s) => s,
        Err(_) => return -7,
    };

    // 9. 检查输出缓冲区大小
    if serialized_capsule.len() > out_len {
        return -8;
    }

    // 10. 复制到输出缓冲区
    let out_slice = unsafe { slice::from_raw_parts_mut(out_ptr, out_len) };
    out_slice[..serialized_capsule.len()].copy_from_slice(&serialized_capsule);

    serialized_capsule.len() as i32
}

/// 获取建议的输出缓冲区大小
#[no_mangle]
pub extern "C" fn get_output_buffer_size() -> usize {
    // Capsule 包含多个字段，预留 8KB
    8192
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_basic() {
        assert_eq!(get_output_buffer_size(), 8192);
    }
}
