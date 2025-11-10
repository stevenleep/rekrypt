// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 stenvenleep

//! Internationalization support

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    ZhCN,
    EnUS,
}

impl Default for Language {
    fn default() -> Self {
        Self::EnUS
    }
}

pub struct I18n {
    lang: Language,
}

impl I18n {
    pub fn new(lang: Language) -> Self {
        Self { lang }
    }
    
    pub fn error_msg(&self, key: &str) -> &'static str {
        match self.lang {
            Language::ZhCN => self.error_msg_zh(key),
            Language::EnUS => self.error_msg_en(key),
        }
    }
    
    fn error_msg_zh(&self, key: &str) -> &'static str {
        match key {
            // 加密相关
            "recrypt_error" => "加密操作失败",
            "aes_error" => "加密失败",
            "decryption_error" => "解密失败",
            
            // 密钥相关
            "invalid_private_key" => "无效的私钥",
            "invalid_public_key" => "无效的公钥",
            "key_derivation_error" => "密钥派生失败",
            
            // 助记词
            "bip39_error" => "助记词格式错误",
            "invalid_mnemonic" => "无效的助记词",
            
            // 数据格式
            "data_format_error" => "数据格式错误",
            "serialization_error" => "序列化错误",
            "invalid_capsule" => "无效的数据",
            "invalid_cfrag" => "无效的授权",
            
            // 签名
            "ed25519_error" => "签名验证失败",
            
            // 完整性
            "integrity_check_failed" => "数据完整性验证失败",
            
            // KDF
            "invalid_kdf_params" => "无效的 KDF 参数",
            
            // 密码
            "weak_password" => "密码强度不足",
            "password_too_short" => "密码至少需要 12 个字符",
            "password_too_long" => "密码过长（最大 128 字符）",
            "password_complexity" => "密码必须包含至少 3 种：小写字母、大写字母、数字、特殊字符",
            
            // 输入验证
            "invalid_input" => "输入无效",
            "data_empty" => "数据不能为空",
            "data_too_large" => "数据过大",
            "timestamp_future" => "时间戳不能超前当前时间",
            "timestamp_too_old" => "时间戳过期",
            "invalid_request_id" => "无效的请求ID",
            
            // 版本
            "unsupported_version" => "不支持的版本",
            
            // IV
            "invalid_iv" => "无效的 IV",
            
            // 警告
            "export_warning" => "⚠️ 警告：您正在导出未加密的私钥！任何人获得此密钥都可以完全控制您的资产。",
            "safety_tip_offline" => "✅ 确保在安全的离线环境中操作",
            "safety_tip_no_network" => "✅ 不要通过网络传输私钥",
            "safety_tip_no_screenshot" => "✅ 不要截图或拍照私钥",
            "safety_tip_encrypt" => "✅ 立即使用 create_keystore 加密保存",
            "safety_tip_clear" => "✅ 使用后立即清除内存和历史记录",
            
            _ => "未知错误",
        }
    }
    
    fn error_msg_en(&self, key: &str) -> &'static str {
        match key {
            // Crypto
            "recrypt_error" => "Encryption operation failed",
            "aes_error" => "Encryption failed",
            "decryption_error" => "Decryption failed",
            
            // Keys
            "invalid_private_key" => "Invalid private key",
            "invalid_public_key" => "Invalid public key",
            "key_derivation_error" => "Key derivation failed",
            
            // Mnemonic
            "bip39_error" => "Invalid mnemonic format",
            "invalid_mnemonic" => "Invalid mnemonic",
            
            // Data format
            "data_format_error" => "Data format error",
            "serialization_error" => "Serialization error",
            "invalid_capsule" => "Invalid data",
            "invalid_cfrag" => "Invalid authorization",
            
            // Signature
            "ed25519_error" => "Signature verification failed",
            
            // Integrity
            "integrity_check_failed" => "Data integrity check failed",
            
            // KDF
            "invalid_kdf_params" => "Invalid KDF parameters",
            
            // Password
            "weak_password" => "Password strength insufficient",
            "password_too_short" => "Password must be at least 12 characters",
            "password_too_long" => "Password too long (max 128 characters)",
            "password_complexity" => "Password must contain at least 3 types: lowercase, uppercase, digits, special characters",
            
            // Input validation
            "invalid_input" => "Invalid input",
            "data_empty" => "Data cannot be empty",
            "data_too_large" => "Data too large",
            "timestamp_future" => "Timestamp cannot be in the future",
            "timestamp_too_old" => "Timestamp expired",
            "invalid_request_id" => "Invalid request ID",
            
            // Version
            "unsupported_version" => "Unsupported version",
            
            // IV
            "invalid_iv" => "Invalid IV",
            
            // Warnings
            "export_warning" => "⚠️ WARNING: You are exporting an unencrypted private key! Anyone with this key has complete control over your assets.",
            "safety_tip_offline" => "✅ Ensure operation in a secure offline environment",
            "safety_tip_no_network" => "✅ Do not transmit private key over network",
            "safety_tip_no_screenshot" => "✅ Do not take screenshots or photos",
            "safety_tip_encrypt" => "✅ Encrypt immediately using create_keystore",
            "safety_tip_clear" => "✅ Clear memory and history after use",
            
            _ => "Unknown error",
        }
    }
    
    pub fn format(&self, key: &str, args: &[(&str, &str)]) -> String {
        let template = self.error_msg(key);
        let mut result = template.to_string();
        
        for (placeholder, value) in args {
            result = result.replace(&format!("{{{}}}", placeholder), value);
        }
        
        result
    }
}

impl Default for I18n {
    fn default() -> Self {
        Self::new(Language::default())
    }
}
