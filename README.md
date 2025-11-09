# @stenvenleep/rekrypt

REKRYPT：一个基于 Rust 的高性能加密库，原生支持代理重加密与 WASM。

## 快速开始

#### 1. 构建 WASM 包

```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# 构建 WASM
wasm-pack build --target web --release
```

#### 2. 在 JavaScript 中使用

```javascript
import init, { EncryptSDK } from './pkg/rekrypt.js';
await init();
const sdk = new EncryptSDK();

// 生成密钥对
const keypair = sdk.gen();
console.log('助记词:', keypair.mnemonic);

// 加密数据
const data = new TextEncoder().encode('Hello, World!');
const encrypted = sdk.put(data, keypair.public_key);

// 解密数据
const decrypted = sdk.get(
    encrypted.capsule,
    keypair.private_key,
    encrypted.c_data
);
console.log('解密结果:', new TextDecoder().decode(decrypted));
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**注意**：采样模式适合演示和快速开发，生产环境敏感数据请使用全量加密模式。

