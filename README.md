# rekrypt

基于 Rust 的代理重加密库 (Proxy Re-Encryption)，提供 WASM 构建。

https://github.com/user-attachments/assets/64e1568e-75d8-4266-8e52-345594fe212f

## 什么是代理重加密？

允许代理在**不解密**的情况下，将 Alice 加密的数据转换为 Bob 可解密的形式。

```
Alice 加密 → 转换密钥 → 代理转换 → Bob 解密
          (Alice 授权)   (无需私钥)
```

**核心优势**：
- **零信任代理** - 代理服务器无法看到明文，只能转换
- **密钥隔离** - Alice 私钥永不暴露，Bob 也无法反推 Alice 私钥
- **灵活授权** - 可随时撤销授权，无需重新加密数据
- **一对多共享** - 同一份密文可授权给多个用户
- **降低开销** - 无需为每个用户重新加密，节省存储和计算

## 快速开始

```bash
# 构建 WASM
wasm-pack build --target web --release

# 运行示例
cd examples && pnpm install

# 文件加密演示
pnpm dev

# 代理重加密演示
pnpm demo
```

## 使用示例

```javascript
import init, { EncryptSDK } from './pkg/rekrypt.js';
await init();
const sdk = new EncryptSDK();

// 1. 生成密钥对
const alice = sdk.gen();
const bob = sdk.gen();

// 2. Alice 加密数据
const message = new TextEncoder().encode('Secret message');
const encrypted = sdk.put(message, alice.public_key);

// 3. Alice 生成转换密钥（授权 Bob）
const transformKey = sdk.auth(
    alice.private_key,
    bob.public_key,
    encrypted.capsule.signing_key_pair
);

// 4. Bob 解密（无需 Alice 私钥）
const decrypted = sdk.getByAuth(
    encrypted.capsule,
    transformKey,
    bob.private_key,
    encrypted.c_data
);
```

## 许可证

[AGPL-3.0](LICENSE)

