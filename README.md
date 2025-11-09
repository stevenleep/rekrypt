# @stenvenleep/rekrypt
rekrypt 一个基于 Rust 的高性能代理重加密库，默认提供 WASM 构建。

https://github.com/user-attachments/assets/64e1568e-75d8-4266-8e52-345594fe212f


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

## 📄 许可证

本项目采用 **GNU Affero General Public License v3.0 (AGPL-3.0)** 开源协议。

### 主要条款

- ✅ **商业使用**：允许用于商业目的
- ✅ **修改**：允许修改源代码
- ✅ **分发**：允许分发原始或修改版本
- ✅ **专利授权**：提供明确的专利授权
- ✅ **私人使用**：允许私人使用和修改

- ⚠️ **网络使用条款**：如果通过网络提供服务，必须公开修改后的源代码
- ⚠️ **相同许可证**：派生作品必须使用相同的 AGPL-3.0 许可证
- ⚠️ **状态声明**：必须说明对原始代码的修改
- ⚠️ **披露源代码**：必须提供完整的源代码

详见 [LICENSE](LICENSE) 文件。

---

**注意**：采样模式适合演示和快速开发，生产环境敏感数据请使用全量加密模式。

