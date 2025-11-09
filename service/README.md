# 代理重加密服务 (Proxy Re-encryption Service)

一个**无状态的密码学转换服务**，用于代理重加密系统中的核心计算操作。

### 核心功能

**唯一功能**：接收加密数据和转换密钥，输出转换后的加密数据

```
输入：
  - Capsule（加密数据的元数据）
  - TransformKey（转换密钥）

输出：
  - 转换后的 Capsule

特点：
  ✅ 不需要任何私钥
  ✅ 无法查看原始数据
  ✅ 完全无状态
  ✅ 纯计算服务
```

### 使用场景

1. **安全文件共享**：Alice 加密的文件，通过代理转换，Bob 可以解密
2. **云存储授权**：不需要下载和重新加密，直接在云端转换
3. **医疗数据共享**：患者授权医生访问加密病历
4. **企业数据委托**：公司数据授权合作方访问，随时可撤销

## 完整流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                         数据所有者 (Alice)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                    1. 加密数据（客户端）
                              │
            ┌─────────────────┴─────────────────┐
            │   sdk.put(data, alice_public)     │
            └─────────────────┬─────────────────┘
                              │
                        生成 Capsule + 密文
                              │
                    2. 生成转换密钥（客户端）
                              │
            ┌─────────────────┴──────────────────────┐
            │   sdk.auth(alice_private, bob_public) │
            └─────────────────┬──────────────────────┘
                              │
                        生成 TransformKey
                              │
                    3. 存储（业务后端）
                              │
                              ↓
            ┌──────────────────────────────────────────┐
            │         你的业务后端数据库                │
            │   ┌──────────────────────────────┐      │
            │   │  authorizations 表             │      │
            │   │  - owner: Alice               │      │
            │   │  - delegate: Bob              │      │
            │   │  - capsule: [bytes]           │      │
            │   │  - transform_key: [bytes]     │      │
            │   │  - c_data: [bytes]            │      │
            │   └──────────────────────────────┘      │
            └──────────────────┬───────────────────────┘
                              │
                              │  4. Bob 请求访问
                              │
┌─────────────────────────────┴──────────────────────────────────┐
│                      被授权者 (Bob)                              │
└──────────────────────────────────────────────────────────────────┘
            │
            │  5. 查询授权（业务后端）
            │     GET /api/authorizations/check
            │
            ↓
    获取 {capsule, transform_key, c_data}
            │
            │  6. 调用代理服务
            │     POST http://proxy:8080/transform
            │     { capsule, transform_key }
            │
            ↓
┌─────────────────────────────────────────────────────────────────┐
│                    🔧 代理重加密服务 (本服务)                     │
│                                                                  │
│    输入: Capsule + TransformKey                                 │
│      ↓                                                          │
│    执行密码学转换 (不知道原始内容)                                │
│      ↓                                                          │
│    输出: 转换后的 Capsule                                        │
└─────────────────────────────┬───────────────────────────────────┘
            │
            │  7. 返回转换后的 Capsule
            │
            ↓
    Bob 用自己的私钥解密（客户端）
    sdk.getByAuth(transformed_capsule, bob_private, c_data)
            │
            ↓
        原始数据 ✅
```

## 详细流程说明

### 步骤 1：Alice 加密数据（客户端）

```javascript
import init, { EncryptSDK } from './pkg/rekrypt.js';
await init();
const sdk = new EncryptSDK();

// Alice 生成密钥对
const alice = sdk.gen();

// 加密数据
const data = new TextEncoder().encode("机密文件内容");
const encrypted = sdk.put(data, alice.public_key);

// 得到：
// - encrypted.capsule: 加密元数据（包含密钥信息）
// - encrypted.c_data: 加密后的数据
// - encrypted.c_hash: 数据完整性哈希
```

### 步骤 2：Alice 授权给 Bob（客户端）

```javascript
// Bob 的公钥（从服务器获取或 Bob 提供）
const bob = sdk.gen();

// 生成转换密钥：Alice → Bob
const transformKey = sdk.auth(
  alice.private_key,                      // Alice 的私钥（只在客户端）
  bob.public_key,                         // Bob 的公钥
  encrypted.capsule.signing_key_pair      // 签名密钥对
);

// transformKey 是转换的关键，但不是私钥！
// 代理服务器拿到它也无法解密数据
```

### 步骤 3：存储到业务后端

```javascript
// 序列化 Capsule
const capsuleBytes = sdk.serializeCapsule(encrypted.capsule);

// 存储到你的数据库
await fetch('https://your-backend.com/api/authorizations', {
  method: 'POST',
  headers: { 
    'Authorization': 'Bearer ' + aliceToken,
    'Content-Type': 'application/json' 
  },
  body: JSON.stringify({
    delegate_id: bob.id,
    resource_id: 'file-123',
    capsule: Array.from(capsuleBytes),
    transform_key: Array.from(transformKey),
    c_data: Array.from(encrypted.c_data)
  })
});
```

### 步骤 4-5：Bob 请求访问（业务后端验证）

```javascript
// Bob 请求访问
const auth = await fetch('https://your-backend.com/api/authorizations/check', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + bobToken },
  body: JSON.stringify({ resource_id: 'file-123' })
});

// 你的后端：
// 1. 验证 Bob 的身份
// 2. 检查是否有访问权限
// 3. 返回必要的数据

const authData = await auth.json();
// → { capsule, transform_key, c_data }
```

### 步骤 6：调用代理服务转换（本服务）

```javascript
// 调用无状态代理服务
const response = await fetch('http://proxy-service:8080/transform', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    capsule: btoa(String.fromCharCode(...authData.capsule)),
    transform_key: btoa(String.fromCharCode(...authData.transform_key))
  })
});

const { transformed_capsule } = await response.json();

// 代理服务只做一件事：密码学转换
// 输入：Capsule + TransformKey
// 输出：转换后的 Capsule
// 不知道原始数据内容！
```

### 步骤 7：Bob 解密数据（客户端）

```javascript
// 反序列化转换后的 Capsule
const transformedBytes = Uint8Array.from(
  atob(transformed_capsule),
  c => c.charCodeAt(0)
);
const transformedCapsule = sdk.deserializeCapsule(transformedBytes);

// 用 Bob 自己的私钥解密
const decrypted = sdk.getByAuth(
  transformedCapsule,           // 转换后的 Capsule
  authData.transform_key,       // 转换密钥
  bob.private_key,              // Bob 的私钥（只在客户端）
  authData.c_data               // 原始密文
);

// 得到原始数据
const text = new TextDecoder().decode(decrypted);
console.log(text); // "机密文件内容" ✅
```

## API 文档

### POST /transform

执行代理重加密转换（唯一功能）

**请求**:
```json
{
  "capsule": "base64-encoded-serialized-capsule",
  "transform_key": "base64-encoded-transform-key"
}
```

**响应**:
```json
{
  "transformed_capsule": "base64-encoded-transformed-capsule"
}
```

**说明**:
- Capsule 包含加密元数据（使用 postcard 序列化）
- TransformKey 是转换密钥（不是私钥）
- 返回转换后的 Capsule（encrypted_data 字段已被转换）

### GET /health

健康检查

**响应**:
```json
{
  "status": "healthy"
}
```

## 快速开始

### 构建

```bash
# 1. 构建 Rust 转换库
cd transform
./build.sh

# 2. 构建 Go 服务
cd ..
go build -o proxy main.go
```

### 运行

```bash
# 默认端口 8080
./proxy

# 或指定端口
PORT=9000 ./proxy
```

### 测试

```bash
# 健康检查
curl http://localhost:8080/health

# 转换测试（需要真实的加密数据）
curl -X POST http://localhost:8080/transform \
  -H "Content-Type: application/json" \
  -d '{
    "capsule": "...",
    "transform_key": "..."
  }'
```

## 架构设计

### 为什么是无状态？

```
有状态代理服务：
✓ 代理服务器存储 TransformKey
✓ 代理服务器管理授权
✗ 需要数据库
✗ 需要用户管理
✗ 部署复杂

无状态代理服务（本服务）：
✓ 只做密码学计算
✓ 无需数据库
✓ 易部署、易扩展
✓ 业务逻辑在业务后端（更灵活）
✓ TransformKey 管理由你控制
```

## 部署

### Docker

```bash
docker build -t rekrypt-proxy .
docker run -p 8080:8080 rekrypt-proxy
```

## 常见问题

### Q: 代理服务器能看到原始数据吗？
**A**: 不能。代理服务器只执行密码学转换，没有任何私钥，无法解密数据。

### Q: TransformKey 存储在哪里？
**A**: 存储在你的业务后端数据库中，代理服务不存储任何数据。

### Q: 如何撤销授权？
**A**: 在你的业务后端删除或标记 TransformKey 为已撤销即可。

### Q: 为什么不把 TransformKey 存在代理服务器？
**A**: 为了保持服务无状态，易部署和扩展。业务逻辑（授权管理）应该在业务后端。

### Q: 这个服务需要数据库吗？
**A**: 不需要。这是一个纯计算服务，完全无状态。

### Q: 可以用于生产环境吗？
**A**: 可以。这是一个简单、可靠的微服务，易于部署和监控。

## 许可证

AGPL-3.0-or-later

## 相关链接

- 客户端 SDK: `../pkg/` (WASM)
- 加密库: `../crates/recrypt-rs/`

