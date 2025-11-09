#!/bin/bash
# 构建 Rust FFI 库

set -e

echo "Building Rust transform library..."

# 获取本地目标平台
TARGET=$(rustc -vV | grep host | cut -d' ' -f2)
echo "Target platform: $TARGET"

# 构建静态库和动态库
cargo build --release --target=$TARGET

# 复制到 Go 可以找到的位置
mkdir -p ../lib
cp target/$TARGET/release/librekrypt_transform.* ../lib/

echo "Build complete!"
echo "Library files:"
ls -lh ../lib/
