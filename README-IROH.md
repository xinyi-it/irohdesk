# RustDesk + Iroh — 去中心化 P2P 远程桌面

基于 RustDesk 1.4.8，用 Iroh 0.35 技术栈替换中心化 hbbs ID 服务器，实现公钥直连。

## 核心改动

- 用 Iroh P2P 传输层替代 hbbs 中转
- 公钥即 ID（64 字符 hex ed25519 公钥）
- 输入公钥自动走 Iroh P2P 直连，输入传统数字 ID 仍走 hbbs（向后兼容）

## 命令行用法

```bash
# 获取本机 Iroh 公钥 ID
./rustdesk --get-iroh-id

# 启动被控端（开放桌面，自动监听 Iroh P2P 连接）
./rustdesk --server

# 主控端公钥直连
./rustdesk --iroh-connect <对端公钥> --password <密码>
```

## 编译方法

### Linux

```bash
# 系统依赖
sudo apt install libvpx-dev libopus-dev pkg-config cmake

# 编译（用 pkg-config 替代 vcpkg）
cargo build --features "linux-pkg-config"
```

### macOS

```bash
# 装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 系统依赖
brew install libvpx opus pkg-config cmake

# 编译
cargo build
```

### Windows

需要 Visual Studio Build Tools + Rust，然后：

```bash
# 需要 vcpkg
set VCPKG_ROOT=<vcpkg路径>
cargo build
```

## 测试流程

1. A 机（被控端）：`./rustdesk --server`，记录输出的 Iroh 公钥
2. B 机（主控端）：`./rustdesk --iroh-connect <A的公钥> --password <A的密码>`
3. 两机必须不同（Iroh 不允许自连）

## 架构

```
输入框 / 命令行
 ├─ 64字符 hex 公钥 → Iroh P2P 直连（无需 hbbs 服务器）
 └─ 传统数字 ID → hbbs 原路径（向后兼容）
```

## 关键文件

- `src/iroh_transport.rs` — Iroh P2P 传输层（693 行）
- `src/client.rs` — 路由判断 + `start_iroh` 连接方法
- `src/core_main.rs` — 命令行入口（`--get-iroh-id` / `--iroh-connect`）
- `src/rendezvous_mediator.rs` — 服务端 Iroh accept loop
- `libs/hbb_common/src/stream.rs` — IrohStream 适配器
