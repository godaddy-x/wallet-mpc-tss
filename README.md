# wallet-mpc-tss

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

基于 TSS（门限签名）的 MPC 钱包服务：支持 ECDSA (t,n) 门限密钥生成与签名，服务端仅做协调与加密转发，不接触密钥与 TSS 明文。

- **模块路径**：`github.com/godaddy-x/wallet-mpc-tss`

## 概述

- **服务端（CLI/Web）**：提供 HTTP API（创建/解锁钱包、MPC 密钥生成、交易单签名等），协调 Keygen/Sign 任务，按 Subject 转发节点间加密消息，不存储 TSS SaveData。
- **节点（node）**：连接服务端 WebSocket，持有 ECDH 临时密钥；参与 TSS 协议（当前为 [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) ECDSA），消息按目标加密后经服务端转发。
- **钱包与类型**：交易单、账户等类型使用 [wallet-adapter](https://github.com/godaddy-x/wallet-adapter)；与钱包服务 API 的交互封装在 **walletapi** 包。

详细 Keygen/Sign 流程见 [MPC_KEYGEN_SIGN_FLOW.md](./MPC_KEYGEN_SIGN_FLOW.md)。

## 目录结构

```
.
├── main.go              # CLI 入口：加载配置、启动交互式控制台
├── app/                 # 服务端：配置、HTTP 路由、CLI 业务、MPC 协调与收集
├── node/                # MPC 节点入口：WebSocket、Keygen/Sign 处理
├── walletapi/           # 钱包服务 API 客户端（HTTP/配置、DTO、签名校验等）
├── mpc/                 # MPC 多算法抽象与 ECDSA 实现
│   ├── algorithm.go     # 算法枚举（ecdsa / ed25519）
│   └── alg_ecdsa/      # ECDSA 密钥派生、Keygen、Sign、存储与传输
├── cli_config.yaml     # 服务端配置示例
├── node/               # MPC 节点程序及配置（如 cli_node0.json）
└── MPC_KEYGEN_SIGN_FLOW.md
```

## 构建与运行

### 环境要求

- Go 1.26+
- 已配置的 Go 模块环境

### 构建

```bash
go build -o cli .
go build -o node ./node
```

### 服务端（CLI）

```bash
# 生成默认配置示例
./cli -init
# 使用指定配置启动（日志文件：配置名_log.log）
./cli -config=cli_config.yaml
```

### MPC 节点

每个节点使用独立配置（如 `cli_node0.json`），包含服务端域名、WebSocket 地址、认证与临时密钥等：

```bash
./node -config=cli_node0.json
```

## 配置说明

- **cli_config.yaml**：服务端端口、JWT、GC、**extract**（appID、appKey、walletDir、walletMode、各白名单/黑名单等）。
- **walletMode**：仅支持 MPC 模式，3=2-of-3（3 节点）、5=3-of-5（5 节点），需部署对应数量节点。
- **walletDir**：钱包与 MPC 元数据目录（如 `walletapi/keys`）；节点配置中的路径与认证需与服务端约定一致。

## 依赖（import 路径）

- [github.com/godaddy-x/wallet-adapter](https://github.com/godaddy-x/wallet-adapter)：多链适配器类型（RawTransaction、KeySignature、错误码等）。
- [github.com/bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib)：ECDSA TSS 协议。
- [github.com/godaddy-x/freego](https://github.com/godaddy-x/freego)：HTTP/WebSocket/JWT/工具等。

本地开发可将 `github.com/godaddy-x/wallet-adapter` 在 `go.mod` 中 replace 到本地路径。

## 许可证

GPL-3.0
