# 钱包 API 流程文档

本文档基于 `walletapi/api_flow_test.go` 测试用例，描述钱包、账户与交易相关 API 的调用流程。

- **项目模块**：`github.com/godaddy-x/wallet-mpc-tss`
- **钱包/交易类型**：`github.com/godaddy-x/wallet-adapter`（多链适配器）

---

## 架构说明

系统采用**服务端 + 业务系统**双层架构：

| 角色 | 说明 |
|------|------|
| **服务端（CLI）** | 本项目的 MPC 钱包服务：提供 HTTP API（钱包列表、创建账户、交易签名等），协调 TSS 节点完成 Keygen/Sign，不存储完整私钥。 |
| **业务系统（OPS）** | 外部业务/云端服务：负责交易单构建、提交广播、与链上交互等；调用服务端 API 获取钱包/账户信息并请求签名。 |

整体流程：业务系统向服务端请求钱包列表、创建账户、签名交易；服务端内部通过 MPC 节点完成密钥生成与签名，再返回结果。

---

## 1. 创建钱包流程

### 流程概述

1. 业务系统调用服务端 **FindWalletList**，获取当前已存在的钱包列表（WalletID、Alias、RootPath 等）。
2. 业务系统将钱包信息同步到自有存储（如 OPS 的 CreateWallet），便于后续按 WalletID 发起创建账户、签名等请求。

### 详细步骤

```go
// 步骤1：请求服务端获取钱包列表（需携带认证 token）
cliRequestData := dto.CliFindWalletListReq{}
cliResponseData := dto.CliFindWalletListRes{}
cliHttpSDK.PostByAuth("/api/FindWalletList", &cliRequestData, &cliResponseData, true)

// 步骤2：将钱包信息同步到业务侧（OPS 等），便于后续按 WalletID 操作
for _, v := range cliResponseData.Result {
    requestData := dto.CreateWalletReq{
        WalletID: v.WalletID,
        Alias:    v.Alias,
        RootPath: v.RootPath,
    }
    responseData := dto.CreateWalletRes{}
    opsHttpSDK.PostByAuth("/api/CreateWallet", &requestData, &responseData, true)
}
```

---

## 2. 创建账户流程

### 流程概述

1. 业务系统指定 **WalletID** 和派生参数（LastIndex、Curve），调用服务端 **CreateAccount**。
2. 服务端在对应 MPC 钱包下派生新账户，返回 AccountID、PublicKey、HdPath、ReqSigs、AccountIndex 等。
3. 业务系统将账户信息上传到自有存储（OPS CreateAccount），便于后续创建交易时指定 AccountID。

### 详细步骤

```go
// 步骤1：请求服务端在指定钱包下派生新账户（LastIndex=-1 表示从 0 起找下一个）
cliRequestData := dto.CliCreateAccountReq{
    WalletID:  "VzYK21Vem6WBXHXZmSRYGN4iaE6n2naF6z", // 已存在的 MPC 钱包 ID
    LastIndex: -1,
    Curve:     1, // ECDSA 曲线标识
}
cliResponseData := dto.CliCreateAccountRes{}
cliHttpSDK.PostByAuth("/api/CreateAccount", &cliRequestData, &cliResponseData, true)

// 步骤2：将账户信息同步到业务侧，并绑定链/币种（如 BETH）
requestData := dto.CreateAccountReq{
    WalletID:     cliResponseData.WalletID,
    AccountID:    cliResponseData.AccountID,
    Alias:        "test",
    Symbol:       "BETH",
    PublicKey:    cliResponseData.PublicKey,
    HdPath:       cliResponseData.HdPath,
    ReqSigs:      cliResponseData.ReqSigs,
    AccountIndex: cliResponseData.AccountIndex,
}
responseData := dto.CreateAccountRes{}
opsHttpSDK.PostByAuth("/api/CreateAccount", &requestData, &responseData, true)
```

---

## 3. 创建与签名交易流程

### 流程概述

1. 业务系统准备好交易参数（Symbol、AccountID、To 地址与金额），调用 OPS **CreateTrade** 构建交易单。
2. OPS 返回 TxData（含 Data、DataSign、TradeSign 等），业务系统用 **CheckTxDataSign** 校验 DataSign 防止篡改。
3. 将交易单 Data 反序列化为 `adapter.RawTransaction`，校验 Symbol、AccountID、To 等关键字段。
4. 调用服务端 **SignTransaction**，传入 Data 与 TradeSign；服务端协调 MPC 节点完成 TSS 签名，返回 SignerList。
5. 业务系统将 SignerList 填回 TxData，调用 OPS **SubmitTrade** 提交广播。

### 详细步骤

```go
// ---------- 步骤1：准备交易参数 ----------
symbol := "BETH"
accountID := "8K4oVwL3dLQmLzrsj2zXzbeapCsETNsRVFtykmAKBvp6"
toAddress := "0x4f8abf232ffd006a49a9426ed9a2ab377ce4bdce"
toAmount := "0.1"

// ---------- 步骤2：请求 OPS 构建交易单 ----------
requestData := dto.CreateTradeReq{
    Sid:       utils.GetUUID(true),
    AccountID: accountID,
    Coin:      dto.CoinInfo{Symbol: symbol},
    To:        map[string]string{toAddress: toAmount},
}
responseData := dto.CreateTradeRes{}
opsHttpSDK.PostByAuth("/api/CreateTrade", &requestData, &responseData, true)

// ---------- 步骤3：校验交易单数据签名（防止 Data 被篡改） ----------
CheckTxDataSign(opsConfig.AppKey, responseData.TxData)

// ---------- 步骤4：反序列化并校验关键字段 ----------
txData := responseData.TxData[0]
tx := &adapter.RawTransaction{} // 类型：github.com/godaddy-x/wallet-adapter
utils.JsonUnmarshal(utils.Str2Bytes(txData.Data), tx)

if tx.Coin.Symbol != symbol {
    // symbol 校验失败
}
if tx.Account.AccountID != accountID {
    // accountID 校验失败
}

// ---------- 步骤5：请求服务端对交易单做 MPC 签名 ----------
cliRequestData := dto.CliSignTransactionReq{
    Data:      txData.Data,
    TradeSign: txData.TradeSign, // 服务端会校验 TradeSign 与 Data 一致
}
cliResponseData := dto.CliSignTransactionRes{}
cliHttpSDK.PostByAuth("/api/SignTransaction", &cliRequestData, &cliResponseData, true)

// ---------- 步骤6：将签名结果提交给 OPS 广播 ----------
txData.SignerList = cliResponseData.SignerList
requestSubmitData := dto.SubmitRawTransactionReq{TxData: txData}
responseSubmitData := dto.SubmitRawTransactionRes{}
opsHttpSDK.PostByAuth("/api/SubmitTrade", &requestSubmitData, &responseSubmitData, true)
```

---

## 4. 创建合约（代币）交易流程

### 流程概述

与普通转账类似，区别在于 **Coin** 中需标记为合约交易并携带 ContractID，其余步骤同「3. 创建与签名交易流程」。

### 关键差异

```go
requestData := dto.CreateTradeReq{
    Sid:       utils.GetUUID(true),
    AccountID: "2TBCLPTaRQpbG6VwWuTNdPPgQtC8o3tzVnqUgJvTXmGs",
    Coin: dto.CoinInfo{
        Symbol:     "BETH",
        IsContract: true,   // 标记为合约/代币交易
        ContractID: "ZA+oTwXimYwVFJ5Tk7ACU6tD+6ycw7u2UsdHLVof8kg=",
    },
    To: map[string]string{
        "0xdAb9c307B8B23A8fD8559f75C71F0694Da30D9F6": "0.2",
    },
}
// 后续步骤同 3：校验 DataSign、反序列化校验、SignTransaction、SubmitTrade
```

---

## 5. 创建汇总交易流程

### 流程概述

将多笔小额资产汇总到指定地址：业务系统调用 OPS **CreateSummaryTx**，传入 AccountID、汇总地址、最小转账金额、保留余额等；返回的 TxData 同样需校验、签名、提交，流程与「3」一致。

### 示例

```go
requestData := dto.CreateSummaryTxReq{
    Sid:             utils.GetUUID(true),
    AccountID:       "2TBCLPTaRQpbG6VwWuTNdPPgQtC8o3tzVnqUgJvTXmGs",
    MinTransfer:     "0",   // 最小转账金额
    RetainedBalance: "0",   // 保留余额
    Address:         "0xa6f4ddc5f8b6b6a07e1e250531f7600daa227138", // 汇总目标地址
    Coin:            dto.CoinInfo{Symbol: "BETH"},
}
responseData := dto.CreateTradeRes{}
opsHttpSDK.PostByAuth("/api/CreateSummaryTx", &requestData, &responseData, true)
// 后续：CheckTxDataSign、反序列化校验、SignTransaction、SubmitTrade
```

---

## 安全注意事项

1. **密钥与签名**：完整私钥不出节点；服务端仅协调 TSS，不存储 SaveData。业务侧需校验 DataSign/TradeSign，确保交易单 Data 未被篡改。
2. **参数校验**：业务系统必须校验 Symbol、AccountID、To、金额等关键参数后再发起签名与广播。
3. **认证与网络**：调用服务端 API 需携带有效认证（如 JWT）；生产环境应对服务端与 OPS 做访问控制与 TLS。

---

## API 端点汇总

| 操作         | 服务端（CLI）            | 业务系统（OPS）           |
| ------------ | ------------------------ | -------------------------- |
| 获取钱包列表 | `POST /api/FindWalletList` | -                          |
| 创建钱包     | -                        | `POST /api/CreateWallet`   |
| 创建账户     | `POST /api/CreateAccount` | `POST /api/CreateAccount`  |
| 创建交易     | -                        | `POST /api/CreateTrade`    |
| 签名交易     | `POST /api/SignTransaction` | -                          |
| 提交交易     | -                        | `POST /api/SubmitTrade`    |
| 创建汇总交易 | -                        | `POST /api/CreateSummaryTx` |

服务端端点由本项目（wallet-mpc-tss）提供；OPS 端点由业务/云端系统实现。
