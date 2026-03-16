// 本文件：CliService 实现（解锁/创建钱包、登录、创建账户/地址、交易单签名与 MPC 协调等）。
package app

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/awnumar/memguard"
	DIC "github.com/godaddy-x/freego/common"
	"github.com/godaddy-x/freego/ex"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/jwt"
	"github.com/godaddy-x/wallet-adapter/types"
	"github.com/godaddy-x/wallet-mpc-tss/mpc"
	"github.com/godaddy-x/wallet-mpc-tss/mpc/alg_ecdsa"
	"github.com/godaddy-x/wallet-mpc-tss/walletapi"
	"github.com/godaddy-x/wallet-mpc-tss/walletapi/dto"
)

// CliService 提供钱包与交易相关业务逻辑，并控制并发（如解锁/创建钱包同时仅允许一个进行中）。
type CliService struct {
	pending atomic.Bool
}

const (
	// 设置认证(auth)密码的最大最小长度
	minAuthLength = 8
	maxAuthLength = 256 // 根据你的业务需求调整这个值

	// CurveECDSA 用于标识 ECDSA(secp256k1) 曲线的魔数（与前端/调用方约定）。
	// 其他曲线（如 Ed25519）可在未来按需增加新的常量。
	CurveECDSA   int64 = 1
	CurveEd25519 int64 = 2
)

var (
	aad     = memguard.NewBufferRandom(32)
	aadCall = func(keyID string) ([]byte, error) {
		return aad.Data(), nil
	}
)

func (s *CliService) CliLogin(req *dto.AppLoginReq, res *dto.AppLoginRes) error {
	if len(req.AppID) == 0 {
		return ex.Throw{Code: ex.BIZ, Msg: "appID is empty"}
	}
	if len(req.Sign) == 0 {
		return ex.Throw{Code: ex.BIZ, Msg: "sign is empty"}
	}
	if len(req.Nonce) == 0 {
		return ex.Throw{Code: ex.BIZ, Msg: "nonce is empty"}
	}
	if utils.MathAbs(utils.UnixSecond()-req.Time) > jwt.FIVE_MINUTES {
		return ex.Throw{Code: ex.BIZ, Msg: "time invalid"}
	}
	// 通过配置的服务端秘钥解码应用的KEY，进行签名验证
	config := GetAllConfig()
	// 方法结束清除内存中的密钥
	decrypt, err := hex.DecodeString(config.Extract.AppKey)
	if err != nil {
		return ex.Throw{Code: ex.DATA, Msg: "api password decoder invalid", Err: err}
	}
	defer DIC.ClearData(decrypt)
	// 使用应用密钥验签失败则响应错误
	if !bytes.Equal(utils.HMAC_SHA256_BASE(decrypt, utils.Str2Bytes(utils.AddStr(req.Nonce, req.Time, req.Source))), utils.Base64Decode(req.Sign)) {
		return ex.Throw{Code: ex.BIZ, Msg: "sign invalid"}
	}
	res.Subject = config.Extract.AppID
	return nil
}

func (s *CliService) FindWalletList(req *dto.CliFindWalletListReq, res *dto.CliFindWalletListRes) error {
	config := GetAllConfig().Extract
	fileList, err := ReadAllFilesInDir(config.WalletDir)
	if err != nil {
		return err
	}
	res.Result = make([]dto.WalletResult, 0, len(fileList))
	for _, v := range fileList {
		res.Result = append(res.Result, dto.WalletResult{
			Alias:    v.Alias,
			WalletID: v.WalletID,
			RootPath: v.RootPubHex,
		})
	}
	return nil
}

func (s *CliService) CreateAccount(req *dto.CliCreateAccountReq, res *dto.CliCreateAccountRes) error {
	if req.WalletID == "" {
		return ex.Throw{Code: ex.BIZ, Msg: "walletID is nil"}
	}
	if req.LastIndex < -1 {
		return ex.Throw{Code: ex.BIZ, Msg: "lastIndex invalid"}
	}
	// Curve 作为算法/曲线参数：当前仅支持 1 表示 ECDSA(secp256k1)，
	// 其他值（例如未来的 Ed25519）暂未实现。
	if req.Curve != CurveECDSA {
		return ex.Throw{Code: ex.BIZ, Msg: "curve invalid"}
	}

	// 全面使用新的 MPC 模式：必须基于 walletID.json 中的 KeyMeta + RootPubHex 派生账户
	walletMetaDir := GetAllConfig().Extract.WalletDir
	metaPath := filepath.Join(walletMetaDir, req.WalletID+".json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc wallet meta not found: " + metaPath, Err: err}
	}
	var meta KeyMeta
	if err := utils.JsonUnmarshal(raw, &meta); err != nil {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc wallet meta decode failed", Err: err}
	}
	if meta.KeyID == "" || meta.RootPubHex == "" {
		return ex.Throw{Code: ex.BIZ, Msg: "invalid mpc wallet meta: missing keyID or rootPubHex"}
	}

	// 校验算法与曲线兼容：当前只实现 ECDSA，要求 Algorithm 为空或 "ecdsa"，且 Curve == CurveECDSA。
	if meta.Algorithm != "" && meta.Algorithm != string(mpc.AlgECDSA) {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc wallet algorithm not supported yet: " + meta.Algorithm}
	}

	// 使用 MPC 派生：RootPubHex + KeyID + index -> AccountID & 公钥 hex
	accountIndex := req.LastIndex + 1
	accountID, pubHex, err := alg_ecdsa.DeriveMPCAccountFromRootPubHex(meta.RootPubHex, meta.KeyID, uint32(accountIndex))
	if err != nil {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc derive account error", Err: err}
	}

	res.WalletID = meta.WalletID
	if res.WalletID == "" {
		res.WalletID = req.WalletID
	}
	res.AccountID = accountID
	res.PublicKey = pubHex
	res.ReqSigs = int64(meta.Threshold)
	res.HdPath = utils.AddStr("m/0/", accountIndex)
	res.AccountIndex = accountIndex
	res.AddressIndex = -1
	// MPC 模式下 OtherOwnerKeys 由上层根据 NodeIDs 衍生或填充，这里暂留为空
	return nil
}

func (s *CliService) CreateAddress(req *dto.CliCreateAddressReq, res *dto.CliCreateAddressRes) error {
	if req.WalletID == "" {
		return ex.Throw{Code: ex.BIZ, Msg: "walletID is nil"}
	}
	if req.AccountIndex < -1 {
		return ex.Throw{Code: ex.BIZ, Msg: "accountIndex invalid"}
	}
	if req.LastIndex < -1 {
		return ex.Throw{Code: ex.BIZ, Msg: "lastIndex invalid"}
	}
	if req.Count <= 0 || req.Count > 2000 {
		return ex.Throw{Code: ex.BIZ, Msg: "count invalid"}
	}
	// Curve 作为算法/曲线参数：当前仅支持 1 表示 ECDSA(secp256k1)，
	// 其他值（例如未来的 Ed25519）暂未实现。
	if req.Curve != CurveECDSA {
		return ex.Throw{Code: ex.BIZ, Msg: "curve invalid"}
	}

	// 全面使用新的 MPC 模式：必须基于 walletID.json 中的 KeyMeta + RootPubHex 派生账户
	walletMetaDir := GetAllConfig().Extract.WalletDir
	metaPath := filepath.Join(walletMetaDir, req.WalletID+".json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc wallet meta not found: " + metaPath, Err: err}
	}
	var meta KeyMeta
	if err := utils.JsonUnmarshal(raw, &meta); err != nil {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc wallet meta decode failed", Err: err}
	}
	if meta.KeyID == "" || meta.RootPubHex == "" {
		return ex.Throw{Code: ex.BIZ, Msg: "invalid mpc wallet meta: missing keyID or rootPubHex"}
	}

	// 校验算法与曲线兼容：当前只实现 ECDSA，要求 Algorithm 为空或 "ecdsa"，且 Curve == CurveECDSA。
	if meta.Algorithm != "" && meta.Algorithm != string(mpc.AlgECDSA) {
		return ex.Throw{Code: ex.BIZ, Msg: "mpc wallet algorithm not supported yet: " + meta.Algorithm}
	}

	res.AddressList = make([]dto.AddressData, 0, req.Count)
	for i := int64(1); i <= req.Count; i++ {
		// 使用 MPC 派生：RootPubHex + KeyID + index -> AccountID & 公钥 hex
		addressIndex := req.LastIndex + i
		pubHex, err := alg_ecdsa.DeriveMPCAddressPubFromRootPubHex(meta.RootPubHex, meta.KeyID, uint32(req.AccountIndex), uint32(req.Change), uint32(addressIndex))
		if err != nil {
			return ex.Throw{Code: ex.BIZ, Msg: "mpc derive address error", Err: err}
		}
		res.AddressList = append(res.AddressList, dto.AddressData{
			AddressIndex:  addressIndex,
			AddressPubHex: pubHex,
			HdPath:        utils.AddStr("m/0/", req.AccountIndex, "/", req.Change, "/", addressIndex),
		})
	}
	return nil
}

func (s *CliService) SignTransaction(req *dto.CliSignTransactionReq, res *dto.CliSignTransactionRes) error {
	tx, err := checkAndUnmarshalTx(req.Type, req.Data, req.TradeSign)
	if err != nil {
		return err
	}
	txSignerList := make(map[string]string, 3)
	for accountID, keySignatures := range tx.Signatures {
		if keySignatures == nil {
			continue
		}
		for k, keySignature := range keySignatures {
			if keySignature.EccType == uint32(CurveECDSA) {
				accountIndex, change, addressIndex, err := ParseMPCPath(keySignature.Address.HDPath)
				if err != nil {
					return ex.Throw{Code: ex.BIZ, Msg: "parse mpc path error", Err: err}
				}
				sign, err := createMPCSignTaskECDSA(dto.SignData{
					WalletID:     tx.Account.WalletID,
					Message:      keySignature.Message,
					AccountIndex: int64(accountIndex),
					Change:       int64(change),
					AddressIndex: int64(addressIndex),
				})

				if err != nil {
					return ex.Throw{Code: ex.BIZ, Msg: "mpc sign error: " + err.Error(), Err: err}
				}

				verify, err := alg_ecdsa.VerifySignatureHex(keySignature.Address.PublicKey, keySignature.Message, sign)
				if err != nil {
					return err
				}

				if !verify {
					return ex.Throw{Code: ex.BIZ, Msg: "mpc signature verify failed"}
				}

				txSignerList[fmt.Sprintf("%s-%d", accountID, k)] = sign
			} else {
				return ex.Throw{Code: ex.BIZ, Msg: "mpc sign transaction curve invalid"}
			}
		}
	}
	res.SignerList = txSignerList
	return nil
}

func (s *CliService) SignTradeKey(req *dto.CliSignTradeKeyReq, res *dto.CliSignTradeKeyRes) error {
	if req.Data == "" {
		return ex.Throw{Code: ex.BIZ, Msg: "data is nil"}
	}
	if !utils.CheckInt64(req.Type, 0, 1) {
		return ex.Throw{Code: ex.BIZ, Msg: "type invalid"}
	}

	var tx *types.RawTransaction

	if req.Type == 0 {
		tx = &types.RawTransaction{}
		if err := utils.JsonUnmarshal(utils.Str2Bytes(req.Data), tx); err != nil {
			return ex.Throw{Code: ex.BIZ, Msg: "tx decode error", Err: err}
		}
	} else {
		txErr := &types.RawTransactionWithError{}
		if err := utils.JsonUnmarshal(utils.Str2Bytes(req.Data), txErr); err != nil {
			return ex.Throw{Code: ex.BIZ, Msg: "tx decode error", Err: err}
		}
		if txErr.Error != nil {
			return ex.Throw{Code: ex.BIZ, Msg: "tx error: " + txErr.Error.Error()}
		}

		tx = txErr.RawTx
	}

	if tx.TxType != req.Type {
		return ex.Throw{Code: ex.BIZ, Msg: "tx type error"}
	}

	if utils.UnixMilli()-tx.CreateTime > 86400000 {
		return ex.Throw{Code: ex.BIZ, Msg: "tx create time invalid"}
	}

	if tx.TxType == 0 { // 普通交易单，校验黑名单
		blacklist := GetAllConfig().Extract.SignerBlacklist
		for to, _ := range tx.To {
			if utils.CheckStr(to, blacklist...) {
				return ex.Throw{Code: ex.BIZ, Msg: "tx submit blacklist invalid: " + to}
			}
		}
	} else if tx.TxType == 1 { // 汇总交易单，校验白名单
		if len(tx.To) > 1 {
			return ex.Throw{Code: ex.BIZ, Msg: "tx submit target address > 1 invalid"}
		}
		whitelist := GetAllConfig().Extract.SummaryWhitelist
		for to, _ := range tx.To {
			if !utils.CheckStr(to, whitelist...) {
				return ex.Throw{Code: ex.BIZ, Msg: "tx submit blacklist invalid: " + to}
			}
		}
	} else {
		return ex.Throw{Code: ex.BIZ, Msg: "tx type invalid"}
	}

	// TODO 校验其他策略

	res.Sign = hex.EncodeToString(utils.HMAC_SHA256_BASE(utils.Str2Bytes(req.Data), walletapi.GetTradeKey().Data()))

	return nil
}

func checkAndUnmarshalTx(typ int64, data, tradeSign string) (*types.RawTransaction, error) {
	if data == "" {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "data is nil"}
	}
	if tradeSign == "" {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "tradeSign is nil"}
	}
	if !utils.CheckInt64(typ, 0, 1) {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "type invalid"}
	}

	if err := walletapi.CheckOneTxTradeSign(walletapi.GetTradeKey().Data(), data, tradeSign); err != nil {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "trade sign invalid", Err: err}
	}

	var tx *types.RawTransaction

	tx = &types.RawTransaction{}
	if err := utils.JsonUnmarshal(utils.Str2Bytes(data), tx); err != nil {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "tx decode error", Err: err}
	}

	if tx.TxType != typ {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "tx type error"}
	}

	if utils.UnixMilli()-tx.CreateTime > 86400000 {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "tx create time invalid"}
	}

	if tx.TxType == 0 { // 普通交易单，校验黑名单
		blacklist := GetAllConfig().Extract.SignerBlacklist
		for to, _ := range tx.To {
			if utils.CheckStr(to, blacklist...) {
				return nil, ex.Throw{Code: ex.BIZ, Msg: "tx submit blacklist invalid: " + to}
			}
		}
	} else if tx.TxType == 1 { // 汇总交易单，校验白名单
		if len(tx.To) > 1 {
			return nil, ex.Throw{Code: ex.BIZ, Msg: "tx submit target address > 1 invalid"}
		}
		whitelist := GetAllConfig().Extract.SummaryWhitelist
		for to, _ := range tx.To {
			if !utils.CheckStr(to, whitelist...) {
				return nil, ex.Throw{Code: ex.BIZ, Msg: "tx submit blacklist invalid: " + to}
			}
		}
	} else {
		return nil, ex.Throw{Code: ex.BIZ, Msg: "tx type invalid"}
	}
	return tx, nil
}
