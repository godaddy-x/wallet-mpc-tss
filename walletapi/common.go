// Package walletapi 提供与钱包服务端 API 的交互：HTTP SDK 配置与创建、交易/推送签名、交易单校验等。
// 类型与 DTO 见子包 dto。import 路径：github.com/godaddy-x/wallet-mpc-tss/walletapi。
package walletapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	DIC "github.com/godaddy-x/freego/common"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/sdk"
	"github.com/godaddy-x/freego/zlog"
	adapter "github.com/godaddy-x/wallet-adapter"
	"github.com/godaddy-x/wallet-mpc-tss/walletapi/dto"
)

// SdkConfig 为节点/CLI 连接钱包服务端所需的 HTTP/WebSocket 与认证参数。
type SdkConfig struct {
	Domain    string `json:"domain"`
	WSDomain  string `json:"wsDomain"`
	KeyPath   string `json:"keyPath"`
	LoginPath string `json:"loginPath"`
	Source    string `json:"source"`
	AppID     string `json:"appID"`
	AppKey    string `json:"appKey"`
	ClientPrk string `json:"clientPrk"`
	ServerPub string `json:"serverPub"`
	ClientNo  int64  `json:"clientNo"`
	TradeKey  string `json:"tradeKey"`
	TokenExp  int64  `json:"tokenExp"` // 轮换密钥间隔 单位/秒，最低15秒
}

// ReadJson 从 path 读取 JSON 并解析为 SdkConfig，失败时 panic。
func ReadJson(path string) SdkConfig {
	data, err := utils.ReadFile(path)
	if err != nil {
		panic(err)
	}
	config := SdkConfig{}
	if err := utils.JsonUnmarshal(data, &config); err != nil {
		panic(err)
	}
	return config
}

// NewHttpSDK 根据 config 创建 HTTP SDK 并配置 ECDSA 与 App 登录认证，后台轮换 token。
func NewHttpSDK(config SdkConfig) *sdk.HttpSDK {
	newObject := &sdk.HttpSDK{
		Domain:    config.Domain,
		KeyPath:   config.KeyPath,
		LoginPath: config.LoginPath,
	}
	clientPrk := config.ClientPrk
	serverPub := config.ServerPub
	newObject.SetClientNo(config.ClientNo)
	_ = newObject.SetECDSAObject(newObject.ClientNo, clientPrk, serverPub)
	newObject.AuthObject(func() (interface{}, error) {
		requestData := dto.AppLoginReq{
			AppID:  config.AppID,
			Nonce:  utils.Base64Encode(utils.GetRandomSecure(32)),
			Time:   utils.UnixSecond(),
			Source: config.Source,
		}
		h, err := hex.DecodeString(config.AppKey)
		if err != nil {
			return nil, err
		}
		requestData.Sign = utils.Base64Encode(utils.HMAC_SHA256_BASE(h, utils.Str2Bytes(utils.AddStr(requestData.Nonce, requestData.Time, requestData.Source))))
		return requestData, nil
	})
	go func() {
		for {
			if err := newObject.ResetAuth(); err != nil {
				zlog.Error("sdk reset auth error", 0, zlog.String("errMsg", err.Error()))
			}
			tokenExp := config.TokenExp
			if config.TokenExp < 15 {
				tokenExp = 15
			}
			time.Sleep(time.Duration(tokenExp) * time.Second) // 10秒轮换一次请求token和secret
		}
	}()
	return newObject
}

var (
	// 默认使用AppKey作为交易密钥
	h, _     = hex.DecodeString("4d53d431ea0f1ff4df64490d71ecdc4799287c6d10d65f32249eaf1d3cf0c662")
	tradeKey = memguard.NewBufferFromBytes(utils.SHA256_BASE(h))
	// 测试先固定密钥
)

// GetTradeKey 返回当前用于交易单 TradeSign 校验的密钥（memguard 锁定内存）。
func GetTradeKey() *memguard.LockedBuffer {
	return tradeKey
}

// DestroyMemoryObject 释放 TradeKey 等敏感内存，退出前调用。
func DestroyMemoryObject() {
	tradeKey.Destroy()
}

// SignTradePush 使用 key（hex）对 data 做 HMAC-SHA256 签名，返回 Base64。
func SignTradePush(key string, data dto.TradePushResult) (string, error) {
	h, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	defer DIC.ClearData(h)
	hashKey := utils.SHA256_BASE(h)
	var signData strings.Builder
	signData.WriteString(utils.AnyToStr(data.ID))
	signData.WriteString("|")
	signData.WriteString(data.AppID)
	signData.WriteString("|")
	signData.WriteString(data.Data)
	signData.WriteString("|")
	signData.WriteString(utils.AnyToStr(data.CreateAt))
	return utils.Base64Encode(utils.HMAC_SHA256_BASE(utils.Str2Bytes(signData.String()), hashKey)), nil
}

// SignTradeBalancePush 使用 key（hex）对余额推送 data 做 HMAC-SHA256 签名，返回 Base64。
func SignTradeBalancePush(key string, data dto.TradeBalancePushResult) (string, error) {
	h, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	defer DIC.ClearData(h)
	hashKey := utils.SHA256_BASE(h)
	var signData strings.Builder
	signData.WriteString(utils.AnyToStr(data.ID))
	signData.WriteString("|")
	signData.WriteString(data.AppID)
	signData.WriteString("|")
	signData.WriteString(data.Data)
	signData.WriteString("|")
	signData.WriteString(utils.AnyToStr(data.CreateAt))
	return utils.Base64Encode(utils.HMAC_SHA256_BASE(utils.Str2Bytes(signData.String()), hashKey)), nil
}

// CheckPendingSignTx 校验 PendingSignTx 中每条记录的 DataSign 是否与 appKey 的 HMAC-SHA256 一致。
func CheckPendingSignTx(appKey string, txData []*adapter.PendingSignTx) error {
	if len(txData) == 0 {
		return errors.New("tx data is nil")
	}
	h, err := hex.DecodeString(appKey)
	if err != nil {
		return err
	}
	for _, v := range txData {
		checkSign := utils.HMAC_SHA256_BASE(utils.Str2Bytes(v.Data), h)
		if v.DataSign != utils.Base64Encode(checkSign) {
			return errors.New(fmt.Sprintf("tx data check sign invalid: %s", v.Data))
		}
	}
	return nil
}

// CheckPendingTradeSignTx 校验 PendingSignTx 中每条记录的 TradeSign 是否与 tradeKey（hex）的 HMAC-SHA256 一致。
func CheckPendingTradeSignTx(tradeKey string, txData []*adapter.PendingSignTx) error {
	if len(txData) == 0 {
		return errors.New("tx data is nil")
	}
	h, err := hex.DecodeString(tradeKey)
	if err != nil {
		return err
	}
	for _, v := range txData {
		checkSign := utils.HMAC_SHA256_BASE(utils.Str2Bytes(v.Data), h)
		if v.TradeSign != utils.Base64Encode(checkSign) {
			return errors.New(fmt.Sprintf("tx data check trade sign invalid: %s", v.Data))
		}
	}
	return nil
}

// CheckOneTxTradeSign 校验单条交易 data 的 tradeSign 是否与 tradeKey 的 HMAC-SHA256 一致。
func CheckOneTxTradeSign(tradeKey []byte, data, sign string) error {
	if len(data) == 0 {
		return errors.New("tx data is nil")
	}
	checkSign := utils.HMAC_SHA256_BASE(utils.Str2Bytes(data), tradeKey)
	if sign != utils.Base64Encode(checkSign) {
		return errors.New(fmt.Sprintf("tx data check trade sign invalid: %s, %s", data, sign))
	}
	return nil
}
