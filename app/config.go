// Package app 提供 MPC 钱包服务端：配置、HTTP 路由、钱包/MPC 业务逻辑与 TSS 任务协调。
// import 路径：github.com/godaddy-x/wallet-mpc-tss/app。
package app

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	DIC "github.com/godaddy-x/freego/common"
	"github.com/godaddy-x/freego/utils"
	"github.com/godaddy-x/freego/utils/crypto"
	"github.com/godaddy-x/freego/zlog"
)

// Extract 为业务抽取配置：应用认证、钱包目录与模式、各类白名单/黑名单。
type Extract struct {
	AppID            string   `yaml:"appID" json:"appID"`
	AppKey           string   `yaml:"appKey" json:"appKey"`
	WalletDir        string   `yaml:"walletDir" json:"walletDir"`               // 钱包与 MPC 元数据目录
	WalletMode       int64    `yaml:"walletMode" json:"walletMode"`             // 仅 MPC：3=2-of-3，5=3-of-5
	SignerBlacklist  []string `yaml:"signerBlacklist" json:"signerBlacklist"`   // 转出地址黑名单
	SignerWhitelist  []string `yaml:"signerWhitelist" json:"signerWhitelist"`  // 交易单签名请求 IP 白名单
	SummaryWhitelist []string `yaml:"summaryWhitelist" json:"summaryWhitelist"` // 汇总地址白名单
	RemoteWhitelist  []string `yaml:"remoteWhitelist" json:"remoteWhitelist"`  // 业务系统请求 IP 白名单
	NodeWhitelist    []string `yaml:"nodeWhitelist" json:"nodeWhitelist"`      // 节点登录 IP 白名单
}

// YamlConfigExtract 内嵌通用 YAML 配置并包含业务 Extract。
type YamlConfigExtract struct {
	DIC.YamlConfig `yaml:",inline"`
	Extract        *Extract `yaml:"extract,omitempty"`
}

// 仅支持 MPC 模式：walletMode 只允许下列取值。
const (
	WalletMode2of3 int64 = 3 // 3 节点，门限 2（2-of-3）
	WalletMode3of5 int64 = 5 // 5 节点，门限 3（3-of-5）
)

var defaultAllYamlConfig *YamlConfigExtract

// InitAllConfig 从 path 加载 YAML 并校验 walletMode 仅能为 3 或 5（仅支持 MPC 模式）。
func InitAllConfig(path string) (err error) {
	defaultAllYamlConfig = &YamlConfigExtract{}
	if err := utils.ReadLocalYamlConfig(path, defaultAllYamlConfig); err != nil {
		return err
	}
	if defaultAllYamlConfig.Extract == nil {
		return errors.New("extract config is required")
	}
	mode := defaultAllYamlConfig.Extract.WalletMode
	if mode != WalletMode2of3 && mode != WalletMode3of5 {
		return errors.New("wallet mode must be 3 or 5 (MPC only)")
	}
	return nil
}

// GetAllConfig 返回已加载的全局配置，未就绪时 panic。
func GetAllConfig() *YamlConfigExtract {
	if defaultAllYamlConfig == nil || !defaultAllYamlConfig.CheckReady() {
		panic(errors.New("yaml config not ready"))
	}
	return defaultAllYamlConfig
}

// InitLogger 按 Zap 配置初始化默认日志，fileName 会拼接到日志文件名。
func InitLogger(config *DIC.ZapConfig, fileName string) {
	if config == nil {
		panic("Log config cannot be nil")
	}
	c := zlog.ZapConfig{}
	c.Layout = config.Layout
	if len(config.Location) > 0 {
		loc, err := time.LoadLocation(config.Location)
		if err != nil {
			panic("zap log location error: " + err.Error())
		}
		c.Location = loc
	}
	c.Level = config.Level
	c.Console = config.Console
	// 若提供了 FileConfig 则写入文件，否则仅控制台输出
	if config.FileConfig != nil {
		c.FileConfig = &zlog.FileConfig{
			Compress:   config.FileConfig.Compress,
			Filename:   config.FileConfig.Filename + fileName,
			MaxAge:     config.FileConfig.MaxAge,
			MaxBackups: config.FileConfig.MaxBackups,
			MaxSize:    config.FileConfig.MaxSize,
		}
	}
	zlog.InitDefaultLog(&c)
}

// NewBaseConfig 加载 configName 对应配置并初始化日志（输出文件名带 logFileName 后缀）。
func NewBaseConfig(configName, logFileName string) {
	// 初始化配置文件
	if err := InitAllConfig(configName); err != nil {
		panic(errors.New("read config error: " + err.Error()))
	}
	config := GetAllConfig()
	// Initialize default logger
	InitLogger(config.GetLoggerConfig(DIC.MASTER), utils.AddStr(logFileName, ".log"))
}

// WriteKeyFile 原子写入 content 到 file（先写临时文件再 Rename），目录不存在时创建（0700）。
func WriteKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), file)
}

const defaultConfigExample = `server:
  cli_main:
    gc_limit_mb: 512
    gc_percent: 30
    port: 9422
    keys:
      - name: %d  # 客户端编号
        public_key: "%s"  # 客户端公钥，对应私钥: %s
        private_key: "%s" # 服务端私钥，对应公钥: %s

jwt:
  cli_main:
    token_key: "%s"
    token_alg: "HS256"
    token_typ: "JWT"
    token_exp: 3600 # 1 小时

logger:
  master:
    layout: 0
    location: "Asia/Shanghai"
    level: "error"
    console: false
    file_config:
      max_size: 50
      max_backups: 10
      max_age: 7
      compress: false

extract:
  appID: "%s"
  appKey: "%s"
  tradeKey: "%s"
  walletDir: "%s"
  walletMode: 3
  remoteWhitelist:
    - "127.0.0.1"
  signerBlacklist:
    - "0x2346f1ca41d0161d26f46ec2885721c28fbf1375"
  summaryWhitelist:
    - "0x2346f1ca41d0161d26f46ec2885721c28fbf1375"
`

// CreateDefaultCliConfigExample 生成默认 CLI 配置示例文件 cli_config_example.yaml（含随机密钥与 token）。
func CreateDefaultCliConfigExample() {
	eccObj := crypto.EcdsaObject{}
	if err := eccObj.CreateS256ECDSA(); err != nil {
		panic(err)
	}
	if err := eccObj.CreateS256ECDSA(); err != nil {
		panic(err)
	}
	eccObj2 := crypto.EcdsaObject{}
	if err := eccObj2.CreateS256ECDSA(); err != nil {
		panic(err)
	}
	clientNo := utils.NextIID()
	clientPublicKey := eccObj2.PublicKeyBase64
	clientPrivateKey := eccObj2.PrivateKeyBase64
	serverPrivateKey := eccObj.PrivateKeyBase64
	serverPublicKey := eccObj.PublicKeyBase64
	tokenKey := hex.EncodeToString(utils.GetRandomSecure(64))
	appID := hex.EncodeToString(utils.GetRandomSecure(16))
	appKey := hex.EncodeToString(utils.GetRandomSecure(32))
	tradeKey := hex.EncodeToString(utils.GetRandomSecure(32))
	walletDir := "keys"
	path := filepath.Join("cli_config_example.yaml")
	content := fmt.Sprintf(defaultConfigExample, clientNo, clientPublicKey, clientPrivateKey, serverPrivateKey, serverPublicKey, tokenKey, appID, appKey, tradeKey, walletDir)
	if err := WriteKeyFile(path, []byte(content)); err != nil {
		panic(err)
	}
}
