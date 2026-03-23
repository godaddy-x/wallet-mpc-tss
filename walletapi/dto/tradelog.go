package dto

import (
	"github.com/godaddy-x/freego/node/common"
	"github.com/godaddy-x/freego/ormx/sqlc"
)

//easyjson:json
type TradeLogResult struct {
	ID        int64  `json:"id"`
	AppID     string `json:"appID" bson:"appID"`
	WalletID  string `json:"walletID" bson:"walletID"`
	AccountID string `json:"accountID" bson:"accountID"`
	Sid       string `json:"sid" bson:"sid"`
	TxID      string `json:"txID" bson:"txID"`
	//"send"	转出	主币/代币从当前账户地址发出
	//"receive"	转入	主币/代币接收到当前账户地址（含合约创建时的 ETH 入账）
	//"internal"	内部转账	from 和 to 归属同一账户（账户内地址互转）
	//"fee"	手续费	Gas 费用支出记录
	TxAction        string   `json:"txAction" bson:"txAction"`
	FromAddress     []string `json:"fromAddress" bson:"fromAddress"`
	FromAddressV    []string `json:"fromAddressV" bson:"fromAddressV"`
	ToAddress       []string `json:"toAddress" bson:"toAddress"`
	ToAddressV      []string `json:"toAddressV" bson:"toAddressV"`
	Amount          string   `json:"amount" bson:"amount"`
	Fees            string   `json:"fees" bson:"fees"`
	MainSymbol      string   `json:"mainSymbol" bson:"mainSymbol"`
	Symbol          string   `json:"symbol" bson:"symbol"`
	IsContract      bool     `json:"isContract" bson:"isContract"`
	BlockHash       string   `json:"blockHash" bson:"blockHash"`
	BlockHeight     int64    `json:"blockHeight" bson:"blockHeight"`
	IsMemo          bool     `json:"isMemo" bson:"isMemo"`
	Memo            string   `json:"memo" bson:"memo"`
	ApplyTime       int64    `json:"applyTime" bson:"applyTime"`
	BlockTime       int64    `json:"blockTime" bson:"blockTime"`
	Decimals        int64    `json:"decimals" bson:"decimals"`
	DealStatus      int64    `json:"dealStatus" bson:"dealStatus"`     // 0.未处理 1.处理中 2.处理成功
	NotifyStatus    int64    `json:"notifyStatus" bson:"notifyStatus"` // 0.未推送 1.已推送
	ContractName    string   `json:"contractName" bson:"contractName"`
	ContractAddress string   `json:"contractAddress" bson:"contractAddress"`
	Success         string   `json:"success" bson:"success"`
	BalanceMode     int64    `json:"balanceMode" bson:"balanceMode"`
	//交易中输出/事件的位置索引：
	//• BTC: vout index
	//• ETH Token: log index
	//• ETH 主币: -1
	//• 手续费: -2
	OutputIndex int64 `json:"outputIndex" bson:"outputIndex"`
}

//easyjson:json
type FindTradeLogReq struct {
	common.BaseReq
	WalletID        string `json:"walletID"`
	AccountID       string `json:"accountID"`
	TxID            string `json:"txID"`
	Sid             string `json:"sid"`
	Symbol          string `json:"symbol"`
	BlockHeight     int64  `json:"blockHeight"`
	TxAction        string `json:"txAction"`
	ContractAddress string `json:"ContractAddress"`
	Address         string `json:"address"`
	UserID          int64  `json:"userID"`
	Sort            int    `json:"sort"`
}

//easyjson:json
type FindTradeLogRes struct {
	Result []TradeLogResult `json:"result"`
	Limit  sqlc.Limit       `json:"limit"`
}
