// Package alg_ecdsa 实现基于 bnb-chain/tss-lib 的 ECDSA (t,n) 门限密钥生成与签名，
// 以及从根公钥 + chainCode 的 BIP32 风格子公钥派生（用于 AccountID/地址）。
// import 路径：github.com/godaddy-x/wallet-mpc-tss/mpc/alg_ecdsa。
package alg_ecdsa

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/godaddy-x/wallet-adapter/chain"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/ckd"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// bip32MainnetVersion 为 BIP32 扩展键的版本字节（仅用于构造 ckd.ExtendedKey，不参与派生计算）。
// 与 Bitcoin mainnet 的 HDPrivateKeyID 一致，便于与常见钱包兼容。
var bip32MainnetVersion = []byte{0x04, 0x88, 0xB2, 0x1E}

// DeriveChildPubFromPath 从 MPC 根公钥 + chainCode + 路径派生子公钥（仅非硬化路径，与 BIP32 一致）。
// 返回 keyDerivationDelta（签名时需传给 RunSignWithKDD）和子公钥（用于生成 AccountID/地址）。
// 不涉及私钥，仅用公钥和 path 即可在服务端/客户端派生。
func DeriveChildPubFromPath(rootPub *crypto.ECPoint, chainCode []byte, path []uint32) (keyDerivationDelta *big.Int, childPub *ecdsa.PublicKey, err error) {
	if rootPub == nil || len(chainCode) < 32 {
		return nil, nil, fmt.Errorf("mpc: rootPub and 32-byte chainCode required")
	}
	ec := tss.S256()
	pk := ecdsa.PublicKey{
		Curve: ec,
		X:     rootPub.X(),
		Y:     rootPub.Y(),
	}
	cc := make([]byte, 32)
	copy(cc, chainCode)
	extendedParent := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  cc,
		ParentFP:   []byte{0x00, 0x00, 0x00, 0x00},
		Version:    bip32MainnetVersion,
	}
	delta, extendedChild, err := ckd.DeriveChildKeyFromHierarchy(path, extendedParent, ec.Params().N, ec)
	if err != nil {
		return nil, nil, err
	}
	childPub = &extendedChild.PublicKey
	return delta, childPub, nil
}

// ChainCodeFromKeyID 用 KeyID 生成 32 字节 chainCode，便于无 seed 时仍有一致派生。
func ChainCodeFromKeyID(keyID string) []byte {
	h := sha256.Sum256([]byte(keyID))
	return h[:]
}

// PubKeyToHex 将 ECDSA 公钥转为 65 字节非压缩 hex（04||X||Y），便于与 GenAccountID/地址派生对接。
func PubKeyToHex(pub *ecdsa.PublicKey) (string, []byte) {
	if pub == nil {
		return "", nil
	}
	const size = 65
	b := make([]byte, size)
	b[0] = 0x04
	copy(b[1:33], Pad32(pub.X.Bytes()))
	copy(b[33:65], Pad32(pub.Y.Bytes()))
	return hex.EncodeToString(b), b
}

// PathFromAccountIndex 生成单层非硬化路径 []uint32{accountIndex}，用于 DeriveChildPubFromPath。
// 若需多级路径（如 m/44/60/0/0/index），可传 []uint32{44, 60, 0, 0, index}。
func PathFromAccountIndex(accountIndex uint32) []uint32 {
	return []uint32{accountIndex}
}

// PathFromAccountAndAddress 生成账户 + 地址两级路径：
// accountIndex: 账户序号（与 AccountID 一一对应）
// change:      0 = 外部收款地址，1 = 内部找零地址
// addrIndex:   地址在该 change 分支下的序号
//
// 只使用非硬化路径，保证可从公钥派生。
func PathFromAccountAndAddress(accountIndex, change, addrIndex uint32) []uint32 {
	return []uint32{accountIndex, change, addrIndex}
}

// DeriveMPCAccountFromIndex 从 MPC 根 SaveData 派生出第 index 个账户的 AccountID 与公钥 hex。
// 仅依赖根公钥(ECDSAPub)、KeyID 与 index，不需要私钥或种子。
func DeriveMPCAccountFromIndex(
	save *keygen.LocalPartySaveData,
	keyID string,
	index uint32,
) (accountID string, pubHex string, err error) {
	if save == nil || save.ECDSAPub == nil {
		return "", "", fmt.Errorf("mpc: nil save data or ECDSAPub")
	}

	// 1) 根公钥（tss ECPoint -> ecdsa.PublicKey）
	rootPub := save.ECDSAPub

	// 2) 基于 KeyID 生成 chainCode（32 字节），保证同一 KeyID 派生稳定可复现
	chainCode := ChainCodeFromKeyID(keyID)

	// 3) 使用 index 生成路径（当前为单层路径 []uint32{index}）
	path := PathFromAccountIndex(index)

	// 4) 根据路径派生子公钥（同时会返回签名用的 delta，这里建账户时不返回）
	_, childPub, err := DeriveChildPubFromPath(rootPub, chainCode, path)
	if err != nil {
		return "", "", err
	}

	// 5) 子公钥编码为旧系统兼容的 hex 公钥字符串
	pubHex, pubBytes := PubKeyToHex(childPub)

	// 6) 算出 AccountID
	accountID = chain.ComputeKeyID(pubBytes)

	return accountID, pubHex, nil
}

// DeriveMPCAccountFromKeyStore 从本地 MPC keyfile（SaveData）派生账户信息。
// baseDir 对应 NewFileKeyStore(baseDir) 的目录（例如 "keys"）。
// nodeID 为本节点 ID（用于定位 keyfile：{keyID}-{nodeID}.json）。
func DeriveMPCAccountFromKeyStore(baseDir, keyID, nodeID string, index uint32) (accountID string, pubHex string, err error) {
	store := NewFileKeyStore(baseDir)
	save, err := store.Load(keyID, nodeID)
	if err != nil {
		return "", "", err
	}
	return DeriveMPCAccountFromIndex(&save, keyID, index)
}

// DeriveMPCAccountFromRootPubHex 从根公钥 hex（RootPubHex）+ KeyID + index 派生 AccountID 与公钥 hex。
// 适用于服务端：只持有 RootPubHex 与 KeyID，而不持有 SaveData。
func DeriveMPCAccountFromRootPubHex(rootPubHex, keyID string, index uint32) (accountID string, pubHex string, err error) {
	if rootPubHex == "" {
		return "", "", fmt.Errorf("mpc: empty rootPubHex")
	}
	b, err := hex.DecodeString(rootPubHex)
	if err != nil {
		return "", "", fmt.Errorf("decode rootPubHex: %w", err)
	}
	if len(b) != 65 || b[0] != 0x04 {
		return "", "", fmt.Errorf("mpc: invalid rootPubHex format")
	}

	// 解析 04||X||Y
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	ec := tss.S256()
	point, err := crypto.NewECPoint(ec, x, y)
	if err != nil {
		return "", "", fmt.Errorf("mpc: invalid EC point: %w", err)
	}

	chainCode := ChainCodeFromKeyID(keyID)
	path := PathFromAccountIndex(index)

	_, childPub, err := DeriveChildPubFromPath(point, chainCode, path)
	if err != nil {
		return "", "", err
	}

	pubHex, pubBytes := PubKeyToHex(childPub)
	accountID = chain.ComputeKeyID(pubBytes)
	return accountID, pubHex, nil
}

// DeriveMPCAddressPubFromRootPubHex 基于 RootPubHex + KeyID + (accountIndex, change, addrIndex)
// 派生出地址级别的子公钥（hex）。
//
// 适用场景：
//   - 已经有某个 AccountID（由 accountIndex 决定），希望在其下派生具体地址用的公钥；
//   - 上层再将返回的 pubHex 交给各链的 AddressDecoder/Adapter 转为地址字符串。
func DeriveMPCAddressPubFromRootPubHex(
	rootPubHex, keyID string,
	accountIndex, change, addrIndex uint32,
) (pubHex string, err error) {
	if rootPubHex == "" {
		return "", fmt.Errorf("mpc: empty rootPubHex")
	}
	b, err := hex.DecodeString(rootPubHex)
	if err != nil {
		return "", fmt.Errorf("decode rootPubHex: %w", err)
	}
	if len(b) != 65 || b[0] != 0x04 {
		return "", fmt.Errorf("mpc: invalid rootPubHex format")
	}

	// 解析 04||X||Y
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])

	ec := tss.S256()
	point, err := crypto.NewECPoint(ec, x, y)
	if err != nil {
		return "", fmt.Errorf("mpc: invalid EC point: %w", err)
	}

	chainCode := ChainCodeFromKeyID(keyID)
	path := PathFromAccountAndAddress(accountIndex, change, addrIndex)

	_, childPub, err := DeriveChildPubFromPath(point, chainCode, path)
	if err != nil {
		return "", err
	}

	pubHex, _ = PubKeyToHex(childPub)
	return pubHex, nil
}
