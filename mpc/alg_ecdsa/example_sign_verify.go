package alg_ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// SignMessageWithPrivHex 示例：使用单机 secp256k1 私钥对 32 字节消息哈希做 ECDSA 签名，
// 返回 64 字节 (R||S) 的 hex 编码。仅用于本地调试 / 对拍，不参与 MPC 协议流程。
//
// privHex: 32 字节私钥的 hex（secp256k1 曲线上的标量）
// msgHex : 32 字节消息哈希的 hex（通常是 keccak256 或 sha256 结果）
func SignMessageWithPrivHex(privHex, msgHex string) (sigHex, pubHex string, err error) {
	dBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return "", "", fmt.Errorf("decode privHex: %w", err)
	}
	if len(dBytes) != 32 {
		return "", "", fmt.Errorf("privHex must be 32 bytes")
	}
	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		return "", "", fmt.Errorf("decode msgHex: %w", err)
	}
	if len(msg) != 32 {
		return "", "", fmt.Errorf("msgHex must be 32 bytes")
	}

	curve := tss.S256()
	d := new(big.Int).SetBytes(dBytes)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return "", "", fmt.Errorf("invalid private key scalar")
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(dBytes)

	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if err != nil {
		return "", "", fmt.Errorf("ecdsa.Sign failed: %w", err)
	}

	sig := append(Pad32(r.Bytes()), Pad32(s.Bytes())...)
	h, _ := PubKeyToHex(&priv.PublicKey)
	return hex.EncodeToString(sig), h, nil
}

// VerifySignatureHex 示例：使用地址公钥和 64 字节 (R||S) 签名验证 32 字节消息哈希。
// pubHex: 65 字节非压缩公钥 hex（04||X||Y），可直接使用 DeriveMPCAddressPubFromRootPubHex 的输出
// msgHex: 32 字节消息哈希 hex
// sigHex: 64 字节 R||S hex
func VerifySignatureHex(pubHex, msgHex, sigHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return false, fmt.Errorf("decode pubHex: %w", err)
	}
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return false, fmt.Errorf("pubHex must be 65 bytes uncompressed (04||X||Y)")
	}
	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		return false, fmt.Errorf("decode msgHex: %w", err)
	}
	if len(msg) != 32 {
		return false, fmt.Errorf("msgHex must be 32 bytes")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("decode sigHex: %w", err)
	}
	if len(sig) != 64 {
		return false, fmt.Errorf("sigHex must be 64 bytes (R||S)")
	}

	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	curve := tss.S256()
	if !curve.IsOnCurve(x, y) {
		return false, fmt.Errorf("pub key not on secp256k1 curve")
	}

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])

	ok := ecdsa.Verify(&pub, msg, r, s)
	return ok, nil
}

// ExampleLocalMPCSignAndVerify 本机 MPC 示例：3 个参与方 (node0,node1,node2)，
// 先在内存中完成一次 keygen，然后在给定 path 上用 RunSignWithKDD 完成一次 MPC 签名，
// 最后用 VerifySignatureHex 校验签名是否与派生出来的地址公钥匹配。
//
// 仅用于开发联调 / 对拍，不参与生产流程。
func ExampleLocalMPCSignAndVerify() error {
	// 1) 本机 3 节点 keygen
	nodeIDs := []string{"node0", "node1", "node2"}
	threshold := 2

	// 使用内存 router 在本进程内路由 TSS 消息
	router := NewInProcessRouter(nil, nil, nil)
	cfg := KeygenConfig{
		PreParamsTimeout: 60 * 1e9, // 60s
		Concurrency:      1,
	}
	kgRes, err := RunKeygen(nodeIDs, threshold, router, cfg, nil)
	if err != nil {
		return fmt.Errorf("local mpc keygen failed: %w", err)
	}
	if len(kgRes.SaveData) != len(nodeIDs) {
		return fmt.Errorf("unexpected saveData length: %d", len(kgRes.SaveData))
	}

	// 2) 基于 RootPubHex + KeyID + path 派生一个地址公钥（账户/地址级）
	accountIndex := uint32(0)
	change := uint32(0)
	addrIndex := uint32(9)

	rootPub := kgRes.SaveData[0].ECDSAPub
	if rootPub == nil {
		return fmt.Errorf("nil ECDSAPub in keygen result")
	}
	rootPubHex, _ := PubKeyToHex(&ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     rootPub.X(),
		Y:     rootPub.Y(),
	})
	if rootPubHex == "" {
		return fmt.Errorf("empty rootPubHex")
	}
	keyID := kgRes.KeyID
	if keyID == "" {
		// 兜底：从 ECDSAPub 计算 KeyID
		keyID = KeyIDFromSaveData(rootPub.X(), rootPub.Y())
	}

	addrPubHex, err := DeriveMPCAddressPubFromRootPubHex(
		rootPubHex,
		keyID,
		accountIndex,
		change,
		addrIndex,
	)
	if err != nil {
		return fmt.Errorf("derive address pub from root failed: %w", err)
	}

	// 3) 在同一条 path 上，用 RunSignWithKDD 完成一次本机 MPC 签名
	path := PathFromAccountAndAddress(accountIndex, change, addrIndex)
	chainCode := ChainCodeFromKeyID(keyID)
	delta, childPub, err := DeriveChildPubFromPath(rootPub, chainCode, path)
	if err != nil {
		return fmt.Errorf("derive child pub for sign failed: %w", err)
	}

	// 构造一个固定的 32 字节消息哈希
	msgHex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	msgHash, err := MessageHashFromTxHash(msgHex)
	if err != nil {
		return fmt.Errorf("invalid msgHex: %w", err)
	}

	// MPC 签名（使用 RunSignWithKDD 保证与 childPub 一致）
	router2 := NewInProcessRouter(nil, nil, nil)
	signRes, err := RunSignWithKDD(
		nodeIDs,
		copySaveSlice(kgRes.SaveData),
		msgHash,
		delta,
		childPub,
		router2,
	)
	if err != nil {
		return fmt.Errorf("local mpc sign failed: %w", err)
	}

	sigHex := hex.EncodeToString(signRes.Signature)

	// 4) 用地址公钥验证 MPC 签名
	ok, err := VerifySignatureHex(addrPubHex, msgHex, sigHex)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("verify failed: signature not match derived address pub")
	}

	fmt.Println("Local MPC sign & verify success")
	fmt.Println("  keyID   =", keyID)
	fmt.Println("  rootPub =", rootPubHex)
	fmt.Println("  addrPub =", addrPubHex)
	fmt.Println("  msgHex  =", msgHex)
	fmt.Println("  sigHex  =", sigHex)
	return nil
}

// copySaveSlice 复制一份 LocalPartySaveData 切片，避免 RunSignWithKDD 在内部修改原切片。
func copySaveSlice(in []keygen.LocalPartySaveData) []keygen.LocalPartySaveData {
	out := make([]keygen.LocalPartySaveData, len(in))
	copy(out, in)
	return out
}
