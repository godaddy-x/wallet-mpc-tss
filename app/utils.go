// 本文件：MPC 路径解析（ParseMPCPath）、钱包列表合并等工具函数。
package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/godaddy-x/freego/zlog"
)

// ParseMPCPath 解析 m/0/accountIndex/change/addrIndex 格式路径，返回账户索引、找零位、地址索引。
func ParseMPCPath(path string) (accountIndex, change, addrIndex uint32, err error) {
	// 允许前缀 m/ 或 /m/
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "m/")
	if path == "" {
		return 0, 0, 0, fmt.Errorf("empty path")
	}

	parts := strings.Split(path, "/")
	// 你的规范是 m/0/accountIndex/change/addressIndex → 去掉 m/ 后应该是 4 段
	if len(parts) != 4 {
		return 0, 0, 0, fmt.Errorf("invalid path length: %s", path)
	}

	// parts[0] 固定是 "0"，代表你现在的 purpose 层，可以校验也可以直接忽略
	if parts[0] != "0" {
		return 0, 0, 0, fmt.Errorf("invalid purpose in path: %s", parts[0])
	}

	// 解析 accountIndex / change / addrIndex
	a, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid account index: %w", err)
	}
	c, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid change index: %w", err)
	}
	i, err := strconv.ParseUint(parts[3], 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid address index: %w", err)
	}

	return uint32(a), uint32(c), uint32(i), nil
}

func ReadAllFilesInDir(dirPath string) ([]*KeyMeta, error) {
	// 读取目录中的所有条目（文件和子目录）
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %q: %w", dirPath, err)
	}
	walletFileList := make([]*KeyMeta, 0, len(entries))
	for _, entry := range entries {
		// 跳过子目录，只处理普通文件
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(dirPath, entry.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			zlog.Error("read file error", 0, zlog.String("errMsg", err.Error()))
			continue
		}
		walletFile := &KeyMeta{}
		if err := json.Unmarshal(content, walletFile); err != nil {
			zlog.Error("read file error", 0, zlog.String("errMsg", err.Error()))
			continue
		}
		walletFileList = append(walletFileList, walletFile)
	}

	return walletFileList, nil
}
