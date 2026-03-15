// 本文件：TUI 交互（tview）菜单与流程：MPC 钱包列表/创建、启动 HTTP/WebSocket、退出及 RunApplication 入口。
package app

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/godaddy-x/wallet-mpc-tss/walletapi"
	"github.com/godaddy-x/freego/utils/crypto"

	"github.com/godaddy-x/wallet-mpc-tss/walletapi/dto"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// === 全局 HTTP 服务状态管理 ===
var (
	httpServerMu     sync.Mutex
	isServiceRunning bool

	wsServerMu         sync.Mutex
	isWSServiceRunning bool
)

const (
	menuListMPCWallets = iota
	menuCreateMPCWallet
	menuStartHttp
	menuStartWebsocket
	menuCreateECDSA
	menuTestMPCSign
	menuExit
)

// 启动 HTTP 服务（仅当未运行时）
func startHTTPService() error {
	httpServerMu.Lock()
	defer httpServerMu.Unlock()

	if isServiceRunning {
		return fmt.Errorf("service already running")
	}

	web := NewHTTP()

	go func() {
		defer func() {
			httpServerMu.Lock()
			isServiceRunning = false
			httpServerMu.Unlock()

			if r := recover(); r != nil {
				log.Printf("[ERROR] Panic in StartHttpNode: %v", r)
			}
			log.Println("[Service] HTTP service exited")
		}()

		StartHttpNode(web)
	}()

	isServiceRunning = true
	log.Println("[Service] HTTP service started successfully")
	return nil
}

// 启动 WebSocket 服务（仅当未运行时）
func startWSService() error {
	wsServerMu.Lock()
	defer wsServerMu.Unlock()

	if isWSServiceRunning {
		return fmt.Errorf("WebSocket service already running")
	}

	go func() {
		defer func() {
			wsServerMu.Lock()
			isWSServiceRunning = false
			wsServerMu.Unlock()

			if r := recover(); r != nil {
				log.Printf("[ERROR] Panic in StartWebSocketNode: %v", r)
			}
			log.Println("[Service] WebSocket service exited")
		}()

		NewSocket()
	}()

	isWSServiceRunning = true
	log.Println("[Service] WebSocket service started successfully")
	return nil
}

// ==================== 应用入口 ====================
// RunApplication 启动 TUI 主循环（菜单：MPC 钱包、启动 HTTP/WS、退出），为 CLI 入口调用。
func RunApplication() {
	app := tview.NewApplication()
	showMainMenu(app)
	if err := app.Run(); err != nil {
		panic(err)
	}
}

func menuNumber(index int32) rune {
	return '1' + index
}

// ==================== 主菜单 ====================
func showMainMenu(app *tview.Application) {
	header := tview.NewTextView()
	header.SetText("🔐 MPC Wallet CLI – Manage your cryptographic wallets\n( Use ↑↓ to navigate, Enter to select, or press 1–7 )")
	header.SetTextColor(tcell.ColorYellow)
	header.SetDynamicColors(true)
	header.SetBorder(false)

	list := tview.NewList()
	list.SetBorder(false)

	status := ""
	httpServerMu.Lock()
	if isServiceRunning {
		status = " (running)"
	}
	httpServerMu.Unlock()

	wsStatus := ""
	wsServerMu.Lock()
	if isWSServiceRunning {
		wsStatus = " (running)"
	}
	wsServerMu.Unlock()

	list.AddItem("List MPC Wallets", "Show MPC walletID / alias / algorithm from walletDir", menuNumber(menuListMPCWallets), nil)
	list.AddItem("Create MPC Wallet (TSS)", "Multi-node TSS keygen (3 or 5 nodes online)", menuNumber(menuCreateMPCWallet), nil)
	list.AddItem("Start HTTP Service"+status, "Start HTTP server exposing signing APIs to clients", menuNumber(menuStartHttp), nil)
	list.AddItem("Start WebSocket Service"+wsStatus, "Start MPC node relay (WebSocket) for TSS keygen/sign", menuNumber(menuStartWebsocket), nil)
	list.AddItem("Generate ECDSA", "Print base64-encoded ECDSA key pair to terminal", menuNumber(menuCreateECDSA), nil)
	list.AddItem("Test MPC Sign", "Run a sample MPC sign task for debugging", menuNumber(menuTestMPCSign), nil)
	list.AddItem("Exit", "Quit the app", menuNumber(menuExit), nil)

	list.SetSelectedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		switch index {
		case menuCreateMPCWallet:
			showCreateMPCKeyWallet(app)
		case menuCreateECDSA:
			showGenerateECDSA(app)
		case menuTestMPCSign:
			showTestMPCSign(app)
		case menuListMPCWallets:
			showMPCWalletList(app)
		case menuStartHttp:
			showHttpService(app)
		case menuStartWebsocket:
			showWSService(app)
		case menuExit:
			walletapi.DestroyMemoryObject()
			app.Stop()
			os.Exit(0)
		}
	})

	list.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			return event
		}
		return event
	})

	layout := tview.NewFlex().SetDirection(tview.FlexRow)
	layout.AddItem(header, 3, 1, false)
	layout.AddItem(list, 0, 1, true)
	app.SetRoot(layout, true)
}

// ==================== 创建钱包 ====================
func isValidAlias(alias string) bool {
	if len(alias) == 0 {
		return false
	}
	for _, r := range alias {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// showCreateMPCKeyWallet 通过轮询多节点完成 TSS keygen，落盘 mpc_keys 后返回 KeyID。
func showCreateMPCKeyWallet(app *tview.Application) {
	app.Suspend(func() {
		fmt.Print("\n")
		fmt.Println("🔐 Create MPC Wallet (TSS Keygen)")
		fmt.Println("────────────────────")
		fmt.Println("Ensure 3 or 5 nodes are online and WebSocket service is running.")
		fmt.Println()

		fmt.Print("Enter alias for this MPC wallet (letters + digits only, non-empty): ")
		var aliasInput string
		fmt.Scanln(&aliasInput)
		alias := strings.TrimSpace(aliasInput)
		if !isValidAlias(alias) {
			fmt.Println("\n❌ Error: Alias must be non-empty and contain only letters and digits (e.g., mpcWallet1).")
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
			return
		}

		walletID, err := CreateMPCKeygenTask(alias)
		if err != nil {
			fmt.Printf("\n❌ MPC keygen failed: %v\n", err.Error())
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
			return
		}

		fmt.Printf("\n✅ MPC wallet created successfully!\n")
		fmt.Printf("   walletID: %s\n", walletID)
		fmt.Printf("   alias   : %s\n", alias)
		fmt.Printf("   Saved to: %s/%s.json\n", GetAllConfig().Extract.WalletDir, walletID)
		fmt.Print("\nPress Enter to return to main menu...")
		fmt.Scanln()
	})
	showMainMenu(app)
}

// showMPCWalletList 列出当前 walletDir 下的 MPC 钱包（walletID.json），展示别名 / 算法 / 节点列表等信息。
// 仅使用 stdout 打印，按 Enter 返回主菜单。
func showMPCWalletList(app *tview.Application) {
	app.Suspend(func() {
		fmt.Print("\n")
		fmt.Println("📄 MPC Wallet List")
		fmt.Println("──────────────────")
		fmt.Println()

		walletDir := GetAllConfig().Extract.WalletDir
		entries, err := os.ReadDir(walletDir)
		if err != nil {
			fmt.Printf("Failed to read walletDir(%s): %v\n", walletDir, err)
			fmt.Print("\nPress Enter to return to main menu...")
			fmt.Scanln()
			return
		}

		shown := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			walletID := strings.TrimSuffix(name, ".json")
			path := filepath.Join(walletDir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("- walletID=%s (read error: %v)\n", walletID, err)
				continue
			}
			var meta KeyMeta
			if err := json.Unmarshal(raw, &meta); err != nil {
				fmt.Printf("- walletID=%s (unmarshal error: %v)\n", walletID, err)
				continue
			}
			if meta.WalletID == "" {
				meta.WalletID = walletID
			}
			shown++
			fmt.Printf("- walletID : %s\n", meta.WalletID)
			if meta.Alias != "" {
				fmt.Printf("  alias    : %s\n", meta.Alias)
			}
			if meta.Algorithm != "" {
				fmt.Printf("  algorithm: %s\n", meta.Algorithm)
			}
			if len(meta.NodeIDs) > 0 {
				fmt.Printf("  nodes    : %v\n", meta.NodeIDs)
			}
			if meta.Threshold > 0 {
				fmt.Printf("  threshold: %d\n", meta.Threshold)
			}
			fmt.Println()
		}

		if shown == 0 {
			fmt.Println("No MPC wallets found in walletDir.")
		}

		fmt.Print("Press Enter to return to main menu...")
		fmt.Scanln()
	})
	showMainMenu(app)
}

// showTestMPCSign 通过 CreateMPCSignTask 触发一次固定消息哈希的 MPC 签名，用于快速联调。
func showTestMPCSign(app *tview.Application) {
	app.Suspend(func() {
		fmt.Print("\n")
		fmt.Println("🧪 Test MPC Sign (TSS)")
		fmt.Println("──────────────────────")
		fmt.Println("This will use a fixed existing KeyID and a fixed 32-byte hash to run a distributed TSS signature.")
		fmt.Println("Ensure WebSocket service is running and all nodes for this KeyID are online.")
		fmt.Println()

		// 固定使用已存在的 KeyID（测试用）
		const walletID = "19xPEVD5G7buyQbAg6UkGTXcnKf2xAKA3S"
		fmt.Printf("Using fixed KeyID: %s\n", walletID)

		// 固定的 32 字节消息哈希（64 位 hex），仅用于测试
		const msgHashHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fmt.Printf("Using fixed msgHashHex: %s\n", msgHashHex)

		sigHex, err := CreateMPCSignTask(dto.SignData{
			WalletID: walletID,
			Message:  msgHashHex,
		})
		if err != nil {
			fmt.Printf("\n❌ MPC sign failed: %v\n", err.Error())
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
			return
		}

		fmt.Printf("\n✅ MPC sign succeeded!\n")
		fmt.Printf("   walletID         : %s\n", walletID)
		fmt.Printf("   MsgHash (hex) : %s\n", msgHashHex)
		fmt.Printf("   Signature(hex): %s\n", sigHex)
		fmt.Print("\nPress Enter to return to main menu...")
		fmt.Scanln()
	})
	showMainMenu(app)
}

// ==================== 启动HTTP服务 ====================
func showHttpService(app *tview.Application) {
	// 检查是否已有服务在运行
	httpServerMu.Lock()
	alreadyRunning := isServiceRunning
	httpServerMu.Unlock()
	if alreadyRunning {
		app.Suspend(func() {
			fmt.Println("\n⚠️  Service is already running!")
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
		return
	}

	// 启动服务
	if err := startHTTPService(); err != nil {
		app.Suspend(func() {
			fmt.Printf("\n❌ Failed to start service: %v\n", err)
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
	} else {
		app.Suspend(func() {
			fmt.Println("\n✅ HTTP service started successfully!")
			fmt.Println(fmt.Sprintf("   Listening on http://localhost:%d", GetAllConfig().GetServerConfig(project).Port))
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
	}
}

// ==================== 启动WebSocket服务 ====================
func showWSService(app *tview.Application) {
	// 检查是否已有服务在运行
	wsServerMu.Lock()
	alreadyRunning := isWSServiceRunning
	wsServerMu.Unlock()
	if alreadyRunning {
		app.Suspend(func() {
			fmt.Println("\n⚠️  WebSocket service is already running!")
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
		return
	}

	// 启动服务
	if err := startWSService(); err != nil {
		app.Suspend(func() {
			fmt.Printf("\n❌ Failed to start WebSocket service: %v\n", err)
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
	} else {
		app.Suspend(func() {
			fmt.Println("\n✅ WebSocket service started successfully!")
			// 注意：这里需要你的配置能获取 WebSocket 端口
			// 假设配置中有 WSPort 字段，否则请调整
			wsPort := GetAllConfig().GetServerConfig(project).Port + 100
			fmt.Printf("   Listening on ws://localhost:%d\n", wsPort)
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
	}
}

// ==================== 生成临时 ECDSA 密钥对（Base64 输出） ====================
func showGenerateECDSA(app *tview.Application) {
	// 生成 ECDSA 密钥对 (P-256)
	o := &crypto.EcdsaObject{}
	if err := o.CreateS256ECDSA(); err != nil {
		app.Suspend(func() {
			fmt.Printf("\n❌ Failed to generate ECDSA key: %v\n", err)
			fmt.Print("Press Enter to return to main menu...")
			fmt.Scanln()
		})
		showMainMenu(app)
		return
	}

	// 安全输出到终端
	app.Suspend(func() {
		fmt.Println("\n🔐 Temporary ECDSA Key Pair (Base64-encoded)")
		fmt.Println("──────────────────────────────────────────────")
		fmt.Printf("Public Key (Base64):\n%s\n\n", o.PublicKeyBase64)
		fmt.Printf("Private Key (Base64):\n%s\n\n", o.PrivateKeyBase64)
		fmt.Println("💡 You can copy these for testing. Keys are NOT saved.")
		fmt.Print("Press Enter to return to main menu...")
		fmt.Scanln()
	})

	showMainMenu(app)
}
