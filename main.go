// 程序入口：加载配置并启动 MPC 钱包 CLI 交互式控制台。
// 支持 -config 指定配置文件、-init 生成默认配置示例。
package main

import (
	"flag"
	"fmt"
	"strings"

	webapp "github.com/godaddy-x/wallet-mpc-tss/app"
)

func main() {
	// 解析命令行：配置文件路径与是否生成示例配置
	configFile := flag.String("config", "cli_config.yaml", "服务端配置文件路径（YAML）")
	initConfig := flag.Bool("init", false, "生成默认配置示例文件并退出")
	flag.Parse()

	// 初始化默认配置文件
	if *initConfig {
		webapp.CreateDefaultCliConfigExample()
		fmt.Printf("Default configuration created at: %s\n", "cli_config_example.yaml")
		return
	}

	// 生成日志文件名：配置文件名（去扩展名）+ "_log"
	logFileName := strings.TrimSuffix(*configFile, ".yaml") + "_log"

	// 初始化配置文件
	webapp.NewBaseConfig(*configFile, logFileName)

	// 启动交互式控制台
	webapp.RunApplication()
}
