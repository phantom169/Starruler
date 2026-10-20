package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"starruler/internal/api"
	"starruler/internal/config"
	"starruler/internal/engine"
	"starruler/internal/probe"
	"starruler/internal/rules"
	"starruler/internal/store"
)

//go:embed web/index.html
var webFS embed.FS

//go:embed rules
var embeddedRules embed.FS

func main() {
	isProbe := flag.Bool("probe", false, "以探针模式运行（默认为中心服务端）")
	server := flag.String("server", "", "探针模式：中心服务地址，如 http://10.1.1.10:8080")
	token := flag.String("token", "", "探针模式：注册令牌")
	flag.Parse()

	if *isProbe {
		runProbe(*server, *token)
		return
	}
	runServer()
}

func runProbe(server, token string) {
	if server == "" || token == "" {
		fmt.Println("探针模式需要 --server 与 --token，示例：")
		fmt.Println("  starruler --probe --server http://10.1.1.10:8080 --token <令牌>")
		os.Exit(1)
	}
	agent := probe.NewAgent(&config.ProbeConfig{ServerAddr: server, Token: token, Version: config.Version})
	if err := agent.Run(); err != nil {
		log.Fatalf("探针运行失败: %v", err)
	}
}

func runServer() {
	cfg := config.Load()
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	if err := st.Migrate(); err != nil {
		log.Fatalf("初始化表结构失败: %v", err)
	}
	st.Seed()

	ruleStore, err := rules.LoadAuto(cfg.RulesDir, embeddedRules)
	if err != nil {
		log.Fatalf("加载基线规则库失败: %v", err)
	}

	sched := engine.NewScheduler(st, ruleStore)
	go sched.RecoverLoop()
	go sched.DispatchLoop()

	addr := cfg.Addr
	if len(addr) > 0 && addr[0] != ':' {
		addr = ":" + addr
	}

	fmt.Println("================================================")
	fmt.Println("  星尺 (Star ruler) 弱口令检测与等保基线核查系统")
	fmt.Println("  控制台:     http://localhost" + addr)
	fmt.Println("  数据库:     " + cfg.DBPath)
	fmt.Println("  基线规则包: " + fmt.Sprint(ruleStore.Count()) + " 套")
	fmt.Println("================================================")

	log.Fatal(api.Serve(addr, st, ruleStore, sched, cfg, webFS))
}
