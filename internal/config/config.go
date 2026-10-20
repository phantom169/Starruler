package config

import "os"

// Config 中心服务端配置，支持环境变量覆盖。
type Config struct {
	Addr     string // Web 监听地址
	DBPath   string // SQLite 数据库路径
	RulesDir string // 基线规则库目录
	ProbeDir string // 探针二进制下载目录（交叉编译产物）
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func Load() *Config {
	return &Config{
		Addr:     env("STARRULER_ADDR", ":8080"),
		DBPath:   env("STARRULER_DB", "data/starruler.db"),
		RulesDir: env("STARRULER_RULES", "rules"),
		ProbeDir: env("STARRULER_PROBES", "probes"),
	}
}

// ProbeConfig 探针进程配置（--probe 模式）。
type ProbeConfig struct {
	ServerAddr string // 中心地址，如 http://10.1.1.10:8080
	Token      string // 注册令牌
	Version    string
}

const Version = "1.0.0"
