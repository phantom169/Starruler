package auth

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Attempt 一次弱口令尝试。
type Attempt struct {
	IP       string
	Port     int
	Username string
	Password string
	Timeout  time.Duration
	Params   map[string]string // http_form 等需要额外参数
}

// Result 判定结果。严格区分认证失败（密码不对）与网络故障，
// Manual=true 表示无法自动判定（如模糊的 Web 响应），需人工确认。
type Result struct {
	Hit    bool
	Manual bool
	Detail string
}

// Authenticator 弱口令认证器接口：新增协议只需实现并注册。
type Authenticator interface {
	Protocol() string
	DefaultPort() int
	Try(a Attempt) Result
}

var (
	mu       sync.RWMutex
	registry = map[string]Authenticator{}
)

func Register(a Authenticator) {
	mu.Lock()
	defer mu.Unlock()
	registry[a.Protocol()] = a
}

func Get(proto string) (Authenticator, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := registry[proto]
	return a, ok
}

func Protocols() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func addr(ip string, port int, defPort int) string {
	if port <= 0 {
		port = defPort
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func normalizePort(p, def int) int {
	if p <= 0 {
		return def
	}
	return p
}
