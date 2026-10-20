package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// netToolReq 连通性探测请求。
type netToolReq struct {
	Op         string `json:"op"`     // ping / telnet / curl
	Target     string `json:"target"` // IP / IP:端口 / URL
	TimeoutSec int    `json:"timeoutSec"`
}

type netToolResp struct {
	OK         bool   `json:"ok"`
	Output     string `json:"output"`
	DurationMs int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

// safeTarget 防命令注入：ping/telnet 目标仅允许主机名/IPv4/IPv6/端口字符。
var safeTarget = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)

// netTool 连通性探测：Ping（系统命令）/ Telnet（TCP端口）/ Curl（HTTP）。
func (s *Server) netTool(w http.ResponseWriter, r *http.Request) {
	var req netToolReq
	if err := readBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeErr(w, 400, "target 不能为空")
		return
	}
	switch req.Op {
	case "ping":
		writeJSON(w, toolPing(req.Target, timeout))
	case "telnet":
		writeJSON(w, toolTelnet(req.Target, timeout))
	case "curl":
		writeJSON(w, toolCurl(req.Target, timeout))
	default:
		writeErr(w, 400, "op 仅支持 ping / telnet / curl")
	}
}

// toolPing 调用系统 ping（Windows 中文系统输出为 GBK，转 UTF-8）。
func toolPing(target string, timeout time.Duration) netToolResp {
	// 防参数注入：目标不可以 - 开头（避免被 ping 解释为命令行选项）
	if !safeTarget.MatchString(target) || strings.HasPrefix(target, "-") {
		return netToolResp{Error: "目标含非法字符"}
	}
	var cmd *exec.Cmd
	pingTimeout := int(timeout.Seconds()) + 1
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "4", "-w", fmt.Sprint(pingTimeout*1000), target)
	} else {
		cmd = exec.Command("ping", "-c", "4", "-W", fmt.Sprint(pingTimeout), target)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout*4+2*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	ms := time.Since(start).Milliseconds()
	// Windows ping 输出为系统代码页(GBK)，转换为 UTF-8
	text := string(out)
	if runtime.GOOS == "windows" {
		if utf8, convErr := simplifiedchinese.GBK.NewDecoder().Bytes(out); convErr == nil {
			text = string(utf8)
		}
	}
	ok := err == nil && (strings.Contains(text, "TTL=") || strings.Contains(text, "ttl=") || strings.Contains(text, "bytes from") || strings.Contains(text, "字节=") || strings.Contains(text, "来自"))
	if ctx.Err() != nil {
		return netToolResp{OK: false, DurationMs: ms, Output: text, Error: "执行超时"}
	}
	return netToolResp{OK: ok, Output: text, DurationMs: ms}
}

// toolTelnet TCP 端口连通测试。
func toolTelnet(target string, timeout time.Duration) netToolResp {
	if !strings.Contains(target, ":") {
		return netToolResp{Error: "telnet 目标需为 主机:端口 形式（如 10.0.0.1:22）"}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		return netToolResp{OK: false, DurationMs: ms, Error: "连接失败: " + err.Error()}
	}
	remote := conn.RemoteAddr().String()
	conn.Close()
	return netToolResp{
		OK: true, DurationMs: ms,
		Output: fmt.Sprintf("TCP 连通：%s → %s（耗时 %dms）", target, remote, ms),
	}
}

var netHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
}

// toolCurl HTTP 探测：状态码/耗时/关键响应头/响应体片段。
func toolCurl(target string, timeout time.Duration) netToolResp {
	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	start := time.Now()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return netToolResp{Error: "URL 无效: " + err.Error()}
	}
	req.Header.Set("User-Agent", "StarRuler-Probe/1.0")
	client := *netHTTPClient
	client.Timeout = timeout
	resp, err := client.Do(req)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		return netToolResp{OK: false, DurationMs: ms, Error: "请求失败: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Fprintf(&b, "耗时: %dms\n", ms)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		fmt.Fprintf(&b, "Content-Type: %s\n", ct)
	}
	if sv := resp.Header.Get("Server"); sv != "" {
		fmt.Fprintf(&b, "Server: %s\n", sv)
	}
	fmt.Fprintf(&b, "Content-Length: %s\n", resp.Header.Get("Content-Length"))
	fmt.Fprintf(&b, "\n--- Body (前 %d 字节) ---\n%s", len(body), string(body))
	return netToolResp{OK: resp.StatusCode >= 200 && resp.StatusCode < 400, Output: b.String(), DurationMs: ms}
}
