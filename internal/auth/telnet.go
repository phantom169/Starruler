package auth

import (
	"bufio"
	"net"
	"strings"
	"time"
)

func init() { Register(&TelnetAuth{}) }

// TelnetAuth 自实现 Telnet 客户端（标准库无 telnet，第三方无维护）。
// 流程：等 login: → 发用户名 → 等 Password: → 发密码 → 判定提示符/失败关键字。
type TelnetAuth struct{}

func (x *TelnetAuth) Protocol() string { return "telnet" }
func (x *TelnetAuth) DefaultPort() int { return 23 }

func (x *TelnetAuth) Try(a Attempt) Result {
	conn, err := net.DialTimeout("tcp", addr(a.IP, a.Port, x.DefaultPort()), a.Timeout)
	if err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(a.Timeout + 2*time.Second))

	r := bufio.NewReader(conn)

	// 等 login 提示（最多读 40 段）
	if !waitContains(r, []string{"login", "user", "name", "Username", "login:"}, conn) {
		return Result{Manual: true, Detail: "未收到登录提示，无法判定"}
	}
	writeLine(conn, a.Username)

	if !waitContains(r, []string{"password", "passcode", "Password:"}, conn) {
		return Result{Manual: true, Detail: "未收到密码提示，无法判定"}
	}
	writeLine(conn, a.Password)

	out := readAll(r)
	low := strings.ToLower(out)
	// 失败特征
	for _, kw := range []string{"incorrect", "failed", "invalid", "denied", "error", "wrong", "fail", "password:"} {
		if strings.Contains(low, kw) {
			return Result{}
		}
	}
	// 成功特征：常见 shell 提示符
	for _, p := range []string{"#", "$", ">"} {
		if strings.HasSuffix(strings.TrimSpace(out), p) {
			return Result{Hit: true}
		}
	}
	if strings.Contains(low, "last login") || strings.Contains(low, "welcome") {
		return Result{Hit: true}
	}
	return Result{Manual: true, Detail: "响应无法判定: " + truncate(out)}
}

// 过滤 Telnet IAC 协商序列后读取
func readChunk(r *bufio.Reader) string {
	buf := make([]byte, 512)
	n, _ := r.Read(buf)
	if n <= 0 {
		return ""
	}
	return stripIAC(string(buf[:n]))
}

func waitContains(r *bufio.Reader, kws []string, conn net.Conn) bool {
	acc := ""
	for i := 0; i < 40; i++ {
		chunk := readChunk(r)
		if chunk == "" {
			return false
		}
		acc += chunk
		low := strings.ToLower(acc)
		for _, kw := range kws {
			if strings.Contains(low, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

func readAll(r *bufio.Reader) string {
	acc := ""
	for i := 0; i < 20; i++ {
		chunk := readChunk(r)
		if chunk == "" {
			break
		}
		acc += chunk
	}
	return acc
}

func writeLine(conn net.Conn, s string) {
	_, _ = conn.Write([]byte(s + "\r\n"))
}

// stripIAC 移除 IAC 协商命令（0xFF 开头的二段/三段序列）。
func stripIAC(s string) string {
	var b strings.Builder
	rs := []byte(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] == 0xFF && i+1 < len(rs) {
			cmd := rs[i+1]
			if cmd == 0xFF { // 转义的 0xFF
				b.WriteByte(0xFF)
				i++
				continue
			}
			if cmd >= 0xFB && cmd <= 0xFE { // 两字节协商
				i += 1
				continue
			}
			if cmd == 0xFA { // 子协商，直到 0xF0
				i += 1
				for i < len(rs) && rs[i] != 0xF0 {
					i++
				}
				continue
			}
			i += 1
			continue
		}
		if rs[i] >= 0x20 || rs[i] == '\n' || rs[i] == '\r' {
			b.WriteByte(rs[i])
		}
	}
	return b.String()
}
