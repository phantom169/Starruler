package discover

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// Identified 服务识别结果。
type Identified struct {
	Type       string // 与 auth 认证器同名：ssh/mysql/redis/http/unknown...
	Banner     string
	Confidence int
}

var portFingerprint = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "https", 445: "smb",
	1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgres",
	6379: "redis", 27017: "mongodb", 8080: "http", 161: "snmp",
}

// Identify 三层识别：被动 Banner → 主动探针 → 端口指纹。
func Identify(ip string, port int) Identified {
	banner, ok := readBanner(ip, port)
	if ok {
		if t, conf := matchBanner(banner); t != "unknown" {
			return Identified{Type: t, Banner: banner, Confidence: conf}
		}
	}
	if t, conf, probeBanner := activeProbe(ip, port); t != "unknown" {
		return Identified{Type: t, Banner: mergeBanner(banner, probeBanner), Confidence: conf}
	}
	if t, ok := portFingerprint[port]; ok {
		return Identified{Type: t, Banner: banner, Confidence: 50}
	}
	return Identified{Type: "unknown", Banner: banner, Confidence: 0}
}

// readBanner 被动读取：部分服务（SSH/FTP/MySQL/SMTP）连接即发欢迎包。
func readBanner(ip string, port int) (string, bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "", false
	}
	return printable(buf[:n]), true
}

// matchBanner 按欢迎包关键字判定服务类型。
func matchBanner(b string) (string, int) {
	l := strings.ToLower(b)
	switch {
	case strings.Contains(l, "ssh-"):
		return "ssh", 95
	case strings.HasPrefix(l, "220") && (strings.Contains(l, "ftp") || strings.Contains(l, "vsftpd") || strings.Contains(l, "filezilla")):
		return "ftp", 90
	case strings.Contains(l, "mysql"):
		return "mysql", 95 // MySQL 握手包含版本串
	case strings.Contains(l, "mariadb"):
		return "mysql", 95
	case strings.Contains(l, "microsoft sql server"), strings.Contains(l, "mssql"):
		return "mssql", 90
	case strings.Contains(l, "postgres"):
		return "postgres", 90
	case strings.Contains(l, "redis"):
		return "redis", 95
	case strings.Contains(l, "mongodb"):
		return "mongodb", 90
	case strings.Contains(l, "oracle"), strings.Contains(l, "tns"):
		return "oracle", 80
	case strings.HasPrefix(l, "http/"):
		return "http", 90
	case strings.Contains(l, "tp-link"), strings.Contains(l, "huawei"), strings.Contains(l, "h3c"), strings.Contains(l, "cisco"):
		return "telnet", 60 // 网络设备常开 telnet
	}
	return "unknown", 0
}

// activeProbe 主动探针：对不主动说话的服务发送特征请求。
func activeProbe(ip string, port int) (string, int, string) {
	// Redis: PING → +PONG
	if b, ok := tcpExchange(ip, port, []byte("PING\r\n"), 0); ok {
		if strings.Contains(strings.ToLower(b), "pong") {
			return "redis", 95, b
		}
		if strings.Contains(strings.ToLower(b), "err") || strings.Contains(strings.ToLower(b), "noauth") {
			return "redis", 85, b
		}
	}
	// HTTP: GET / → HTTP/
	if b, ok := tcpExchange(ip, port, []byte("GET / HTTP/1.0\r\nHost: t\r\n\r\n"), 0); ok {
		l := strings.ToLower(b)
		if strings.HasPrefix(l, "http/") {
			if strings.Contains(l, "tomcat") {
				return "http", 90, b
			}
			return "http", 90, b
		}
	}
	// MySQL 服务器会先发握手包：再给一次机会读
	if b, ok := tcpExchange(ip, port, nil, 1200*time.Millisecond); ok {
		if t, c := matchBanner(b); t != "unknown" {
			return t, c, b
		}
	}
	return "unknown", 0, ""
}

// tcpExchange 发送数据并读回响应（timeout 3s）。
func tcpExchange(ip string, port int, payload []byte, extraWait time.Duration) (string, bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 3*time.Second)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if payload != nil {
		if _, err := conn.Write(payload); err != nil {
			return "", false
		}
	}
	r := bufio.NewReader(conn)
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if n == 0 {
		return "", false
	}
	_ = err
	return printable(buf[:n]), true
}

func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			sb.WriteByte(c)
		} else {
			sb.WriteByte(' ')
		}
	}
	s := strings.TrimSpace(sb.String())
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func mergeBanner(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " | " + b
}
