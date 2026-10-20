package auth

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

func init() { Register(&SSHAuth{}) }

// SSHAuth SSH 弱口令认证器。
type SSHAuth struct{}

func (x *SSHAuth) Protocol() string { return "ssh" }
func (x *SSHAuth) DefaultPort() int { return 22 }

func (x *SSHAuth) Try(a Attempt) Result {
	cfg := &ssh.ClientConfig{
		User:            a.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(a.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         a.Timeout,
	}
	client, err := ssh.Dial("tcp", addr(a.IP, a.Port, x.DefaultPort()), cfg)
	if err == nil {
		defer client.Close()
		ver := ""
		if s := client.Conn.ServerVersion(); len(s) > 0 {
			ver = strings.TrimSpace(string(s))
		}
		return Result{Hit: true, Detail: ver}
	}
	// 区分：认证失败（密码错）vs 网络/协议故障
	msg := err.Error()
	if strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain") {
		return Result{}
	}
	return Result{Detail: "网络错误: " + truncate(msg)}
}

func truncate(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
