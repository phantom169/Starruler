package baseline

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/masterzen/winrm"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"

	"starruler/internal/model"
)

// sshDial 建立到目标的 SSH 连接（核查凭据来自资产配置）。
func sshDial(ip string, port int, user, pass string, timeout time.Duration) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", ip, port), cfg)
}

// winrmExec 在 Windows 上执行 PowerShell 核查命令。
func winrmExec(ip string, port int, user, pass, cmd string, timeout time.Duration) (bool, string, string) {
	endpoint := winrm.NewEndpoint(ip, port, false, true, nil, nil, nil, timeout)
	client, err := winrm.NewClient(endpoint, user, pass)
	if err != nil {
		return false, "", "WinRM连接失败: " + err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	out, _, _, err := client.RunPSWithContext(ctx, cmd)
	if err != nil {
		return false, "", "执行失败: " + err.Error()
	}
	return true, string(out), ""
}

// networkRunCommand 网络设备交互式命令执行：
// 建立 PTY shell → 等就绪 → 发命令 → 静默判停（0.8s 无新输出即认为完成）。
func networkRunCommand(ip string, port int, user, pass, cmd string, timeout time.Duration) (string, error) {
	client, err := sshDial(ip, port, user, pass, timeout)
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	modes := ssh.TerminalModes{ssh.ECHO: 0}
	if err := sess.RequestPty("vt100", 80, 200, modes); err != nil {
		return "", err
	}
	outBuf := &bytes.Buffer{}
	sess.Stdout = outBuf
	sess.Stderr = outBuf
	if err := sess.Shell(); err != nil {
		return "", err
	}
	// 等登录就绪
	time.Sleep(700 * time.Millisecond)
	outBuf.Reset()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", err
	}
	_, _ = stdin.Write([]byte("screen-length 0 temporary\n")) // 华为取消分页；思科命令不同但无副作用
	time.Sleep(300 * time.Millisecond)
	if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}
	// 静默判停：无新输出 800ms 视为命令完成，上限 timeout
	deadline := time.Now().Add(timeout)
	lastLen := 0
	silent := time.Duration(0)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		n := outBuf.Len()
		if n == lastLen {
			silent += 200 * time.Millisecond
			if silent >= 800*time.Millisecond {
				break
			}
		} else {
			silent = 0
			lastLen = n
		}
	}
	return outBuf.String(), nil
}

// mongoExec 执行 MongoDB 核查命令（getParameter / serverStatus 风格）。
func mongoExec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 27017
	}
	uri := fmt.Sprintf("mongodb://%s:%d", a.IP, a.AccessPort)
	opts := options.Client().ApplyURI(uri).
		SetConnectTimeout(timeout).SetServerSelectionTimeout(timeout)
	if a.CredUser != "" {
		opts.SetAuth(options.Credential{Username: a.CredUser, Password: a.CredPassword, AuthSource: "admin"})
	}
	cli, err := mongo.Connect(ctx, opts)
	if err != nil {
		return false, "", "连接失败: " + err.Error()
	}
	defer cli.Disconnect(context.Background())
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	parts := splitFields(cmd)
	if len(parts) >= 2 && parts[0] == "getParameter" {
		key := parts[len(parts)-1]
		res := cli.Database("admin").RunCommand(cctx, bson.D{{Key: "getParameter", Value: 1}, {Key: key, Value: 1}})
		var doc bson.M
		if err := res.Decode(&doc); err != nil {
			return false, "", "命令失败: " + err.Error()
		}
		delete(doc, "ok")
		if v, exist := doc[key]; exist {
			return true, fmt.Sprint(v), ""
		}
		return true, "", ""
	}
	// serverStatus 风格：serverStatus <字段>
	if len(parts) == 2 && parts[0] == "serverStatus" {
		res := cli.Database("admin").RunCommand(cctx, bson.D{{Key: "serverStatus", Value: 1}})
		var doc bson.M
		if err := res.Decode(&doc); err != nil {
			return false, "", "命令失败: " + err.Error()
		}
		if v, exist := doc[parts[1]]; exist {
			return true, fmt.Sprint(v), ""
		}
		return true, "", ""
	}
	return false, "", "不支持的命令形式: " + cmd
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		default:
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
