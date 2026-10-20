package auth

import (
	"github.com/stacktitan/smb/smb"
)

func init() { Register(&SMBAuth{}) }

// SMBAuth Windows SMB(445) 弱口令 —— NTLM 认证判定。
type SMBAuth struct{}

func (x *SMBAuth) Protocol() string { return "smb" }
func (x *SMBAuth) DefaultPort() int { return 445 }

func (x *SMBAuth) Try(a Attempt) Result {
	session, err := smb.NewSession(smb.Options{
		Host:        a.IP,
		Port:        normalizePort(a.Port, x.DefaultPort()),
		User:        a.Username,
		Password:    a.Password,
		Domain:      a.Params["domain"],
		Workstation: "",
	}, false)
	if err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer session.Close()
	if session.IsAuthenticated {
		return Result{Hit: true, Detail: "SMB认证成功（若目标启用Guest会话可能误报，重要主机建议人工复核）"}
	}
	return Result{}
}
