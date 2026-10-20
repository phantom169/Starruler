package auth

import (
	"github.com/jlaffaye/ftp"
)

func init() { Register(&FTPAuth{}) }

// FTPAuth FTP 弱口令。
type FTPAuth struct{}

func (x *FTPAuth) Protocol() string { return "ftp" }
func (x *FTPAuth) DefaultPort() int { return 21 }

func (x *FTPAuth) Try(a Attempt) Result {
	c, err := ftp.Dial(addr(a.IP, a.Port, x.DefaultPort()), ftp.DialWithTimeout(a.Timeout))
	if err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer c.Quit()
	if err := c.Login(a.Username, a.Password); err != nil {
		return Result{}
	}
	return Result{Hit: true}
}
