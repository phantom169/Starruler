package auth

import (
	"github.com/gosnmp/gosnmp"
)

func init() { Register(&SNMPAuth{}) }

// SNMPAuth SNMP v2c community 字典猜测（网络设备"口令"）。
type SNMPAuth struct{}

func (x *SNMPAuth) Protocol() string { return "snmp" }
func (x *SNMPAuth) DefaultPort() int { return 161 }

func (x *SNMPAuth) Try(a Attempt) Result {
	g := &gosnmp.GoSNMP{
		Target:     a.IP,
		Port:       uint16(normalizePort(a.Port, x.DefaultPort())),
		Community:  a.Password, // community 即口令
		Version:    gosnmp.Version2c,
		Timeout:    a.Timeout,
		Retries:    0,
	}
	if err := g.Connect(); err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer g.Conn.Close()
	// 系统描述 OID：正确 community 返回响应，错误则超时无响应
	if _, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}); err != nil {
		return Result{}
	}
	return Result{Hit: true, Detail: "community 有效"}
}
