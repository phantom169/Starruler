package baseline

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb"

	"starruler/internal/model"
)

// ================= SSH（Linux / 中间件配置文件） =================

type SSHCollector struct{}

func (c *SSHCollector) Name() string { return "ssh" }

func (c *SSHCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 22
	}
	client, err := sshDial(a.IP, a.AccessPort, a.CredUser, a.CredPassword, timeout)
	if err != nil {
		return false, "", "SSH连接失败: " + err.Error()
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return false, "", "创建会话失败: " + err.Error()
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal("KILL")
		return false, "", "执行超时或取消"
	case <-time.After(timeout):
		_ = sess.Signal("KILL")
		return false, "", "执行超时"
	case err := <-done:
		if err != nil {
			// 命令非零退出不一定是连接问题：输出仍可用于比对（如 grep 无匹配退出码1）
			if out.Len() > 0 {
				return true, out.String(), ""
			}
			return false, "", "命令失败: " + err.Error()
		}
		return true, out.String(), ""
	}
}

// ================= Windows WinRM =================

type WinRMCollector struct{}

func (c *WinRMCollector) Name() string { return "winrm" }

func (c *WinRMCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 5985
	}
	return winrmExec(a.IP, a.AccessPort, a.CredUser, a.CredPassword, cmd, timeout)
}

// ================= 网络设备（SSH 交互式 shell） =================

type NetworkCollector struct{}

func (c *NetworkCollector) Name() string { return "network" }

func (c *NetworkCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 22
	}
	out, err := networkRunCommand(a.IP, a.AccessPort, a.CredUser, a.CredPassword, cmd, timeout)
	if err != nil {
		return false, "", "设备连接失败: " + err.Error()
	}
	return true, out, ""
}

// ================= MySQL =================

type MySQLCollector struct{}

func (c *MySQLCollector) Name() string { return "mysql" }

func (c *MySQLCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 3306
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = a.CredUser, a.CredPassword
	cfg.Net, cfg.Addr = "tcp", fmt.Sprintf("%s:%d", a.IP, a.AccessPort)
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return false, "", err.Error()
	}
	defer db.Close()
	var out string
	if err := db.QueryRowContext(ctx, cmd).Scan(&out); err != nil {
		if strings.Contains(err.Error(), "sql: no rows") {
			return true, "", ""
		}
		return false, "", "SQL执行失败: " + err.Error()
	}
	return true, out, ""
}

// ================= PostgreSQL =================

type PGCollector struct{}

func (c *PGCollector) Name() string { return "postgres" }

func (c *PGCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 5432
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		url.PathEscape(a.CredUser), url.PathEscape(a.CredPassword), a.IP, a.AccessPort, int(timeout.Seconds())+1)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return false, "", err.Error()
	}
	defer db.Close()
	var out string
	if err := db.QueryRowContext(ctx, cmd).Scan(&out); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return true, "", ""
		}
		return false, "", "SQL执行失败: " + err.Error()
	}
	return true, out, ""
}

// ================= Redis =================

type RedisCollector struct{}

func (c *RedisCollector) Name() string { return "redis" }

func (c *RedisCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 6379
	}
	rdb := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", a.IP, a.AccessPort),
		Password: a.CredPassword,
		DialTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout, MaxRetries: -1,
	})
	defer rdb.Close()
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return false, "", "空命令"
	}
	cmdArgs := make([]any, 0, len(parts))
	for _, p := range parts {
		cmdArgs = append(cmdArgs, p)
	}
	rcmd := redis.NewCmd(ctx, cmdArgs...)
	if err := rdb.Process(ctx, rcmd); err != nil {
		return false, "", "命令失败: " + err.Error()
	}
	v, err := rcmd.Result()
	if err != nil && v == nil {
		return false, "", "命令失败: " + err.Error()
	}
	return true, redisFormat(v), ""
}

// redisFormat CONFIG GET 返回 [key, value]：取 value；多对取换行连接的 value 部分。
func redisFormat(v any) string {
	switch t := v.(type) {
	case []any:
		var vals []string
		for i, e := range t {
			if i%2 == 1 {
				vals = append(vals, fmt.Sprint(e))
			}
		}
		return strings.Join(vals, "\n")
	case string:
		return t
	case int64:
		return fmt.Sprint(t)
	default:
		return fmt.Sprint(t)
	}
}

// ================= MongoDB =================

type MongoCollector struct{}

func (c *MongoCollector) Name() string { return "mongodb" }

func (c *MongoCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	return mongoExec(ctx, a, cmd, timeout)
}

// ================= MSSQL（规则核查用） =================

type MSSQLCollector struct{}

func (c *MSSQLCollector) Name() string { return "mssql" }

func (c *MSSQLCollector) Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (bool, string, string) {
	if a.AccessPort == 0 {
		a.AccessPort = 1433
	}
	secs := int(timeout.Seconds()) + 1
	dsn := fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=master&encrypt=disable&dial+timeout=%d&connection+timeout=%d",
		url.PathEscape(a.CredUser), url.PathEscape(a.CredPassword), a.IP, a.AccessPort, secs, secs)
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return false, "", err.Error()
	}
	defer db.Close()
	var out string
	if err := db.QueryRowContext(ctx, cmd).Scan(&out); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return true, "", ""
		}
		return false, "", "SQL执行失败: " + err.Error()
	}
	return true, out, ""
}

func init() {
	RegisterCollector(&SSHCollector{})
	RegisterCollector(&WinRMCollector{})
	RegisterCollector(&NetworkCollector{})
	RegisterCollector(&MySQLCollector{})
	RegisterCollector(&PGCollector{})
	RegisterCollector(&RedisCollector{})
	RegisterCollector(&MongoCollector{})
	RegisterCollector(&MSSQLCollector{})
}
