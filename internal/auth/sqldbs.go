package auth

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	_ "github.com/lib/pq"
)

func init() {
	Register(&MSSQLAuth{})
	Register(&PostgresAuth{})
}

const timeBuf = 2 * time.Second

// ---------- SQL Server ----------

type MSSQLAuth struct{}

func (x *MSSQLAuth) Protocol() string { return "mssql" }
func (x *MSSQLAuth) DefaultPort() int { return 1433 }

func (x *MSSQLAuth) Try(a Attempt) Result {
	secs := int(a.Timeout.Seconds()) + 1
	dsn := fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=master&encrypt=disable&dial+timeout=%d&connection+timeout=%d",
		url.PathEscape(a.Username), url.PathEscape(a.Password), a.IP,
		normalizePort(a.Port, x.DefaultPort()), secs, secs)
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return Result{Detail: "初始化失败: " + truncate(err.Error())}
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		if strings.Contains(err.Error(), "Login failed") || strings.Contains(err.Error(), "18456") {
			return Result{}
		}
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	return Result{Hit: true}
}

// ---------- PostgreSQL ----------

type PostgresAuth struct{}

func (x *PostgresAuth) Protocol() string { return "postgres" }
func (x *PostgresAuth) DefaultPort() int { return 5432 }

func (x *PostgresAuth) Try(a Attempt) Result {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=%d",
		url.PathEscape(a.Username), url.PathEscape(a.Password), a.IP,
		normalizePort(a.Port, x.DefaultPort()), int(a.Timeout.Seconds())+1)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return Result{Detail: "初始化失败: " + truncate(err.Error())}
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		if strings.Contains(err.Error(), "password authentication failed") {
			return Result{}
		}
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	return Result{Hit: true}
}
