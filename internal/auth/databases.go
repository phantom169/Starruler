package auth

import (
	"context"
	"database/sql"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
)

func init() {
	Register(&MySQLAuth{})
	Register(&RedisAuth{})
}

// ---------- MySQL ----------

type MySQLAuth struct{}

func (x *MySQLAuth) Protocol() string { return "mysql" }
func (x *MySQLAuth) DefaultPort() int { return 3306 }

func (x *MySQLAuth) Try(a Attempt) Result {
	cfg := mysql.NewConfig()
	cfg.User = a.Username
	cfg.Passwd = a.Password
	cfg.Net = "tcp"
	cfg.Addr = addr(a.IP, a.Port, x.DefaultPort())
	cfg.Timeout = a.Timeout
	cfg.ReadTimeout = a.Timeout
	cfg.ParseTime = false
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return Result{Detail: "初始化失败: " + truncate(err.Error())}
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		if strings.Contains(err.Error(), "Error 1045") || strings.Contains(err.Error(), "Access denied") {
			return Result{}
		}
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	ver, _ := selectVersion(db)
	return Result{Hit: true, Detail: ver}
}

func selectVersion(db *sql.DB) (string, error) {
	var v string
	err := db.QueryRow("SELECT VERSION()").Scan(&v)
	return v, err
}

// ---------- Redis ----------

type RedisAuth struct{}

func (x *RedisAuth) Protocol() string { return "redis" }
func (x *RedisAuth) DefaultPort() int { return 6379 }

func (x *RedisAuth) Try(a Attempt) Result {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr(a.IP, a.Port, x.DefaultPort()),
		Password:     a.Password,
		DialTimeout:  a.Timeout,
		ReadTimeout:  a.Timeout,
		WriteTimeout: a.Timeout,
		MaxRetries:   -1,
	})
	defer rdb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout+timeBuf)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "WRONGPASS") || strings.Contains(msg, "invalid username-password") ||
			strings.Contains(msg, "ERR Client sent AUTH") {
			return Result{}
		}
		return Result{Detail: "网络错误: " + truncate(msg)}
	}
	return Result{Hit: true, Detail: "认证成功(注意:未设密码的Redis任意口令均通过)"}
}
