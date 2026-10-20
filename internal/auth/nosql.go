package auth

import (
	"context"
	"database/sql"
	"strings"

	go_ora "github.com/sijms/go-ora/v2"
	_ "github.com/sijms/go-ora/v2"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func init() {
	Register(&OracleAuth{})
	Register(&MongoAuth{})
}

// ---------- Oracle（纯 Go thin 驱动，无需客户端） ----------

type OracleAuth struct{}

func (x *OracleAuth) Protocol() string { return "oracle" }
func (x *OracleAuth) DefaultPort() int { return 1521 }

func (x *OracleAuth) Try(a Attempt) Result {
	service := a.Params["service_name"]
	if service == "" {
		service = "orcl"
	}
	dsn := go_ora.BuildUrl(a.IP, normalizePort(a.Port, x.DefaultPort()), service, a.Username, a.Password, nil)
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return Result{Detail: "初始化失败: " + truncate(err.Error())}
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout+timeBuf)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		if strings.Contains(err.Error(), "ORA-01017") || strings.Contains(err.Error(), "invalid username/password") {
			return Result{}
		}
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	return Result{Hit: true}
}

// ---------- MongoDB ----------

type MongoAuth struct{}

func (x *MongoAuth) Protocol() string { return "mongodb" }
func (x *MongoAuth) DefaultPort() int { return 27017 }

func (x *MongoAuth) Try(a Attempt) Result {
	uri := "mongodb://" + addr(a.IP, a.Port, x.DefaultPort())
	cred := options.Credential{Username: a.Username, Password: a.Password}
	cli, err := mongo.Connect(context.Background(), options.Client().ApplyURI(uri).
		SetAuth(cred).SetConnectTimeout(a.Timeout).SetServerSelectionTimeout(a.Timeout))
	if err != nil {
		return Result{Detail: "初始化失败: " + truncate(err.Error())}
	}
	defer cli.Disconnect(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout+timeBuf)
	defer cancel()
	if err := cli.Ping(ctx, nil); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "AuthenticationFailed") || strings.Contains(msg, "auth failed") {
			return Result{}
		}
		return Result{Detail: "网络错误: " + truncate(msg)}
	}
	return Result{Hit: true}
}
