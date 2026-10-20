package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store 封装 SQLite 访问。modernc.org/sqlite 为纯 Go 实现，
// 编译无 CGO 依赖，可直接交叉编译到任意平台。
type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建数据库目录: %w", err)
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite 单写者，串行化规避 locked
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB 暴露底层连接（调度器做少量只读查询）。
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS hosts (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ip         TEXT NOT NULL UNIQUE,
	source     TEXT NOT NULL DEFAULT 'discovered',
	os_guess   TEXT NOT NULL DEFAULT '',
	note       TEXT NOT NULL DEFAULT '',
	first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS services (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id    INTEGER NOT NULL DEFAULT 0,
	ip         TEXT NOT NULL,
	port       INTEGER NOT NULL,
	type       TEXT NOT NULL DEFAULT 'unknown',
	banner     TEXT NOT NULL DEFAULT '',
	confidence INTEGER NOT NULL DEFAULT 0,
	manual     INTEGER NOT NULL DEFAULT 0,
	first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(ip, port)
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE TABLE IF NOT EXISTS assets (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	ip            TEXT NOT NULL,
	name          TEXT NOT NULL DEFAULT '',
	category      TEXT NOT NULL,
	sub_type      TEXT NOT NULL DEFAULT '',
	access_proto  TEXT NOT NULL DEFAULT 'ssh',
	access_port   INTEGER NOT NULL DEFAULT 0,
	cred_user     TEXT NOT NULL DEFAULT '',
	cred_password TEXT NOT NULL DEFAULT '',
	vars          TEXT NOT NULL DEFAULT '{}',
	created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS probes (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	token      TEXT NOT NULL UNIQUE,
	bind_ip    TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT 'offline',
	hostname   TEXT NOT NULL DEFAULT '',
	source_ip  TEXT NOT NULL DEFAULT '',
	version    TEXT NOT NULL DEFAULT '',
	last_seen  DATETIME,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	type        TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'pending',
	config      TEXT NOT NULL DEFAULT '{}',
	stats       TEXT NOT NULL DEFAULT '{}',
	error       TEXT NOT NULL DEFAULT '',
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	finished_at DATETIME
);
CREATE TABLE IF NOT EXISTS shards (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id    INTEGER NOT NULL,
	kind       TEXT NOT NULL,
	range_key  TEXT NOT NULL,
	status     TEXT NOT NULL DEFAULT 'pending',
	probe_id   INTEGER NOT NULL DEFAULT 0,
	claimed_at DATETIME,
	done_at    DATETIME,
	error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_shards_task ON shards(task_id, status);
CREATE TABLE IF NOT EXISTS weak_results (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id   INTEGER NOT NULL,
	ip        TEXT NOT NULL,
	protocol  TEXT NOT NULL,
	port      INTEGER NOT NULL,
	username  TEXT NOT NULL,
	password  TEXT NOT NULL DEFAULT '',
	detail    TEXT NOT NULL DEFAULT '',
	manual    INTEGER NOT NULL DEFAULT 0,
	found_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_weak_task ON weak_results(task_id);
CREATE TABLE IF NOT EXISTS baseline_results (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id     INTEGER NOT NULL,
	asset_ip    TEXT NOT NULL,
	asset_name  TEXT NOT NULL DEFAULT '',
	target      TEXT NOT NULL,
	rule_id     TEXT NOT NULL,
	title       TEXT NOT NULL,
	control     TEXT NOT NULL DEFAULT '',
	ref         TEXT NOT NULL DEFAULT '',
	severity    TEXT NOT NULL DEFAULT 'medium',
	actual      TEXT NOT NULL DEFAULT '',
	expected    TEXT NOT NULL DEFAULT '',
	passed      INTEGER NOT NULL DEFAULT -1,
	remediation TEXT NOT NULL DEFAULT '',
	detail      TEXT NOT NULL DEFAULT '',
	checked_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_baseline_task ON baseline_results(task_id);
CREATE TABLE IF NOT EXISTS dicts (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	dtype   TEXT NOT NULL UNIQUE,
	content TEXT NOT NULL
);
`)
	return err
}

// Seed 初始化内置用户名与弱密码字典（仅首次）。
func (s *Store) Seed() {
	if n, _ := s.count("dicts"); n > 0 {
		return
	}
	usernames := `root
admin
administrator
test
oracle
mysql
postgres
sa
mongodb
redis
tomcat
guest
ubuntu
centos
deploy
git
jenkins
elastic
kafka
hadoop
dba
backup
operator
user
manager`
	passwords := `123456
admin123
root123
P@ssw0rd
1qaz2wsx
abcd1234
admin@123
123456789
password
test123
qwer1234
111111
000000
123123
admin
root
toor
pass123
1234
12345
a123456
147258369
987654321
Admin@123
Root@123
!QAZ2wsx
1qaz@WSX
P@ss1234
Passw0rd
p@ssw0rd
admin888
12345678
1234567890
abc123
000000
666666
888888
88888888
66666666
112233
123321
121212
654321
qwerty
asdfgh
zxcvbnm
password123
admin1
root1234
system
server
manager
changeme
guest
test
test1234
qwe123
1q2w3e4r
qazwsx
5201314
woaini
woaini1314
520520
a12345678
aa123456
qq123456
taobao
wang123
li123
zhang123
huawei@123
Huawei@123
h3c@123
cisco@123
oracle123
mysql123
postgres123
redis123
mongo123
sa123
Sql2008
sqlserver
tomcat123
nginx123
test123456
dev123
dev@123
uat@123
prod@123
Passw0rd!
Pass1234!
Qwer1234!
!@#$%^&
aaaaaaaa
sunshine
princess
welcome
monkey
dragon
letmein
master
freedom
whatever
superman
batman
trustno1`
	_, _ = s.db.Exec("INSERT OR IGNORE INTO dicts(dtype, content) VALUES('username', ?), ('password', ?)",
		usernames, passwords)
}

func (s *Store) count(table string) (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n, err
}
