package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	"starruler/internal/model"
)

// NewToken 生成 32 位十六进制注册令牌。
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) CreateProbe(name, bindIP string) (*model.Probe, error) {
	token := NewToken()
	res, err := s.db.Exec(`INSERT INTO probes(name, token, bind_ip, status) VALUES(?,?,?,'offline')`,
		name, token, bindIP)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &model.Probe{ID: id, Name: name, Token: token, BindIP: bindIP, Status: "offline"}, nil
}

func (s *Store) ListProbes() ([]model.Probe, error) {
	rows, err := s.db.Query(`SELECT id, name, token, bind_ip, status, hostname, source_ip, version, last_seen, created_at
		FROM probes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Probe{}
	for rows.Next() {
		var p model.Probe
		var lastSeen sql.NullTime
		if err := rows.Scan(&p.ID, &p.Name, &p.Token, &p.BindIP, &p.Status, &p.Hostname, &p.SourceIP, &p.Version, &lastSeen, &p.CreatedAt); err != nil {
			return nil, err
		}
		if lastSeen.Valid {
			p.LastSeen = lastSeen.Time
		}
		out = append(out, p)
	}
	return out, nil
}

// AuthProbe 校验注册/轮询：token 有效、未禁用、来源 IP 匹配（如绑定）。
// 返回探针记录并刷新心跳。
func (s *Store) AuthProbe(token, sourceIP string) (*model.Probe, error) {
	var p model.Probe
	var lastSeen sql.NullTime
	err := s.db.QueryRow(`SELECT id, name, token, bind_ip, status, hostname, source_ip, version, last_seen, created_at
		FROM probes WHERE token=?`, token).
		Scan(&p.ID, &p.Name, &p.Token, &p.BindIP, &p.Status, &p.Hostname, &p.SourceIP, &p.Version, &lastSeen, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	if p.Status == "disabled" {
		return nil, sql.ErrNoRows
	}
	if p.BindIP != "" && p.BindIP != sourceIP {
		return nil, sql.ErrNoRows
	}
	_, _ = s.db.Exec("UPDATE probes SET status='online', source_ip=?, last_seen=CURRENT_TIMESTAMP WHERE id=?", sourceIP, p.ID)
	p.Status = "online"
	p.SourceIP = sourceIP
	return &p, nil
}

// UpdateProbeInfo 探针注册时上报主机信息。
func (s *Store) UpdateProbeInfo(id int64, hostname, version string) error {
	_, err := s.db.Exec("UPDATE probes SET hostname=?, version=? WHERE id=?", hostname, version, id)
	return err
}

// MarkOfflineProbes 心跳超时的探针置离线。
func (s *Store) MarkOfflineProbes(before time.Time) {
	_, _ = s.db.Exec("UPDATE probes SET status='offline' WHERE last_seen < ? AND status='online'", before)
}

func (s *Store) SetProbeStatus(id int64, status string) error {
	_, err := s.db.Exec("UPDATE probes SET status=? WHERE id=?", status, id)
	return err
}

func (s *Store) DeleteProbe(id int64) error {
	_, err := s.db.Exec("DELETE FROM probes WHERE id=?", id)
	return err
}
