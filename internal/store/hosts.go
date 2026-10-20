package store

import (
	"starruler/internal/model"
)

// ---------- hosts ----------

func (s *Store) UpsertHost(ip, source, osGuess string) (int64, error) {
	_, err := s.db.Exec(`INSERT INTO hosts(ip, source, os_guess) VALUES(?,?,?)
		ON CONFLICT(ip) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, os_guess=CASE WHEN ?<>'' THEN ? ELSE os_guess END`,
		ip, source, osGuess, osGuess, osGuess)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRow("SELECT id FROM hosts WHERE ip=?", ip).Scan(&id)
	return id, err
}

func (s *Store) ListHosts(keyword string, limit, offset int) ([]model.Host, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if keyword != "" {
		where += " AND ip LIKE ?"
		args = append(args, "%"+keyword+"%")
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM hosts"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := "SELECT id, ip, source, os_guess, note, first_seen, last_seen FROM hosts" + where + " ORDER BY ip LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []model.Host{} // 空结果返回 [] 而非 null（前端兼容）
	for rows.Next() {
		var h model.Host
		if err := rows.Scan(&h.ID, &h.IP, &h.Source, &h.OSGuess, &h.Note, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, nil
}

// ---------- services ----------

// UpsertService 幂等写入发现的服务；人工指认(manual)不会被自动结果覆盖。
func (s *Store) UpsertService(hostID int64, ip string, port int, svcType, banner string, confidence int) error {
	_, err := s.db.Exec(`INSERT INTO services(host_id, ip, port, type, banner, confidence)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(ip, port) DO UPDATE SET
		  last_seen=CURRENT_TIMESTAMP,
		  type=CASE WHEN services.manual=1 THEN services.type ELSE excluded.type END,
		  banner=CASE WHEN services.manual=1 THEN services.banner ELSE excluded.banner END,
		  confidence=CASE WHEN services.manual=1 THEN services.confidence ELSE excluded.confidence END`,
		hostID, ip, port, svcType, banner, confidence)
	return err
}

func (s *Store) ListServices(ip string) ([]model.Service, error) {
	rows, err := s.db.Query(`SELECT id, host_id, ip, port, type, banner, confidence, manual
		FROM services WHERE ip=? ORDER BY port`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Service{}
	for rows.Next() {
		var v model.Service
		if err := rows.Scan(&v.ID, &v.HostID, &v.IP, &v.Port, &v.Type, &v.Banner, &v.Confidence, &v.Manual); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// ListServicesByTypes 取指定类型的全部服务（弱口令任务消费）。
func (s *Store) ListServicesByTypes(types []string) ([]model.Service, error) {
	if len(types) == 0 {
		return nil, nil
	}
	q := `SELECT id, host_id, ip, port, type, banner, confidence, manual FROM services WHERE type IN (`
	args := []any{}
	for i, t := range types {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, t)
	}
	q += ") ORDER BY ip, port"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Service{}
	for rows.Next() {
		var v model.Service
		if err := rows.Scan(&v.ID, &v.HostID, &v.IP, &v.Port, &v.Type, &v.Banner, &v.Confidence, &v.Manual); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// AssignServiceType 人工指认服务类型（覆盖自动识别）。
func (s *Store) AssignServiceType(id int64, svcType string) error {
	_, err := s.db.Exec("UPDATE services SET type=?, manual=1 WHERE id=?", svcType, id)
	return err
}

// ServiceStats 各类型服务数量统计（仪表盘）。
func (s *Store) ServiceStats() (map[string]int, error) {
	rows, err := s.db.Query("SELECT type, COUNT(*) FROM services GROUP BY type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, nil
}

func (s *Store) Count(table string, where string, args ...any) (int, error) {
	q := "SELECT COUNT(*) FROM " + table
	if where != "" {
		q += " WHERE " + where
	}
	var n int
	err := s.db.QueryRow(q, args...).Scan(&n)
	return n, err
}
