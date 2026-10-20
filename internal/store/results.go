package store

import (
	"starruler/internal/model"
)

// ---------- weak_results ----------

func (s *Store) InsertWeakResults(taskID int64, rs []model.WeakResult) error {
	if len(rs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO weak_results(task_id, ip, protocol, port, username, password, detail, manual)
		VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rs {
		if _, err := stmt.Exec(taskID, r.IP, r.Protocol, r.Port, r.Username, r.Password, r.Detail, r.Manual); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListWeakResults(taskID int64) ([]model.WeakResult, error) {
	rows, err := s.db.Query(`SELECT id, task_id, ip, protocol, port, username, password, detail, manual, found_at
		FROM weak_results WHERE task_id=? ORDER BY ip, protocol, port`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.WeakResult{}
	for rows.Next() {
		var r model.WeakResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.IP, &r.Protocol, &r.Port, &r.Username, &r.Password, &r.Detail, &r.Manual, &r.FoundAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------- baseline_results ----------

func (s *Store) InsertBaselineResults(taskID int64, rs []model.BaselineResult) error {
	if len(rs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO baseline_results(task_id, asset_ip, asset_name, target, rule_id, title,
		control, ref, severity, actual, expected, passed, remediation, detail)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rs {
		if _, err := stmt.Exec(taskID, r.AssetIP, r.AssetName, r.Target, r.RuleID, r.Title,
			r.Control, r.Ref, r.Severity, r.Actual, r.Expected, r.Passed, r.Remediation, r.Detail); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

type BaselineFilter struct {
	Passed   *int
	Severity string
	Target   string
}

func (s *Store) ListBaselineResults(taskID int64, f BaselineFilter) ([]model.BaselineResult, error) {
	q := `SELECT id, task_id, asset_ip, asset_name, target, rule_id, title, control, ref, severity,
		actual, expected, passed, remediation, detail, checked_at FROM baseline_results WHERE task_id=?`
	args := []any{taskID}
	if f.Passed != nil {
		q += " AND passed=?"
		args = append(args, *f.Passed)
	}
	if f.Severity != "" {
		q += " AND severity=?"
		args = append(args, f.Severity)
	}
	if f.Target != "" {
		q += " AND target=?"
		args = append(args, f.Target)
	}
	q += " ORDER BY asset_ip, rule_id"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BaselineResult{}
	for rows.Next() {
		var r model.BaselineResult
		if err := rows.Scan(&r.ID, &r.TaskID, &r.AssetIP, &r.AssetName, &r.Target, &r.RuleID, &r.Title,
			&r.Control, &r.Ref, &r.Severity, &r.Actual, &r.Expected, &r.Passed, &r.Remediation, &r.Detail, &r.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------- dicts ----------

func (s *Store) GetDicts() (map[string]string, error) {
	rows, err := s.db.Query("SELECT dtype, content FROM dicts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		out[t] = c
	}
	return out, nil
}

func (s *Store) UpdateDict(dtype, content string) error {
	_, err := s.db.Exec("UPDATE dicts SET content=? WHERE dtype=?", content, dtype)
	return err
}
