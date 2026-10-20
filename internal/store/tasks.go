package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"starruler/internal/model"
)

// ---------- tasks ----------

func (s *Store) CreateTask(t *model.Task) (int64, error) {
	cfg, _ := json.Marshal(t.Config)
	stats, _ := json.Marshal(t.Stats)
	res, err := s.db.Exec(`INSERT INTO tasks(name, type, status, config, stats) VALUES(?,?,?,?,?)`,
		t.Name, t.Type, "pending", string(cfg), string(stats))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateTaskStatus(id int64, status, errMsg string) error {
	if status == "done" || status == "failed" || status == "canceled" {
		_, err := s.db.Exec("UPDATE tasks SET status=?, error=?, finished_at=CURRENT_TIMESTAMP WHERE id=?", status, errMsg, id)
		return err
	}
	_, err := s.db.Exec("UPDATE tasks SET status=?, error=? WHERE id=?", status, errMsg, id)
	return err
}

func (s *Store) UpdateTaskStats(id int64, stats map[string]any) error {
	b, _ := json.Marshal(stats)
	_, err := s.db.Exec("UPDATE tasks SET stats=? WHERE id=?", string(b), id)
	return err
}

func (s *Store) GetTask(id int64) (*model.Task, error) {
	var t model.Task
	var cfg, stats string
	var finished sql.NullTime
	err := s.db.QueryRow(`SELECT id, name, type, status, config, stats, error, created_at, finished_at
		FROM tasks WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.Type, &t.Status, &cfg, &stats, &t.Error, &t.CreatedAt, &finished)
	if err != nil {
		return nil, err
	}
	t.Config, t.Stats = map[string]any{}, map[string]any{}
	_ = json.Unmarshal([]byte(cfg), &t.Config)
	_ = json.Unmarshal([]byte(stats), &t.Stats)
	if finished.Valid {
		t.FinishedAt = &finished.Time
	}
	return &t, nil
}

func (s *Store) ListTasks(limit int) ([]model.Task, error) {
	rows, err := s.db.Query(`SELECT id, name, type, status, config, stats, error, created_at, finished_at
		FROM tasks ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Task{}
	for rows.Next() {
		var t model.Task
		var cfg, stats string
		var finished sql.NullTime
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Status, &cfg, &stats, &t.Error, &t.CreatedAt, &finished); err != nil {
			return nil, err
		}
		t.Config, t.Stats = map[string]any{}, map[string]any{}
		_ = json.Unmarshal([]byte(cfg), &t.Config)
		_ = json.Unmarshal([]byte(stats), &t.Stats)
		if finished.Valid {
			t.FinishedAt = &finished.Time
		}
		out = append(out, t)
	}
	return out, nil
}

// ---------- shards ----------

func (s *Store) CreateShards(taskID int64, kind string, ranges []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("INSERT INTO shards(task_id, kind, range_key, status) VALUES(?,?,?,'pending')")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range ranges {
		if _, err := stmt.Exec(taskID, kind, r); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ClaimShard 原子认领一个 pending 分片（多探针并发安全）。
// 仅认领未结束（pending/running）任务的分片 —— 暂停/取消的任务不再派发。
func (s *Store) ClaimShard(taskID int64, probeID int64) (*model.Shard, error) {
	q := `SELECT s.id, s.task_id, s.kind, s.range_key FROM shards s
		JOIN tasks t ON t.id = s.task_id
		WHERE s.status='pending' AND t.status IN ('pending','running')`
	args := []any{}
	if taskID > 0 {
		q += ` AND s.task_id=?`
		args = append(args, taskID)
	}
	q += ` LIMIT 1`
	var id, tid int64
	var kind, rangeKey string
	err := s.db.QueryRow(q, args...).Scan(&id, &tid, &kind, &rangeKey)
	if err != nil {
		return nil, err // sql.ErrNoRows 表示没有可领分片
	}
	res, err := s.db.Exec(`UPDATE shards SET status='running', probe_id=?, claimed_at=CURRENT_TIMESTAMP
		WHERE id=? AND status='pending'`, probeID, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, sql.ErrNoRows // 被别人抢走，等下一轮
	}
	return &model.Shard{ID: id, TaskID: tid, Kind: kind, RangeKey: rangeKey, ProbeID: probeID, Status: "running", ClaimedAt: time.Now()}, nil
}

// DeleteTask 彻底删除任务：连同分片与全部结果。
func (s *Store) DeleteTask(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmts := []string{
		"DELETE FROM shards WHERE task_id=?",
		"DELETE FROM weak_results WHERE task_id=?",
		"DELETE FROM baseline_results WHERE task_id=?",
		"DELETE FROM tasks WHERE id=?",
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// OnlineRemoteProbes 在线远程探针数量（本地探针不在 probes 表）。
func (s *Store) OnlineRemoteProbes() int {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM probes WHERE status='online'").Scan(&n)
	return n
}

// PendingShardCount 可领取（pending 且任务未结束）的分片数。
func (s *Store) PendingShardCount() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM shards s JOIN tasks t ON t.id=s.task_id
		WHERE s.status='pending' AND t.status IN ('pending','running')`).Scan(&n)
	return n
}

// CancelPendingShards 取消任务的全部 pending 分片（任务取消时）。
func (s *Store) CancelPendingShards(taskID int64) error {
	_, err := s.db.Exec("UPDATE shards SET status='canceled', done_at=CURRENT_TIMESTAMP WHERE task_id=? AND status='pending'", taskID)
	return err
}

func (s *Store) FinishShard(id int64, status, errMsg string) error {
	_, err := s.db.Exec("UPDATE shards SET status=?, error=?, done_at=CURRENT_TIMESTAMP WHERE id=?", status, errMsg, id)
	return err
}

func (s *Store) ShardCounts(taskID int64) (pending, running, done, failed int, err error) {
	rows, err := s.db.Query("SELECT status, COUNT(*) FROM shards WHERE task_id=? GROUP BY status", taskID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if scanErr := rows.Scan(&st, &n); scanErr != nil {
			return 0, 0, 0, 0, scanErr
		}
		switch st {
		case "pending":
			pending = n
		case "running":
			running = n
		case "done":
			done = n
		case "failed":
			failed = n
		}
	}
	return
}

// RecycleStaleShards 回收超时未完成的 running 分片（失联探针）。
func (s *Store) RecycleStaleShards(before time.Time) (int64, error) {
	res, err := s.db.Exec(`UPDATE shards SET status='pending', probe_id=0, claimed_at=NULL
		WHERE status='running' AND claimed_at < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// NextPendingTask 取一个有 pending 分片且未结束的任务。
func (s *Store) NextPendingTask() (*model.Task, error) {
	row := s.db.QueryRow(`SELECT t.id FROM tasks t
		JOIN shards s ON s.task_id = t.id AND s.status='pending'
		WHERE t.status IN ('pending','running') LIMIT 1`)
	var id int64
	if err := row.Scan(&id); err != nil {
		return nil, err
	}
	return s.GetTask(id)
}
