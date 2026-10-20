package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"starruler/internal/discover"
	"starruler/internal/model"
	"starruler/internal/rules"
	"starruler/internal/store"
	"starruler/internal/weakpwd"
)

// Scheduler 中心调度器：任务→分片→派发（本地/远程探针）→结果落库→进度聚合。
type Scheduler struct {
	st    *store.Store
	rules *rules.Store

	mu        sync.Mutex
	cancelFns map[int64]context.CancelFunc // 运行中任务的本地取消
	dictCache map[string][]string
	dictAt    time.Time
}

func NewScheduler(st *store.Store, rs *rules.Store) *Scheduler {
	return &Scheduler{st: st, rules: rs, cancelFns: map[int64]context.CancelFunc{}}
}

// ---------- 任务提交：配置 → 分片 ----------

// Submit 解析任务配置并生成分片入库。任务类型：
//   discover / discover_weakpwd: cidrs → 网段桶(256 IP/桶)
//   weakpwd: config.services → 25个/桶
//   baseline: config.asset_ids → 25个/桶
func (s *Scheduler) Submit(task *model.Task) error {
	cfgJSON, _ := json.Marshal(task.Config)
	task.Config = map[string]any{}
	_ = json.Unmarshal(cfgJSON, &task.Config)

	var kinds []string
	var ranges []string
	switch task.Type {
	case "discover", "discover_weakpwd":
		cidrs := strSlice(task.Config["cidrs"])
		if len(cidrs) == 0 {
			return errNew("网段列表不能为空")
		}
		if task.Type == "discover_weakpwd" {
			s.fillDicts(task)
		}
		for _, cidr := range cidrs {
			ips, err := discover.ExpandCIDR(cidr)
			if err != nil {
				return errNew("网段 %s 非法: %v", cidr, err)
			}
			for i := 0; i < len(ips); i += 256 {
				end := i + 255
				if end >= len(ips) {
					end = len(ips) - 1
				}
				ranges = append(ranges, "range:"+ips[i]+"-"+ips[end])
			}
		}
		kinds = []string{"discover"}
	case "weakpwd":
		svcs := parseServices(task.Config["services"])
		if len(svcs) == 0 {
			return errNew("未选择任何服务")
		}
		s.fillDicts(task)
		for i := 0; i < len(svcs); i += 25 {
			end := i + 24
			if end >= len(svcs) {
				end = len(svcs) - 1
			}
			ranges = append(ranges, "svc:"+strconv.Itoa(i)+"-"+strconv.Itoa(end))
		}
		kinds = []string{"weakpwd"}
	case "baseline":
		ids := int64Slice(task.Config["asset_ids"])
		if len(ids) == 0 {
			return errNew("未选择任何资产")
		}
		for i := 0; i < len(ids); i += 25 {
			end := i + 24
			if end >= len(ids) {
				end = len(ids) - 1
			}
			ranges = append(ranges, "asset:"+strconv.Itoa(i)+"-"+strconv.Itoa(end))
		}
		kinds = []string{"baseline"}
	case "full":
		return errNew("full 任务请拆分为 discover_weakpwd + baseline")
	default:
		return errNew("未知任务类型 %s", task.Type)
	}

	id, err := s.st.CreateTask(task)
	if err != nil {
		return err
	}
	task.ID = id
	for _, k := range kinds {
		if err := s.st.CreateShards(id, k, ranges); err != nil {
			return err
		}
	}
	return nil
}

// fillDicts 未显式指定字典时填充内置字典。
func (s *Scheduler) fillDicts(task *model.Task) {
	if strSlice(task.Config["usernames"]) == nil || strSlice(task.Config["passwords"]) == nil {
		u, p := s.dicts()
		if task.Config["usernames"] == nil {
			task.Config["usernames"] = u
		}
		if task.Config["passwords"] == nil {
			task.Config["passwords"] = p
		}
	}
}

func (s *Scheduler) dicts() ([]string, []string) {
	if s.dictCache != nil && time.Since(s.dictAt) < time.Minute {
		return s.dictCache["u"], s.dictCache["p"]
	}
	m, err := s.st.GetDicts()
	if err != nil {
		return nil, nil
	}
	u := splitLines(m["username"])
	p := splitLines(m["password"])
	s.dictCache = map[string][]string{"u": u, "p": p}
	s.dictAt = time.Now()
	return u, p
}

// ---------- 派发循环 ----------

// DispatchLoop 本地探针：持续认领分片执行。
// 有在线远程探针时为其保留等量 pending 分片，避免本地抢空。
func (s *Scheduler) DispatchLoop() {
	for {
		reserve := s.st.OnlineRemoteProbes()
		for {
			if reserve > 0 && s.st.PendingShardCount() <= reserve {
				break // 留给远程探针
			}
			shard, err := s.st.ClaimShard(0, 0) // 任意任务，本地探针 probe_id=0
			if err != nil {
				break
			}
			task, err := s.st.GetTask(shard.TaskID)
			if err != nil || task.Status == "canceled" {
				_ = s.st.FinishShard(shard.ID, "canceled", "")
				continue
			}
			payload, err := s.BuildPayload(task, shard)
			if err != nil {
				_ = s.st.FinishShard(shard.ID, "failed", err.Error())
				continue
			}
			_ = s.st.UpdateTaskStatus(task.ID, "running", "")
			ctx := s.taskCtx(task.ID)
			go func() {
				rep := RunShard(ctx, *payload)
				s.ApplyReport(rep)
			}()
		}
		s.checkFinishedTasks()
		time.Sleep(1500 * time.Millisecond)
	}
}

// RecoverLoop 分片回收（失联探针）+ 探针离线标记。
func (s *Scheduler) RecoverLoop() {
	for {
		time.Sleep(30 * time.Second)
		if n, err := s.st.RecycleStaleShards(time.Now().Add(-5 * time.Minute)); err == nil && n > 0 {
			log.Printf("[scheduler] 回收失联分片 %d 个", n)
		}
		s.st.MarkOfflineProbes(time.Now().Add(-90 * time.Second))
		s.checkFinishedTasks()
	}
}

// ClaimForRemote 远程探领取分片（/probe/poll 调用）。
func (s *Scheduler) ClaimForRemote(probeID int64) (*ShardPayload, error) {
	shard, err := s.st.ClaimShard(0, probeID)
	if err != nil {
		return nil, err
	}
	task, err := s.st.GetTask(shard.TaskID)
	if err != nil || task.Status == "canceled" {
		_ = s.st.FinishShard(shard.ID, "canceled", "")
		return nil, errNew("任务已取消")
	}
	payload, err := s.BuildPayload(task, shard)
	if err != nil {
		_ = s.st.FinishShard(shard.ID, "failed", err.Error())
		return nil, err
	}
	_ = s.st.UpdateTaskStatus(task.ID, "running", "")
	return payload, nil
}

// BuildPayload 按分片类型组装自包含执行数据。
func (s *Scheduler) BuildPayload(task *model.Task, shard *model.Shard) (*ShardPayload, error) {
	p := &ShardPayload{
		ShardID: shard.ID, TaskID: task.ID,
		TaskType: task.Type, Kind: shard.Kind,
	}
	switch {
	case strings.HasPrefix(shard.RangeKey, "range:"):
		rg := strings.TrimPrefix(shard.RangeKey, "range:")
		parts := strings.SplitN(rg, "-", 2)
		p.CIDRs = []string{parts[0] + "-" + parts[1]}
		p.PortPolicy = discover.PortPolicy{
			Mode:    strOr(task.Config["port_mode"], "top"),
			Custom:  intSlice(task.Config["custom_ports"]),
			Timeout: 2 * time.Second,
		}
		p.ScanConc = intOr(task.Config["scan_conc"], 256)
		if task.Type == "discover_weakpwd" {
			p.Usernames = strSlice(task.Config["usernames"])
			p.Passwords = strSlice(task.Config["passwords"])
			p.WeakOpts = parseWeakOpts(task.Config["weak_opts"])
		}
	case strings.HasPrefix(shard.RangeKey, "svc:"):
		rg := strings.TrimPrefix(shard.RangeKey, "svc:")
		i, j := rangeBounds(rg)
		svcs := parseServices(task.Config["services"])
		if j >= len(svcs) {
			j = len(svcs) - 1
		}
		p.Services = svcs[i : j+1]
		p.Usernames = strSlice(task.Config["usernames"])
		p.Passwords = strSlice(task.Config["passwords"])
		p.WeakOpts = parseWeakOpts(task.Config["weak_opts"])
	case strings.HasPrefix(shard.RangeKey, "asset:"):
		rg := strings.TrimPrefix(shard.RangeKey, "asset:")
		i, j := rangeBounds(rg)
		ids := int64Slice(task.Config["asset_ids"])
		if j >= len(ids) {
			j = len(ids) - 1
		}
		assets, err := s.st.GetAssetsByIDs(ids[i : j+1])
		if err != nil {
			return nil, err
		}
		p.Assets = assets
		seen := map[string]bool{}
		for _, a := range assets {
			if !seen[a.SubType] {
				if pack, ok := s.rules.Get(a.SubType); ok {
					p.BaselinePacks = append(p.BaselinePacks, pack)
					seen[a.SubType] = true
				}
			}
		}
		p.CheckTimeout = 15 * time.Second
	default:
		return nil, errNew("无法解析分片范围 %s", shard.RangeKey)
	}
	return p, nil
}

// ApplyReport 分片结果统一落库（本地与远程探针共用）。
func (s *Scheduler) ApplyReport(r *ShardReport) {
	if r == nil {
		return
	}
	task, err := s.st.GetTask(r.TaskID)
	if err != nil {
		return
	}
	if task.Status == "canceled" {
		_ = s.st.FinishShard(r.ShardID, "canceled", "")
		return
	}
	for _, h := range r.Hosts {
		_, _ = s.st.UpsertHost(h.IP, "discovered", "")
	}
	if len(r.Hosts) > 0 {
		// 关联 host_id
		for _, sv := range r.Services {
			var hid int64
			_ = s.st.DB().QueryRow("SELECT id FROM hosts WHERE ip=?", sv.IP).Scan(&hid)
			_ = s.st.UpsertService(hid, sv.IP, sv.Port, sv.Type, sv.Banner, sv.Confidence)
		}
	}
	if len(r.WeakResults) > 0 {
		_ = s.st.InsertWeakResults(r.TaskID, r.WeakResults)
	}
	if len(r.BaselineResults) > 0 {
		_ = s.st.InsertBaselineResults(r.TaskID, r.BaselineResults)
	}
	status := "done"
	if r.Error != "" {
		status = "failed"
	}
	_ = s.st.FinishShard(r.ShardID, status, r.Error)
	s.mergeTaskStats(r)
	s.checkFinishedTasks()
}

func (s *Scheduler) mergeTaskStats(r *ShardReport) {
	task, err := s.st.GetTask(r.TaskID)
	if err != nil {
		return
	}
	stats := task.Stats
	if stats == nil {
		stats = map[string]any{}
	}
	for k, v := range r.Stats {
		if cur, ok := stats[k].(float64); ok {
			stats[k] = cur + float64(v)
		} else {
			stats[k] = float64(v)
		}
	}
	p, run, d, f, _ := s.st.ShardCounts(r.TaskID)
	stats["shards_pending"] = float64(p)
	stats["shards_running"] = float64(run)
	stats["shards_done"] = float64(d)
	stats["shards_failed"] = float64(f)
	stats["shards_total"] = float64(p + run + d + f)
	_ = s.st.UpdateTaskStats(r.TaskID, stats)
}

func (s *Scheduler) checkFinishedTasks() {
	tasks, err := s.st.ListTasks(50)
	if err != nil {
		return
	}
	for _, t := range tasks {
		if t.Status != "running" && t.Status != "pending" {
			continue
		}
		p, run, d, f, _ := s.st.ShardCounts(t.ID)
		if p+run == 0 && d+f > 0 {
			status := "done"
			if d == 0 && f > 0 {
				status = "failed"
			}
			_ = s.st.UpdateTaskStatus(t.ID, status, "")
			s.mu.Lock()
			if cancel, ok := s.cancelFns[t.ID]; ok {
				cancel()
				delete(s.cancelFns, t.ID)
			}
			s.mu.Unlock()
		} else if p+run+d+f == 0 {
			_ = s.st.UpdateTaskStatus(t.ID, "failed", "无有效分片")
		}
	}
}

// Cancel 取消任务。
func (s *Scheduler) Cancel(taskID int64) error {
	if err := s.st.UpdateTaskStatus(taskID, "canceled", ""); err != nil {
		return err
	}
	_ = s.st.CancelPendingShards(taskID)
	s.mu.Lock()
	if cancel, ok := s.cancelFns[taskID]; ok {
		cancel()
		delete(s.cancelFns, taskID)
	}
	s.mu.Unlock()
	return nil
}

// Pause 暂停任务：停止派发新分片，已在执行的分片跑完即挂起（可恢复）。
func (s *Scheduler) Pause(taskID int64) error {
	return s.st.UpdateTaskStatus(taskID, "paused", "")
}

// Resume 恢复已暂停任务：继续派发剩余 pending 分片。
func (s *Scheduler) Resume(taskID int64) error {
	return s.st.UpdateTaskStatus(taskID, "running", "")
}

func (s *Scheduler) taskCtx(taskID int64) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancelFns[taskID] = cancel
	s.mu.Unlock()
	return ctx
}

// ---------- 工具 ----------

func errNew(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}

func strSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case nil:
		return nil
	}
	return nil
}

func int64Slice(v any) []int64 {
	switch t := v.(type) {
	case []int64:
		return t
	case []any:
		var out []int64
		for _, e := range t {
			switch x := e.(type) {
			case float64:
				out = append(out, int64(x))
			case int64:
				out = append(out, x)
			}
		}
		return out
	}
	return nil
}

func intSlice(v any) []int {
	var out []int
	for _, x := range int64Slice(v) {
		out = append(out, int(x))
	}
	return out
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func intOr(v any, def int) int {
	if f, ok := v.(float64); ok && f > 0 {
		return int(f)
	}
	return def
}

func rangeBounds(rg string) (int, int) {
	parts := strings.SplitN(rg, "-", 2)
	i, _ := strconv.Atoi(parts[0])
	j, _ := strconv.Atoi(parts[1])
	return i, j
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func parseServices(v any) []SvcTarget {
	raw := strSlice(v)
	var out []SvcTarget
	for _, s := range raw {
		parts := strings.Split(s, "|")
		if len(parts) >= 3 {
			port, _ := strconv.Atoi(parts[1])
			out = append(out, SvcTarget{IP: parts[0], Port: port, Type: parts[2]})
		}
	}
	return out
}

func parseWeakOpts(v any) weakpwd.Options {
	o := weakpwd.Options{}
	if m, ok := v.(map[string]any); ok {
		if f, ok := m["concurrency"].(float64); ok {
			o.Concurrency = int(f)
		}
		if f, ok := m["timeout_sec"].(float64); ok {
			o.Timeout = time.Duration(f) * time.Second
		}
		if f, ok := m["max_try_per_user"].(float64); ok {
			o.MaxTryPerUser = int(f)
		}
		if s, ok := m["stop_on_hit"].(string); ok {
			o.StopOnHit = s
		}
	}
	return o
}
