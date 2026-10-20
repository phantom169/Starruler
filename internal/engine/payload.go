package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"starruler/internal/auth"
	"starruler/internal/baseline"
	"starruler/internal/discover"
	"starruler/internal/model"
	"starruler/internal/weakpwd"
)

// SvcTarget 弱口令目标服务。
type SvcTarget struct {
	IP     string            `json:"ip"`
	Port   int               `json:"port"`
	Type   string            `json:"type"`
	Params map[string]string `json:"params,omitempty"`
}

// ShardPayload 分片执行所需的完整自包含数据（本地与远程探针统一）。
type ShardPayload struct {
	ShardID  int64  `json:"shard_id"`
	TaskID   int64  `json:"task_id"`
	TaskType string `json:"task_type"` // discover / discover_weakpwd / weakpwd / baseline
	Kind     string `json:"kind"`

	// discover
	CIDRs      []string            `json:"cidrs,omitempty"`
	PortPolicy discover.PortPolicy `json:"port_policy,omitempty"`
	ScanConc   int                 `json:"scan_conc,omitempty"`

	// weakpwd（含发现即测）
	Services  []SvcTarget    `json:"services,omitempty"`
	Usernames []string       `json:"usernames,omitempty"`
	Passwords []string       `json:"passwords,omitempty"`
	WeakOpts  weakpwd.Options `json:"weak_opts,omitempty"`

	// baseline
	Assets      []model.Asset    `json:"assets,omitempty"`
	BaselinePacks []*baseline.Pack `json:"baseline_packs,omitempty"`
	CheckTimeout time.Duration   `json:"check_timeout,omitempty"`
}

// ShardReport 分片执行结果（回传中心统一落库）。
type ShardReport struct {
	ShardID int64 `json:"shard_id"`
	TaskID  int64 `json:"task_id"`
	Error   string `json:"error,omitempty"`

	Hosts           []model.Host        `json:"hosts,omitempty"`
	Services        []model.Service     `json:"services,omitempty"`
	WeakResults     []model.WeakResult  `json:"weak_results,omitempty"`
	BaselineResults []model.BaselineResult `json:"baseline_results,omitempty"`
	Stats           map[string]int64    `json:"stats,omitempty"`
}

// SupportedProtocols 支持的弱口令协议清单。
func SupportedProtocols() []string { return auth.Protocols() }

// RunShard 执行一个分片：纯函数，无 DB 依赖，本地与远程探针共用。
func RunShard(ctx context.Context, p ShardPayload) *ShardReport {
	rep := &ShardReport{ShardID: p.ShardID, TaskID: p.TaskID, Stats: map[string]int64{}}
	fail := func(err error) *ShardReport {
		rep.Error = err.Error()
		return rep
	}
	switch p.Kind {
	case "discover":
		return runDiscover(ctx, p, rep, fail)
	case "weakpwd":
		return runWeakpwd(ctx, p, rep, fail)
	case "baseline":
		return runBaseline(ctx, p, rep, fail)
	default:
		return fail(fmt.Errorf("未知分片类型 %s", p.Kind))
	}
}

// ---------- 发现（可选发现即测） ----------

func runDiscover(ctx context.Context, p ShardPayload, rep *ShardReport, fail func(error) *ShardReport) *ShardReport {
	var ips []string
	for _, cidr := range p.CIDRs {
		list, err := discover.ExpandCIDR(cidr)
		if err != nil {
			return fail(err)
		}
		ips = append(ips, list...)
	}
	if p.PortPolicy.Timeout == 0 {
		p.PortPolicy.Timeout = 2 * time.Second
	}
	conc := p.ScanConc
	if conc <= 0 {
		conc = 256
	}
	results := discover.ScanSubnet(ctx, ips, p.PortPolicy, false, conc)
	now := time.Now()
	for _, hr := range results {
		if !hr.Alive {
			continue
		}
		rep.Hosts = append(rep.Hosts, model.Host{IP: hr.IP, Source: "discovered", FirstSeen: now, LastSeen: now})
		for _, port := range hr.Ports {
			id := discover.Identify(hr.IP, port)
			rep.Services = append(rep.Services, model.Service{
				IP: hr.IP, Port: port, Type: id.Type,
				Banner: id.Banner, Confidence: id.Confidence,
			})
		}
	}
	rep.Stats["alive"] = int64(len(rep.Hosts))
	rep.Stats["open_ports"] = int64(len(rep.Services))

	// 发现即测：对识别出的可爆破服务直接进入弱口令引擎
	if p.TaskType == "discover_weakpwd" && len(rep.Services) > 0 {
		targets := buildTargets(rep.Services, p.Usernames)
		if len(targets) > 0 {
			eng := weakpwd.New(ctx, p.WeakOpts)
			stats, hits := eng.Run(targets, p.Passwords)
			rep.WeakResults = append(rep.WeakResults, hits...)
			mergeStats(rep.Stats, stats)
		}
	}
	return rep
}

// ---------- 弱口令（对已入库服务） ----------

func runWeakpwd(ctx context.Context, p ShardPayload, rep *ShardReport, fail func(error) *ShardReport) *ShardReport {
	targets := buildTargetsFromSvc(p.Services, p.Usernames)
	if len(targets) == 0 {
		return rep
	}
	eng := weakpwd.New(ctx, p.WeakOpts)
	stats, hits := eng.Run(targets, p.Passwords)
	rep.WeakResults = append(rep.WeakResults, hits...)
	mergeStats(rep.Stats, stats)
	return rep
}

// buildTargets 服务×用户名 → 爆破目标（跳过 unknown 类型与不可爆破协议）。
func buildTargets(services []model.Service, usernames []string) []weakpwd.Target {
	svcs := make([]SvcTarget, 0, len(services))
	for _, s := range services {
		svcs = append(svcs, SvcTarget{IP: s.IP, Port: s.Port, Type: s.Type})
	}
	return buildTargetsFromSvc(svcs, usernames)
}

func buildTargetsFromSvc(svcs []SvcTarget, usernames []string) []weakpwd.Target {
	var targets []weakpwd.Target
	for _, s := range svcs {
		if _, ok := auth.Get(s.Type); !ok {
			continue // unknown / 无认证器的类型不盲爆
		}
		for _, u := range usernames {
			targets = append(targets, weakpwd.Target{IP: s.IP, Port: s.Port, Protocol: s.Type, Params: s.Params, Username: u})
		}
	}
	return targets
}

// ---------- 基线核查 ----------

func runBaseline(ctx context.Context, p ShardPayload, rep *ShardReport, fail func(error) *ShardReport) *ShardReport {
	timeout := p.CheckTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	packMap := map[string]*baseline.Pack{}
	for _, pk := range p.BaselinePacks {
		packMap[pk.Target] = pk
	}
	for _, a := range p.Assets {
		pack, ok := packMap[a.SubType]
		if !ok {
			continue
		}
		collector, ok := baseline.GetCollector(pack.Collector)
		if !ok {
			continue
		}
		for _, item := range pack.Items {
			if ctx.Err() != nil {
				return rep
			}
			cmd := renderVars(item.Command, a.Vars)
			ok, out, errDetail := collector.Exec(ctx, a, cmd, timeout)
			passed, actual, detail := baseline.Compare(item, ok, out)
			if errDetail != "" {
				detail = errDetail
			}
			rep.BaselineResults = append(rep.BaselineResults, model.BaselineResult{
				AssetIP: a.IP, AssetName: a.Name, Target: pack.Target,
				RuleID: item.ID, Title: item.Title, Control: item.Control, Ref: item.Ref,
				Severity: item.Severity, Actual: actual, Expected: item.Expected,
				Passed: passed, Remediation: item.Remediation, Detail: detail,
			})
		}
	}
	rep.Stats["baseline_checks"] = int64(len(rep.BaselineResults))
	return rep
}

// renderVars 渲染规则命令中的模板变量 {tomcat_home} 等。
func renderVars(cmd string, vars map[string]string) string {
	for k, v := range vars {
		cmd = strings.ReplaceAll(cmd, "{"+k+"}", v)
	}
	return cmd
}

func mergeStats(dst map[string]int64, s weakpwd.Stats) {
	dst["weak_attempts"] += s.Attempts
	dst["weak_hits"] += s.Hits
	dst["weak_errors"] += s.Errors
	dst["weak_skipped"] += s.Skipped
	dst["weak_manual"] += s.Manual
}
