package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"starruler/internal/config"
	"starruler/internal/engine"
	"starruler/internal/model"
	"starruler/internal/report"
	"starruler/internal/rules"
	"starruler/internal/store"
)

// Server API 路由与依赖。
type Server struct {
	st    *store.Store
	rules *rules.Store
	sched *engine.Scheduler
	cfg   *config.Config
	web   embed.FS
}

func New(st *store.Store, rs *rules.Store, sched *engine.Scheduler, cfg *config.Config, web embed.FS) *Server {
	return &Server{st: st, rules: rs, sched: sched, cfg: cfg, web: web}
}

// Serve 启动 HTTP 服务（带基础超时，防慢速连接占用资源）。
func Serve(addr string, st *store.Store, rs *rules.Store, sched *engine.Scheduler, cfg *config.Config, web embed.FS) error {
	srv := New(st, rs, sched, cfg, web)
	server := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute, // 报告/CSV 生成可能较慢
		IdleTimeout:       120 * time.Second,
	}
	return server.ListenAndServe()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ---- 管理面 ----
	mux.HandleFunc("GET /api/dashboard", s.dashboard)
	mux.HandleFunc("GET /api/hosts", s.listHosts)
	mux.HandleFunc("GET /api/hosts/{ip}/services", s.hostServices)
	mux.HandleFunc("POST /api/services/{id}/assign", s.assignService)
	mux.HandleFunc("GET /api/assets", s.listAssets)
	mux.HandleFunc("POST /api/assets", s.createAsset)
	mux.HandleFunc("PUT /api/assets/{id}", s.updateAsset)
	mux.HandleFunc("DELETE /api/assets/{id}", s.deleteAsset)
	mux.HandleFunc("POST /api/assets/from-hosts", s.assetsFromHosts)
	mux.HandleFunc("GET /api/services", s.listAllServices)
	mux.HandleFunc("GET /api/dicts", s.getDicts)
	mux.HandleFunc("PUT /api/dicts", s.putDicts)
	mux.HandleFunc("GET /api/rules", s.listRules)
	mux.HandleFunc("GET /api/tasks", s.listTasks)
	mux.HandleFunc("POST /api/tasks", s.createTask)
	mux.HandleFunc("GET /api/tasks/{id}", s.getTask)
	mux.HandleFunc("DELETE /api/tasks/{id}", s.deleteTask)
	mux.HandleFunc("POST /api/tasks/{id}/cancel", s.cancelTask)
	mux.HandleFunc("POST /api/tasks/{id}/pause", s.pauseTask)
	mux.HandleFunc("POST /api/tasks/{id}/resume", s.resumeTask)
	mux.HandleFunc("GET /api/tasks/{id}/weak", s.weakResults)
	mux.HandleFunc("GET /api/tasks/{id}/baseline", s.baselineResults)
	mux.HandleFunc("GET /api/report/{id}", s.htmlReport)
	mux.HandleFunc("GET /api/export/{id}", s.csvExport)
	mux.HandleFunc("GET /api/protocols", s.protocols)
	mux.HandleFunc("POST /api/nettool", s.netTool)

	// ---- 探针管理 ----
	mux.HandleFunc("GET /api/probes", s.listProbes)
	mux.HandleFunc("POST /api/probes", s.createProbe)
	mux.HandleFunc("PUT /api/probes/{id}", s.updateProbe)
	mux.HandleFunc("DELETE /api/probes/{id}", s.deleteProbe)
	mux.HandleFunc("GET /api/probe-binaries", s.probeBinaries)

	// ---- 探针信道（token 认证） ----
	mux.HandleFunc("POST /probe/register", s.probeRegister)
	mux.HandleFunc("GET /probe/poll", s.probePoll)
	mux.HandleFunc("POST /probe/report", s.probeReport)

	// ---- 前端（内嵌单页） ----
	mux.HandleFunc("GET /", s.serveWeb)

	// ---- 探针二进制下载（仅精确文件名，无目录列表） ----
	mux.HandleFunc("GET /download/probe/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := path.Base(r.PathValue("name")) // 防路径遍历
		http.ServeFile(w, r, filepath.Join(s.cfg.ProbeDir, name))
	})

	return mux
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	writeJSON(w, map[string]string{"error": msg})
}

func readBody[T any](r *http.Request, v *T) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return fmt.Errorf("空请求体")
	}
	return json.Unmarshal(b, v)
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- 仪表盘 ----------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.st.Count("hosts", "")
	svcs, _ := s.st.Count("services", "")
	hits, _ := s.st.Count("weak_results", "")
	noncomply, _ := s.st.Count("baseline_results", "passed=0")
	comply, _ := s.st.Count("baseline_results", "passed=1")
	manual, _ := s.st.Count("baseline_results", "passed=-1")
	tasks, _ := s.st.ListTasks(8)
	svcStats, _ := s.st.ServiceStats()
	writeJSON(w, map[string]any{
		"hosts": hosts, "services": svcs, "weak_hits": hits,
		"comply": comply, "non_comply": noncomply, "manual": manual,
		"recent_tasks": tasks, "service_stats": svcStats,
		"protocols": engine.SupportedProtocols(),
	})
}

// ---------- 主机与服务 ----------

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("keyword")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size := 50
	hosts, total, err := s.st.ListHosts(keyword, size, (page-1)*size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"items": hosts, "total": total, "page": page, "size": size})
}

func (s *Server) hostServices(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	svcs, err := s.st.ListServices(ip)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, svcs)
}

func (s *Server) listAllServices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	types := q["type"]
	svcs, err := s.st.ListServicesByTypes(types)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 支持按类型过滤（不传 type 时全量）
	writeJSON(w, svcs)
}

func (s *Server) assignService(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type string `json:"type"`
	}
	if err := readBody(r, &body); err != nil || body.Type == "" {
		writeErr(w, 400, "type 不能为空")
		return
	}
	if err := s.st.AssignServiceType(pathID(r), body.Type); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// ---------- 资产 ----------

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.st.ListAssets()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, assets)
}

func (s *Server) createAsset(w http.ResponseWriter, r *http.Request) {
	var a model.Asset
	if err := readBody(r, &a); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if a.IP == "" || a.Category == "" || a.SubType == "" {
		writeErr(w, 400, "ip/category/sub_type 必填")
		return
	}
	id, err := s.st.CreateAsset(&a)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	a.ID = id
	writeJSON(w, a)
}

func (s *Server) updateAsset(w http.ResponseWriter, r *http.Request) {
	var a model.Asset
	if err := readBody(r, &a); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a.ID = pathID(r)
	if err := s.st.UpdateAsset(&a); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) deleteAsset(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteAsset(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// assetsFromHosts 发现的主机一键转核查资产。
func (s *Server) assetsFromHosts(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs     []string `json:"ips"`
		SubType string   `json:"sub_type"`
		CredUser string  `json:"cred_user"`
		CredPassword string `json:"cred_password"`
		AccessPort int   `json:"access_port"`
	}
	if err := readBody(r, &body); err != nil || len(body.IPs) == 0 {
		writeErr(w, 400, "ips 必填")
		return
	}
	var created []model.Asset
	for _, ip := range body.IPs {
		a := model.Asset{
			IP: ip, Name: ip, Category: categoryOf(body.SubType), SubType: body.SubType,
			AccessProto: protoOf(body.SubType), AccessPort: body.AccessPort,
			CredUser: body.CredUser, CredPassword: body.CredPassword, Vars: map[string]string{},
		}
		id, err := s.st.CreateAsset(&a)
		if err == nil {
			a.ID = id
			created = append(created, a)
		}
	}
	writeJSON(w, created)
}

func categoryOf(sub string) string {
	switch sub {
	case "linux", "windows":
		return "os"
	case "huawei", "cisco", "h3c":
		return "network"
	case "mysql", "mssql", "oracle", "postgres", "redis", "mongodb":
		return "database"
	case "nginx", "tomcat":
		return "middleware"
	}
	return "os"
}

func protoOf(sub string) string {
	switch sub {
	case "windows":
		return "winrm"
	case "mysql", "postgres", "redis", "mongodb", "mssql":
		return sub
	case "huawei", "cisco", "h3c":
		return "network"
	}
	return "ssh"
}

// ---------- 字典 ----------

func (s *Server) getDicts(w http.ResponseWriter, r *http.Request) {
	m, err := s.st.GetDicts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, m)
}

func (s *Server) putDicts(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := readBody(r, &body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	for k, v := range body {
		if k == "username" || k == "password" {
			if err := s.st.UpdateDict(k, v); err != nil {
				writeErr(w, 500, err.Error())
				return
			}
		}
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// ---------- 规则 ----------

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.rules.All())
}

// ---------- 任务 ----------

func (s *Server) listTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.st.ListTasks(50)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, tasks)
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var t model.Task
	if err := readBody(r, &t); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if t.Name == "" {
		t.Name = "任务 " + time.Now().Format("2006-01-02 150405")
	}
	// weakpwd 任务：未指定服务时自动取当前识别出的全部可爆破服务
	if t.Type == "weakpwd" && t.Config["services"] == nil {
		var list []string
		for _, svc := range engine.SupportedProtocols() {
			svcs, err := s.st.ListServicesByTypes([]string{svc})
			if err != nil {
				continue
			}
			for _, x := range svcs {
				list = append(list, fmt.Sprintf("%s|%d|%s", x.IP, x.Port, x.Type))
			}
		}
		if len(list) == 0 {
			writeErr(w, 400, "当前无已识别服务，请先执行发现任务或手工指定 services")
			return
		}
		t.Config["services"] = list
	}
	if err := s.sched.Submit(&t); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, t)
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.GetTask(pathID(r))
	if err != nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	writeJSON(w, t)
}

func (s *Server) deleteTask(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	_ = s.sched.Cancel(id)          // 停止派发与本地执行
	_ = s.st.DeleteTask(id)         // 连同分片与结果彻底删除
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) pauseTask(w http.ResponseWriter, r *http.Request) {
	if err := s.sched.Pause(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) resumeTask(w http.ResponseWriter, r *http.Request) {
	if err := s.sched.Resume(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) cancelTask(w http.ResponseWriter, r *http.Request) {
	if err := s.sched.Cancel(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) weakResults(w http.ResponseWriter, r *http.Request) {
	rs, err := s.st.ListWeakResults(pathID(r))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, rs)
}

func (s *Server) baselineResults(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.BaselineFilter
	if v := q.Get("passed"); v != "" {
		n, _ := strconv.Atoi(v)
		f.Passed = &n
	}
	f.Severity = q.Get("severity")
	f.Target = q.Get("target")
	rs, err := s.st.ListBaselineResults(pathID(r), f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, rs)
}

func (s *Server) protocols(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, engine.SupportedProtocols())
}

// ---------- 报告 ----------

func (s *Server) htmlReport(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	task, err := s.st.GetTask(id)
	if err != nil {
		writeErr(w, 404, "任务不存在")
		return
	}
	weak, _ := s.st.ListWeakResults(id)
	base, _ := s.st.ListBaselineResults(id, store.BaselineFilter{})
	assets, _ := s.st.ListAssets()
	html := report.Render(task, weak, base, assets, s.rules.All())
	name := fmt.Sprintf("starruler-report-%d.html", id)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	_, _ = w.Write([]byte(html))
}

func (s *Server) csvExport(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	q := r.URL.Query()
	kind := q.Get("type")
	if kind == "" {
		kind = "weak"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=starruler-%d-%s.csv", id, kind))
	// BOM 方便 Excel 中文
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	if kind == "baseline" {
		base, _ := s.st.ListBaselineResults(id, store.BaselineFilter{})
		csv := "资产,规则包,规则ID,标题,控制点,等保条款,严重级别,实际值,期望值,判定,整改建议,明细\n"
		for _, x := range base {
			csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\",%s,\"%s\",\"%s\"\n",
				csvSafe(x.AssetIP), csvSafe(x.Target), csvSafe(x.RuleID), csvSafe(x.Title), csvSafe(x.Control), csvSafe(x.Ref), csvSafe(x.Severity),
				csvSafe(x.Actual), csvSafe(x.Expected), passedText(x.Passed), csvSafe(x.Remediation), csvSafe(x.Detail))
		}
		_, _ = w.Write([]byte(csv))
		return
	}
	weak, _ := s.st.ListWeakResults(id)
	csv := "IP,协议,端口,账号,口令,类型,详情\n"
	for _, x := range weak {
		manual := ""
		if x.Manual {
			manual = "人工确认"
		} else {
			manual = "命中"
		}
		csv += fmt.Sprintf("%s,%s,%d,%s,%s,%s,\"%s\"\n", csvSafe(x.IP), csvSafe(x.Protocol), x.Port, csvSafe(x.Username), csvSafe(x.Password), manual, csvSafe(x.Detail))
	}
	_, _ = w.Write([]byte(csv))
}

// csvSafe 防 Excel 公式注入：以 = + - @ 开头的单元格加单引号前缀。
func csvSafe(s string) string {
	if len(s) > 0 && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@') {
		return "'" + s
	}
	return s
}

func passedText(p int) string {
	switch p {
	case 1:
		return "合规"
	case 0:
		return "不合规"
	}
	return "人工判定"
}

// ---------- 前端 ----------

func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	f, err := s.web.ReadFile("web/index.html")
	if err != nil {
		writeErr(w, 500, "前端资源缺失")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(f)
}

// ---------- 探针管理 ----------

func (s *Server) listProbes(w http.ResponseWriter, r *http.Request) {
	probes, err := s.st.ListProbes()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, probes)
}

func (s *Server) createProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string `json:"name"`
		BindIP string `json:"bind_ip"`
	}
	if err := readBody(r, &body); err != nil || body.Name == "" {
		writeErr(w, 400, "name 必填")
		return
	}
	p, err := s.st.CreateProbe(body.Name, body.BindIP)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, p)
}

func (s *Server) updateProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
	}
	if err := readBody(r, &body); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.st.SetProbeStatus(pathID(r), body.Status); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) deleteProbe(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteProbe(pathID(r)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// probeBinaries 列出可下载的探针二进制。
func (s *Server) probeBinaries(w http.ResponseWriter, r *http.Request) {
	out := []map[string]string{}
	entries, err := os.ReadDir(s.cfg.ProbeDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || strings.Contains(e.Name(), ".db") {
				continue
			}
			info, _ := e.Info()
			out = append(out, map[string]string{
				"name": e.Name(), "url": "/download/probe/" + e.Name(),
				"size": fmt.Sprint(info.Size()),
			})
		}
	}
	writeJSON(w, out)
}

// DownloadHandler 探针二进制下载路由（main 中挂载）。
// ---------- 探针信道 ----------

func (s *Server) probeRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Hostname string `json:"hostname"`
		Version  string `json:"version"`
		Platform string `json:"platform"`
	}
	if err := readBody(r, &body); err != nil || body.Token == "" {
		writeErr(w, 400, "token 必填")
		return
	}
	p, err := s.st.AuthProbe(body.Token, clientIP(r))
	if err != nil {
		writeErr(w, 401, "令牌无效或已被禁用")
		return
	}
	_ = s.st.UpdateProbeInfo(p.ID, body.Hostname, body.Version+" / "+body.Platform)
	writeJSON(w, map[string]any{"probe_id": p.ID})
}

func (s *Server) probePoll(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Probe-Token")
	p, err := s.st.AuthProbe(token, clientIP(r))
	if err != nil {
		writeErr(w, 401, "令牌无效")
		return
	}
	payload, err := s.sched.ClaimForRemote(p.ID)
	if err != nil {
		writeJSON(w, map[string]any{"wait": true})
		return
	}
	writeJSON(w, map[string]any{"payload": payload})
}

func (s *Server) probeReport(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Probe-Token")
	if _, err := s.st.AuthProbe(token, clientIP(r)); err != nil {
		writeErr(w, 401, "令牌无效")
		return
	}
	var rep engine.ShardReport
	if err := readBody(r, &rep); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	go s.sched.ApplyReport(&rep)
	writeJSON(w, map[string]string{"status": "ok"})
}
