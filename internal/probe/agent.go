package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"starruler/internal/config"
	"starruler/internal/engine"
)

func platformInfo() string { return runtime.GOOS + "/" + runtime.GOARCH }

// Agent 远程探针：注册 → 心跳轮询领分片 → 执行 → 批量回传。
// 只发出站 HTTP 连接，不监听任何端口（内网防火墙友好）。
type Agent struct {
	cfg  *config.ProbeConfig
	http *http.Client
	id   int64
}

func NewAgent(cfg *config.ProbeConfig) *Agent {
	return &Agent{
		cfg:  cfg,
		http: &http.Client{Timeout: 120 * time.Second},
	}
}

type registerReq struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
}

type registerResp struct {
	ProbeID int64  `json:"probe_id"`
	Error   string `json:"error,omitempty"`
}

type pollResp struct {
	Payload *engine.ShardPayload `json:"payload,omitempty"`
	Wait    bool                 `json:"wait"`
	Error   string               `json:"error,omitempty"`
}

func (a *Agent) Run() error {
	log.SetPrefix("[probe] ")
	log.Printf("探针启动，中心: %s", a.cfg.ServerAddr)
	hostname, _ := os.Hostname()
	// 注册（失败重试直到成功）
	for {
		var rr registerResp
		err := a.post("/probe/register", registerReq{
			Token: a.cfg.Token, Hostname: hostname,
			Version: a.cfg.Version, Platform: platformInfo(),
		}, &rr)
		if err == nil && rr.Error == "" && rr.ProbeID > 0 {
			a.id = rr.ProbeID
			log.Printf("注册成功，探针ID=%d (%s)", a.id, hostname)
			break
		}
		log.Printf("注册失败(%v)，10秒后重试...", err)
		time.Sleep(10 * time.Second)
	}

	// 主循环：轮询领分片
	for {
		var pr pollResp
		err := a.get("/probe/poll", &pr)
		if err != nil {
			log.Printf("轮询失败: %v，5秒后重试", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if pr.Error != "" {
			log.Printf("中心错误: %s，5秒后重试", pr.Error)
			time.Sleep(5 * time.Second)
			continue
		}
		if pr.Wait || pr.Payload == nil {
			time.Sleep(5 * time.Second)
			continue
		}
		p := pr.Payload
		log.Printf("领取分片 #%d（%s，任务 #%d）开始执行", p.ShardID, p.Kind, p.TaskID)
		rep := engine.RunShard(context.Background(), *p)
		if err := a.post("/probe/report", rep, &struct{}{}); err != nil {
			log.Printf("回传失败: %v", err)
			// 结果丢失由中心超时回收重派兜底
		} else {
			log.Printf("分片 #%d 完成：alive=%d ports=%d hits=%d checks=%d",
				p.ShardID, rep.Stats["alive"], rep.Stats["open_ports"], rep.Stats["weak_hits"], rep.Stats["baseline_checks"])
		}
	}
}

func (a *Agent) url(path string) string { return a.cfg.ServerAddr + path }

func (a *Agent) post(path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", a.url(path), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probe-Token", a.cfg.Token)
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (a *Agent) get(path string, out any) error {
	req, _ := http.NewRequest("GET", a.url(path), nil)
	req.Header.Set("X-Probe-Token", a.cfg.Token)
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
