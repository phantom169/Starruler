package weakpwd

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"starruler/internal/auth"
	"starruler/internal/model"
)

// Options 弱口令引擎选项。
type Options struct {
	Concurrency   int           // 全局并发（默认500）
	PerHostLimit  int           // 单主机同时在飞尝试数（默认16）
	Timeout       time.Duration // 单次尝试超时（默认5s）
	MaxTryPerUser int           // 每(主机,端口,账户)尝试上限 —— 防账户锁定（默认20）
	StopOnHit     string        // user=命中后停该账户 / service=命中后停整个服务
}

func (o *Options) fill() {
	if o.Concurrency <= 0 {
		o.Concurrency = 500
	}
	if o.PerHostLimit <= 0 {
		o.PerHostLimit = 16
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.MaxTryPerUser <= 0 {
		o.MaxTryPerUser = 20
	}
	if o.StopOnHit == "" {
		o.StopOnHit = "user"
	}
}

// Stats 引擎运行统计。
type Stats struct {
	Attempts int64 `json:"attempts"`
	Hits     int64 `json:"hits"`
	Errors   int64 `json:"errors"`
	Skipped  int64 `json:"skipped"`
	Manual   int64 `json:"manual"`
}

// Target 待爆破目标（服务 × 用户名），密码由引擎遍历。
type Target struct {
	IP       string
	Port     int
	Protocol string
	Params   map[string]string
	Username string
}

type job struct {
	t Target
	p string
}

// Engine 单次任务内的爆破执行器（实例非并发安全，一个分片一个实例）。
type Engine struct {
	opts     Options
	ctx      context.Context
	stats    Stats
	mu       sync.Mutex
	results  []model.WeakResult
	tryCount sync.Map // "ip:port:proto:user" -> *int32
	hitUser  sync.Map // 已命中账户
	hitSvc   sync.Map // 已命中服务（service 级停）
	hostGate sync.Map // ip -> chan struct{}（容量 PerHostLimit）
}

func New(ctx context.Context, opts Options) *Engine {
	opts.fill()
	return &Engine{ctx: ctx, opts: opts, results: []model.WeakResult{}}
}

func (e *Engine) key(j job) string {
	return j.t.IP + ":" + itoa(j.t.Port) + ":" + j.t.Protocol + ":" + j.t.Username
}

// Run 阻塞执行直至全部完成或取消。
func (e *Engine) Run(targets []Target, passwords []string) (Stats, []model.WeakResult) {
	jobs := make(chan job)
	var wg sync.WaitGroup
	for i := 0; i < e.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				e.exec(j)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, t := range targets {
			for _, pwd := range passwords {
				if e.ctx.Err() != nil {
					return
				}
				j := job{t: t, p: pwd}
				// 防锁定上限
				cv, _ := e.tryCount.LoadOrStore(e.key(j), new(int32))
				if atomic.AddInt32(cv.(*int32), 1) > int32(e.opts.MaxTryPerUser) {
					atomic.AddInt64(&e.stats.Skipped, 1)
					continue
				}
				select {
				case jobs <- j:
				case <-e.ctx.Done():
					return
				}
			}
		}
	}()
	wg.Wait()
	return e.stats, e.results
}

func (e *Engine) exec(j job) {
	key := e.key(j)
	// 命中即停
	if _, ok := e.hitUser.Load(key); ok {
		atomic.AddInt64(&e.stats.Skipped, 1)
		return
	}
	if e.opts.StopOnHit == "service" {
		if _, ok := e.hitSvc.Load(j.t.IP + itoa(j.t.Port)); ok {
			atomic.AddInt64(&e.stats.Skipped, 1)
			return
		}
	}

	// 单主机在飞闸门
	gv, _ := e.hostGate.LoadOrStore(j.t.IP, make(chan struct{}, e.opts.PerHostLimit))
	gate := gv.(chan struct{})
	timer := time.NewTimer(e.opts.Timeout * 6)
	defer timer.Stop()
	select {
	case gate <- struct{}{}:
	case <-e.ctx.Done():
		atomic.AddInt64(&e.stats.Skipped, 1)
		return
	case <-timer.C:
		atomic.AddInt64(&e.stats.Skipped, 1) // 主机拥塞，放弃该次
		return
	}
	defer func() { <-gate }()

	authenticator, ok := auth.Get(j.t.Protocol)
	if !ok {
		atomic.AddInt64(&e.stats.Skipped, 1)
		return
	}
	// 硬超时保护：部分协议库（如SMB）无内部超时，卡死的连接由外层放弃
	type tryOut struct {
		res auth.Result
	}
	ch := make(chan tryOut, 1)
	go func() {
		ch <- tryOut{authenticator.Try(auth.Attempt{
			IP: j.t.IP, Port: j.t.Port,
			Username: j.t.Username, Password: j.p,
			Timeout: e.opts.Timeout, Params: j.t.Params,
		})}
	}()
	select {
	case out := <-ch:
		res := out.res
		atomic.AddInt64(&e.stats.Attempts, 1)
		switch {
		case res.Hit:
			atomic.AddInt64(&e.stats.Hits, 1)
			e.hitUser.Store(key, struct{}{})
			if e.opts.StopOnHit == "service" {
				e.hitSvc.Store(j.t.IP+itoa(j.t.Port), struct{}{})
			}
			e.mu.Lock()
			e.results = append(e.results, model.WeakResult{
				IP: j.t.IP, Protocol: j.t.Protocol, Port: j.t.Port,
				Username: j.t.Username, Password: j.p, Detail: res.Detail,
			})
			e.mu.Unlock()
		case res.Manual:
			atomic.AddInt64(&e.stats.Manual, 1)
			e.mu.Lock()
			e.results = append(e.results, model.WeakResult{
				IP: j.t.IP, Protocol: j.t.Protocol, Port: j.t.Port,
				Username: j.t.Username, Password: j.p, Detail: res.Detail, Manual: true,
			})
			e.mu.Unlock()
		case res.Detail != "":
			atomic.AddInt64(&e.stats.Errors, 1)
		}
	case <-time.After(e.opts.Timeout * 3):
		atomic.AddInt64(&e.stats.Errors, 1)
	case <-e.ctx.Done():
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
