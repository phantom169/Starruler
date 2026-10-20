package discover

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- CIDR 与 IP 工具 ----------

// ExpandCIDR 展开 CIDR 为 IP 列表。支持三种形式：
//
//	10.0.0.0/24          —— 标准CIDR（去掉网络/广播地址）
//	10.0.0.1-10.0.0.254  —— 起止范围（调度器分片用）
//	10.0.0.5             —— 单IP
func ExpandCIDR(cidr string) ([]string, error) {
	if strings.Contains(cidr, "-") {
		parts := strings.SplitN(cidr, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start == nil || end == nil {
			return nil, fmt.Errorf("非法IP范围: %s", cidr)
		}
		var out []string
		for ip := start; compareIP(ip, end) <= 0; ip = nextIP(ip) {
			out = append(out, ip.String())
			if len(out) > 60000 {
				return nil, fmt.Errorf("范围过大: %s", cidr)
			}
		}
		return out, nil
	}
	if !strings.Contains(cidr, "/") {
		if net.ParseIP(cidr) != nil {
			return []string{cidr}, nil
		}
		return nil, fmt.Errorf("非法IP: %s", cidr)
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := ipnet.Mask.Size()
	total := uint64(1) << uint(bits-ones)
	if bits-ones > 24 { // 防止误配大网段导致内存爆炸（/24 单桶由上层保证）
		return nil, fmt.Errorf("网段过大（/24 以内），收到 %s", cidr)
	}
	var out []string
	start := ip.Mask(ipnet.Mask)
	for i := uint64(1); i < total-1; i++ {
		out = append(out, dupIP(start, i).String())
	}
	if ones >= 31 {
		out = ipsOfNet(ip, ipnet)
		if len(out) == 0 {
			out = []string{start.String()}
		}
	}
	return out, nil
}

func compareIP(a, b net.IP) int {
	ab, bb := to16(a), to16(b)
	for i := range ab {
		switch {
		case ab[i] < bb[i]:
			return -1
		case ab[i] > bb[i]:
			return 1
		}
	}
	return 0
}

func to16(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func dupIP(base net.IP, off uint64) net.IP {
	b := make([]byte, len(base))
	copy(b, base)
	for i := len(b) - 1; i >= 0 && off > 0; i-- {
		add := off & 0xFF
		sum := uint64(b[i]) + add
		b[i] = byte(sum & 0xFF)
		off = off>>8 + sum>>8
	}
	return net.IP(b)
}

func ipsOfNet(ip net.IP, ipnet *net.IPNet) []string {
	var out []string
	for cand := ip.Mask(ipnet.Mask); ipnet.Contains(cand); cand = nextIP(cand) {
		out = append(out, cand.String())
		if len(out) > 300 {
			break
		}
	}
	return out
}

func nextIP(ip net.IP) net.IP {
	b := make([]byte, len(ip))
	copy(b, ip)
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return net.IP(b)
}

// ---------- 存活探测 ----------

var tcpPingPorts = []int{22, 80, 443, 445, 3389, 8080}

// Alive TCP-Ping 存活探测：任一常用端口可连即视为存活（ICMP 常被禁，TCP 更通用）。
func Alive(ip string, timeout time.Duration) bool {
	for _, p := range tcpPingPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(p)), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// ---------- 端口扫描 ----------

var topPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 389, 443, 445, 465,
	587, 636, 993, 995, 1080, 1099, 1433, 1521, 2049, 2181, 2375, 2376, 2601,
	3000, 3128, 3306, 3389, 4444, 4848, 5000, 5432, 5560, 5900, 5901, 5985,
	6379, 6443, 7001, 7002, 7070, 8069, 8080, 8081, 8088, 8089, 8161, 8443,
	8500, 8888, 8983, 9000, 9001, 9043, 9080, 9090, 9200, 9300, 9443, 9527,
	9999, 10000, 11211, 15672, 18083, 19000, 27017, 27018, 28017, 50070, 61616,
}

// PortPolicy 端口策略。
type PortPolicy struct {
	Mode    string // top / all / custom
	Custom  []int
	Timeout time.Duration
}

// ScanHost 对单主机扫描端口，返回开放端口列表。
func ScanHost(ctx context.Context, ip string, policy PortPolicy) []int {
	ports := topPorts
	switch policy.Mode {
	case "custom":
		ports = policy.Custom
	case "all":
		ports = make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
	}
	return ScanPorts(ctx, ip, ports, policy.Timeout, 800)
}

// ScanPorts 并发 TCP connect 扫描。
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration, concurrency int) []int {
	if concurrency <= 0 {
		concurrency = 800
	}
	var open []int
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return open
}

// ScanSubnet 对网段内全部 IP 执行（存活→端口），aliveOnly 为 true 时仅返回存活主机。
type HostResult struct {
	IP      string
	Alive   bool
	Ports   []int
}

func ScanSubnet(ctx context.Context, ips []string, policy PortPolicy, aliveOnly bool, concurrency int) []HostResult {
	results := make([]HostResult, len(ips))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var done int64
	for i, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, ip string) {
			defer wg.Done()
			defer func() { <-sem; atomic.AddInt64(&done, 1) }()
			if !Alive(ip, 2*time.Second) {
				results[idx] = HostResult{IP: ip, Alive: false}
				return
			}
			hr := HostResult{IP: ip, Alive: true}
			if !aliveOnly {
				hr.Ports = ScanHost(ctx, ip, policy)
			}
			results[idx] = hr
		}(i, ip)
	}
	wg.Wait()
	return results
}
