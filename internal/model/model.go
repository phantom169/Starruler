package model

import "time"

// ---------- 主机与服务（发现引擎产出） ----------

type Host struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Source    string    `json:"source"`
	OSGuess   string    `json:"osGuess"`
	Note      string    `json:"note"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

type Service struct {
	ID         int64  `json:"id"`
	HostID     int64  `json:"hostId"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Type       string `json:"type"`
	Banner     string `json:"banner"`
	Confidence int    `json:"confidence"`
	Manual     bool   `json:"manual"`
}

// ---------- 核查资产（基线专用：主机 + 凭据） ----------

type Asset struct {
	ID           int64             `json:"id"`
	IP           string            `json:"ip"`
	Name         string            `json:"name"`
	Category     string            `json:"category"`
	SubType      string            `json:"subType"`
	AccessProto  string            `json:"accessProto"`
	AccessPort   int               `json:"accessPort"`
	CredUser     string            `json:"credUser"`
	CredPassword string            `json:"credPassword"`
	Vars         map[string]string `json:"vars"`
}

// ---------- 任务与分片 ----------

type Task struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Status     string            `json:"status"`
	Config     map[string]any    `json:"config"`
	Stats      map[string]any    `json:"stats"`
	Error      string            `json:"error"`
	CreatedAt  time.Time         `json:"createdAt"`
	FinishedAt *time.Time        `json:"finishedAt"`
}

// Shard 任务分片：发现类=网段桶(/24)，爆破/基线类=资产桶。断点续扫最小单位。
type Shard struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"taskId"`
	Kind      string    `json:"kind"`
	RangeKey  string    `json:"rangeKey"`
	Status    string    `json:"status"`
	ProbeID   int64     `json:"probeId"`
	ClaimedAt time.Time `json:"claimedAt"`
	Error     string    `json:"error"`
}

// ---------- 探针 ----------

type Probe struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Token     string    `json:"token"`
	BindIP    string    `json:"bindIp"`
	Status    string    `json:"status"`
	Hostname  string    `json:"hostname"`
	SourceIP  string    `json:"sourceIp"`
	Version   string    `json:"version"`
	LastSeen  time.Time `json:"lastSeen"`
	CreatedAt time.Time `json:"createdAt"`
}

// ---------- 结果 ----------

type WeakResult struct {
	ID       int64     `json:"id"`
	TaskID   int64     `json:"taskId"`
	IP       string    `json:"ip"`
	Protocol string    `json:"protocol"`
	Port     int       `json:"port"`
	Username string    `json:"username"`
	Password string    `json:"password"`
	Detail   string    `json:"detail"`
	Manual   bool      `json:"manual"`
	FoundAt  time.Time `json:"foundAt"`
}

type BaselineResult struct {
	ID          int64     `json:"id"`
	TaskID      int64     `json:"taskId"`
	AssetIP     string    `json:"assetIp"`
	AssetName   string    `json:"assetName"`
	Target      string    `json:"target"`
	RuleID      string    `json:"ruleId"`
	Title       string    `json:"title"`
	Control     string    `json:"control"`
	Ref         string    `json:"ref"`
	Severity    string    `json:"severity"`
	Actual      string    `json:"actual"`
	Expected    string    `json:"expected"`
	Passed      int       `json:"passed"`
	Remediation string    `json:"remediation"`
	Detail      string    `json:"detail"`
	CheckedAt   time.Time `json:"checkedAt"`
}

type Dict struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}
