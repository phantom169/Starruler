package baseline

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"starruler/internal/model"
)

// Item 对应规则库中一条核查项（YAML 结构）。
type Item struct {
	ID          string `yaml:"id" json:"id"`
	Title       string `yaml:"title" json:"title"`
	Control     string `yaml:"control" json:"control"`   // 等保控制点：身份鉴别/访问控制/安全审计...
	Ref         string `yaml:"ref" json:"ref"`           // 等保 2.0 三级条款号
	Severity    string `yaml:"severity" json:"severity"` // high / medium / low
	Command     string `yaml:"command" json:"command"`
	Op          string `yaml:"op" json:"op"`                 // 比对算子
	Expected    string `yaml:"expected" json:"expected"`
	WhenEmpty   string `yaml:"when_empty" json:"when_empty"` // fail / pass / manual
	Mask        bool   `yaml:"mask" json:"mask"`             // 脱敏输出
	Remediation string `yaml:"remediation" json:"remediation"`
	Note        string `yaml:"note" json:"note"`
}

// Pack 一套规则包（对应一个 target）。
type Pack struct {
	Target    string `yaml:"target"`
	Name      string `yaml:"name"`
	Collector string `yaml:"collector"` // ssh / winrm / network / mysql / redis / postgres / mongodb
	Items     []Item `yaml:"items"`
	// ManualItems 无法自动判定的人工核查清单（进报告）。
	ManualItems []ManualItem `yaml:"manual_items"`
}

type ManualItem struct {
	ID     string `yaml:"id" json:"id"`
	Title  string `yaml:"title" json:"title"`
	Ref    string `yaml:"ref" json:"ref"`
	Method string `yaml:"method" json:"method"` // 核查方法说明
}

// Collector 采集器接口：执行核查命令返回输出。所有采集走目标凭据。
type Collector interface {
	Name() string
	// Exec 执行一条核查命令；cmd 由规则定义（shell/SQL/配置路径），变量已渲染。
	Exec(ctx context.Context, a model.Asset, cmd string, timeout time.Duration) (ok bool, output string, errDetail string)
}

var collectors = map[string]Collector{}

func RegisterCollector(c Collector) { collectors[c.Name()] = c }

func GetCollector(name string) (Collector, bool) {
	c, ok := collectors[name]
	return c, ok
}

// Compare 比对引擎：实际值 × 算子 × 期望值 → 判定（1合规/0不合规/-1人工）。
func Compare(item Item, ok bool, output string) (passed int, actual string, detail string) {
	actual = strings.TrimSpace(output)
	if item.Mask && actual != "" {
		actual = "(已设置)"
	}
	if !ok {
		return -1, actual, "采集失败：无法执行核查命令"
	}
	if actual == "" {
		switch item.WhenEmpty {
		case "pass":
			return 1, "(空)", "按规则约定空值视为合规"
		case "manual":
			return -1, "(空)", "无输出，需人工判定"
		default:
			return 0, "(空)", "无输出，按规则约定判定为不合规"
		}
	}
	exp := strings.TrimSpace(item.Expected)
	switch item.Op {
	case "exists":
		return 1, actual, ""
	case "not_exists":
		return 0, actual, "不应存在的内容被检测到"
	case "eq":
		if norm(actual) == norm(exp) {
			return 1, actual, ""
		}
		return 0, actual, "期望: " + exp
	case "ne":
		if norm(actual) != norm(exp) {
			return 1, actual, ""
		}
		return 0, actual, "期望不等于: " + exp
	case "gt", "ge", "lt", "le":
		av, err1 := toNum(actual)
		ev, err2 := toNum(exp)
		if err1 != nil || err2 != nil {
			return -1, actual, "数值解析失败，需人工判定（期望: " + exp + "）"
		}
		pass := false
		switch item.Op {
		case "gt":
			pass = av > ev
		case "ge":
			pass = av >= ev
		case "lt":
			pass = av < ev
		case "le":
			pass = av <= ev
		}
		if pass {
			return 1, actual, ""
		}
		return 0, actual, "期望 " + opName(item.Op) + " " + exp
	case "in":
		for _, part := range strings.Split(exp, ",") {
			if norm(actual) == norm(strings.TrimSpace(part)) {
				return 1, actual, ""
			}
		}
		return 0, actual, "期望属于: " + exp
	case "contains":
		if strings.Contains(norm(actual), norm(exp)) {
			return 1, actual, ""
		}
		return 0, actual, "期望包含: " + exp
	case "not_contains":
		if strings.Contains(norm(actual), norm(exp)) {
			return 0, actual, "检测到不应存在的内容: " + exp
		}
		return 1, actual, ""
	case "regex":
		re, err := regexp.Compile(exp)
		if err != nil {
			return -1, actual, "规则正则无效，需人工判定"
		}
		if re.MatchString(actual) {
			return 1, actual, ""
		}
		return 0, actual, "期望匹配: " + exp
	default:
		return -1, actual, "未知算子: " + item.Op
	}
}

func norm(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(s, `"'`)))
}

func toNum(s string) (float64, error) {
	// 取第一个数字段（容忍 "0 0" / "maxmemory 104857600" 之类输出）
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ',' || r == ';' || r == ':'
	}) {
		if v, err := strconv.ParseFloat(strings.TrimSpace(part), 64); err == nil {
			return v, nil
		}
	}
	return 0, fmt.Errorf("no number in %q", s)
}

func opName(op string) string {
	switch op {
	case "gt":
		return ">"
	case "ge":
		return ">="
	case "lt":
		return "<"
	case "le":
		return "<="
	}
	return op
}
