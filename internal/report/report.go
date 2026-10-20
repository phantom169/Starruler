package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"starruler/internal/baseline"
	"starruler/internal/model"
)

// Render 生成测评风格自包含 HTML 合规报告（浏览器打开可直接打印/转PDF）。
func Render(task *model.Task, weak []model.WeakResult, base []model.BaselineResult, assets []model.Asset, packs []*baseline.Pack) string {
	var b strings.Builder

	// 统计
	comply, nonComply, manual := 0, 0, 0
	for _, x := range base {
		switch x.Passed {
		case 1:
			comply++
		case 0:
			nonComply++
		default:
			manual++
		}
	}
	hitCount := 0
	for _, x := range weak {
		if !x.Manual {
			hitCount++
		}
	}
	assetSet := map[string]bool{}
	for _, x := range base {
		assetSet[x.AssetIP] = true
	}
	for _, x := range weak {
		assetSet[x.IP] = true
	}

	conclusion := "符合"
	if nonComply > 0 || hitCount > 0 {
		conclusion = "不符合"
	} else if manual > 0 {
		conclusion = "基本符合"
	}

	b.WriteString(head(task.Name, conclusion))
	b.WriteString(cover(task, conclusion, len(assetSet), hitCount, comply, nonComply, manual))

	// 一、测评范围
	b.WriteString("<h2>一、测评范围</h2><table class='tb'><tr><th>资产</th><th>名称</th><th>类型</th></tr>")
	assetName := map[string]string{}
	assetCat := map[string]string{}
	for _, a := range assets {
		assetName[a.IP] = a.Name
		assetCat[a.IP] = a.Category + "/" + a.SubType
	}
	ips := make([]string, 0, len(assetSet))
	for ip := range assetSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
			html.EscapeString(ip), html.EscapeString(assetName[ip]), html.EscapeString(assetCat[ip])))
	}
	b.WriteString("</table>")

	// 二、总体结果：资产×控制点 符合率矩阵
	b.WriteString("<h2>二、总体结果（资产 × 等保控制点符合率矩阵）</h2>")
	b.WriteString(matrix(base))

	// 三、弱口令专项
	b.WriteString("<h2>三、弱口令专项</h2>")
	if len(weak) == 0 {
		b.WriteString("<p class='ok'>未发现弱口令命中。</p>")
	} else {
		b.WriteString(fmt.Sprintf("<p>命中 <b class='danger'>%d</b> 项，需人工确认 %d 项。</p>", hitCount, len(weak)-hitCount))
		b.WriteString("<table class='tb'><tr><th>IP</th><th>协议</th><th>端口</th><th>账号</th><th>口令</th><th>详情</th></tr>")
		for _, x := range weak {
			cls := "danger"
			tag := "命中"
			if x.Manual {
				cls = "warn"
				tag = "人工确认"
			}
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td class='%s'>%s</td><td>%s <span class='tag %s-bg'>%s</span></td></tr>",
				html.EscapeString(x.IP), html.EscapeString(x.Protocol), x.Port,
				html.EscapeString(x.Username), cls, html.EscapeString(x.Password),
				html.EscapeString(x.Detail), cls, tag))
		}
		b.WriteString("</table>")
	}

	// 四、逐资产核查明细
	b.WriteString("<h2>四、基线核查明细</h2>")
	if len(base) == 0 {
		b.WriteString("<p>本任务无基线核查项。</p>")
	} else {
		byAsset := map[string][]model.BaselineResult{}
		for _, x := range base {
			byAsset[x.AssetIP] = append(byAsset[x.AssetIP], x)
		}
		for _, ip := range ips {
			items, ok := byAsset[ip]
			if !ok {
				continue
			}
			b.WriteString(fmt.Sprintf("<h3>%s（%d 项）</h3>", html.EscapeString(ip), len(items)))
			b.WriteString("<table class='tb'><tr><th>规则</th><th>控制点</th><th>条款</th><th>实际值</th><th>期望值</th><th>判定</th><th>整改建议</th></tr>")
			for _, x := range items {
				cls, txt := "ok", "合规"
				if x.Passed == 0 {
					cls, txt = "danger", "不合规"
				} else if x.Passed == -1 {
					cls, txt = "warn", "人工判定"
				}
				exp := x.Expected
				if exp == "" {
					exp = "—"
				}
				b.WriteString(fmt.Sprintf("<tr><td>%s<br><small>%s</small></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class='tag %s-bg'>%s</span></td><td>%s</td></tr>",
					html.EscapeString(x.Title), html.EscapeString(x.RuleID),
					html.EscapeString(x.Control), html.EscapeString(x.Ref),
					html.EscapeString(trunc(x.Actual)), html.EscapeString(exp), cls, txt,
					html.EscapeString(x.Remediation)))
			}
			b.WriteString("</table>")
		}
	}

	// 五、人工核查清单（等保三级中无法远程判定的条款）
	b.WriteString("<h2>五、人工核查清单（三级等保补充项）</h2>")
	seen := map[string]bool{}
	for _, p := range packs {
		for _, m := range p.ManualItems {
			if seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			b.WriteString(fmt.Sprintf("<div class='manual'><b>%s</b><span class='tag warn-bg'>%s</span><p>%s</p></div>",
				html.EscapeString(m.Title), html.EscapeString(m.Ref), html.EscapeString(m.Method)))
		}
	}
	if len(seen) == 0 {
		b.WriteString("<p>无。</p>")
	}

	// 六、整改路线图
	b.WriteString("<h2>六、整改建议汇总（按严重级别）</h2>")
	b.WriteString(remediation(base, weak))

	b.WriteString(foot())
	return b.String()
}

// matrix 资产×控制点 符合率矩阵。
func matrix(base []model.BaselineResult) string {
	controls := map[string]bool{}
	byCell := map[string][2]int{} // "ip|control" -> {comply, total}
	byAsset := map[string]bool{}
	for _, x := range base {
		controls[x.Control] = true
		byAsset[x.AssetIP] = true
		c := byCell[x.AssetIP+"|"+x.Control]
		c[1]++
		if x.Passed == 1 {
			c[0]++
		}
		byCell[x.AssetIP+"|"+x.Control] = c
	}
	cl := make([]string, 0, len(controls))
	for k := range controls {
		cl = append(cl, k)
	}
	sort.Strings(cl)
	al := make([]string, 0, len(byAsset))
	for k := range byAsset {
		al = append(al, k)
	}
	sort.Strings(al)

	var b strings.Builder
	b.WriteString("<table class='tb matrix'><tr><th>资产 \\ 控制点</th>")
	for _, c := range cl {
		b.WriteString("<th>" + html.EscapeString(c) + "</th>")
	}
	b.WriteString("</tr>")
	for _, ip := range al {
		b.WriteString("<tr><th>" + html.EscapeString(ip) + "</th>")
		for _, c := range cl {
			cell := byCell[ip+"|"+c]
			if cell[1] == 0 {
				b.WriteString("<td class='dim'>—</td>")
				continue
			}
			pct := cell[0] * 100 / cell[1]
			cls := "ok"
			if pct < 60 {
				cls = "danger"
			} else if pct < 100 {
				cls = "warn"
			}
			b.WriteString(fmt.Sprintf("<td class='%s'>%d%%</td>", cls, pct))
		}
		b.WriteString("</tr>")
	}
	return b.String() + "</table><p class='dim'>矩阵单元格为该资产在对应控制点的规则符合率；绿色=全部合规，琥珀=部分合规，红色=合规率低于60%。</p>"
}

func remediation(base []model.BaselineResult, weak []model.WeakResult) string {
	type item struct {
		sev, title, fix string
	}
	var items []item
	for _, x := range base {
		if x.Passed == 0 {
			items = append(items, item{sev: x.Severity, title: x.AssetIP + "：" + x.Title, fix: x.Remediation})
		}
	}
	for _, x := range weak {
		if !x.Manual {
			items = append(items, item{sev: "high", title: fmt.Sprintf("%s：%s(%d) 账号 %s 弱口令", x.IP, x.Protocol, x.Port, x.Username), fix: "立即修改口令为强口令（长度≥12，大小写+数字+特殊字符），并排查该账号是否有异常登录"})
		}
	}
	sevRank := map[string]int{"high": 0, "medium": 1, "low": 2}
	sort.SliceStable(items, func(i, j int) bool { return sevRank[items[i].sev] < sevRank[items[j].sev] })
	if len(items) == 0 {
		return "<p class='ok'>无待整改项。</p>"
	}
	var b strings.Builder
	b.WriteString("<ol class='fixlist'>")
	for _, it := range items {
		cls := map[string]string{"high": "danger", "medium": "warn", "low": "dim"}[it.sev]
		b.WriteString(fmt.Sprintf("<li><span class='tag %s-bg'>%s</span> %s<div class='fix'>%s</div></li>",
			cls, sevName(it.sev), html.EscapeString(it.title), html.EscapeString(it.fix)))
	}
	return b.String() + "</ol>"
}

func sevName(s string) string {
	return map[string]string{"high": "高危", "medium": "中危", "low": "低危"}[s]
}

func trunc(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// ---------- HTML 模板 ----------

func head(title, conclusion string) string {
	c := "#0FA36B"
	if conclusion == "不符合" {
		c = "#E5484D"
	} else if conclusion == "基本符合" {
		c = "#F59E0B"
	}
	return fmt.Sprintf(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>%s - 星尺合规报告</title>
<style>
body{font-family:"Microsoft YaHei",system-ui,sans-serif;margin:0;background:#F4F8FC;color:#17233B}
.page{max-width:1100px;margin:0 auto;padding:40px 32px;background:#fff;min-height:100vh}
h1{font-size:26px;border-bottom:3px solid #2E90FA;padding-bottom:12px}
h2{font-size:19px;margin-top:36px;border-left:4px solid #2E90FA;padding-left:10px}
h3{font-size:15px;color:#1B74E0}
.tb{border-collapse:collapse;width:100%%;font-size:13px;margin:10px 0}
.tb th,.tb td{border:1px solid #E1EAF5;padding:6px 10px;text-align:left;vertical-align:top}
.tb th{background:#F0F6FC}
.tb small{color:#93A5B8}
.matrix td,.matrix th{text-align:center}
.ok{color:#0FA36B}.warn{color:#F59E0B}.danger{color:#E5484D;font-weight:600}.dim{color:#93A5B8}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:normal}
.ok-bg{background:#E6F7F0;color:#0FA36B}
.warn-bg{background:#FEF5E7;color:#B9770E}
.danger-bg{background:#FDECEC;color:#E5484D}
.cover{background:linear-gradient(135deg,#E8F2FE,#F4F8FC);border:1px solid #E1EAF5;border-radius:12px;padding:24px;margin:16px 0}
.cover .concl{font-size:22px;font-weight:700;color:%s}
.kpis{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px}
.kpi{background:#fff;border:1px solid #E1EAF5;border-radius:10px;padding:10px 18px;min-width:120px}
.kpi b{display:block;font-size:24px}
.manual{border:1px solid #E1EAF5;border-radius:8px;padding:10px 14px;margin:8px 0;background:#F0F6FC}
.fixlist li{margin:8px 0}
.fix{color:#5C6F85;font-size:13px;margin-top:2px}
.foot{margin-top:40px;color:#93A5B8;font-size:12px;text-align:center;border-top:1px solid #E1EAF5;padding-top:14px}
@media print{.page{padding:0}}
</style></head><body><div class="page"><h1>星尺 · %s 远程安全评估合规报告</h1>`,
		html.EscapeString(title), c, html.EscapeString(title))
}

func cover(task *model.Task, conclusion string, assets, hits, comply, nonComply, manual int) string {
	return fmt.Sprintf(`<div class="cover">
<div>测评对象：<b>%s</b>　任务类型：%s　测评时间：%s</div>
<div class="concl">总体结论：%s</div>
<div class="kpis">
<div class="kpi">资产数<b>%d</b></div>
<div class="kpi">弱口令命中<b class="danger">%d</b></div>
<div class="kpi">合规项<b class="ok">%d</b></div>
<div class="kpi">不合规项<b class="danger">%d</b></div>
<div class="kpi">待人工判定<b class="warn">%d</b></div>
</div></div>`,
		html.EscapeString(task.Name), html.EscapeString(task.Type),
		task.CreatedAt.Format("2006-01-02 15:04"), conclusion, assets, hits, comply, nonComply, manual)
}

func foot() string {
	return fmt.Sprintf(`<div class="foot">星尺 (Star ruler) 弱口令检测与等保基线核查系统 · 生成时间 %s · 本报告为技术核查辅助材料，最终测评结论以权威机构测评为准</div></div></body></html>`,
		time.Now().Format("2006-01-02 15:04:05"))
}
