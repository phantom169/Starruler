<div align="center">

# ⭐ 星尺 · Star Ruler

**弱口令检测与等保基线核查系统**

自主发现内网服务 · 14 种协议弱口令检测 · 三级等保基线核查 · 一键合规报告

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20ARM-555555)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Version-1.0.0-blue.svg)]()

*开源的企业内网远程安全评估工具：单二进制零依赖，规则全开放，可自由扩展。*

</div>

---

## ✨ 特性

- 🔍 **自主发现** — 输入 CIDR 网段，自动完成存活探测 → 端口扫描 → 三层服务指纹识别（Banner / 主动探针 / 端口指纹），自动建档，无需手工录入资产
- 🔓 **全协议弱口令** — SSH / Telnet / SMB / FTP / MySQL / SQL Server / Oracle / PostgreSQL / Redis / MongoDB / Tomcat / HTTP Basic / HTTP 表单 / SNMP，共 14 种认证器插件
- 🛡️ **三级等保基线** — 12 套规则包、100+ 条核查项逐条映射等保 2.0 三级条款（含条款号与整改建议），双因素认证等人工项自动生成核查清单
- 📄 **一键合规报告** — 测评机构风格自包含 HTML（资产×控制点符合率矩阵 / 弱口令专项 / 逐项明细 / 整改路线图），浏览器直接打印转 PDF
- 📡 **分布式探针** — Web 页面生成令牌、下载探针程序，目标机器一条命令加入扫描集群；分片自动均衡、断点续扫、失联自动回收
- 🧰 **连通性探测** — 内置 Ping / Telnet / Curl 三连工具，排查网络快
- 📦 **单二进制** — 中心程序 + Web 控制台 + 规则库全部内嵌，拷贝即用，内网离线环境友好

## 🚀 快速开始

```bash
# Windows
starruler.exe

# Linux
chmod +x starruler && ./starruler
```

浏览器打开 **http://localhost:8080** —— 完成。数据存于本地 `data/starruler.db`（SQLite，自动创建），无任何外部依赖。

## 🧭 使用流程

```
① 发现任务          ② 查看资产         ③ 基线核查            ④ 出报告
输入网段 ──────►  主机/服务自动建档 ──► 一键转化+补凭据 ────► 测评风格 HTML
勾选"发现即测"      指认 unknown 服务    按类型匹配规则包       可打印转 PDF
弱口令自动爆破
```

1. **🛰️ 发现任务** — 输入网段（如 `10.0.1.0/24`），勾选“发现即测”则识别到服务后自动进入弱口令爆破（内置防账户锁定：每主机/端口/账户尝试上限）
2. **💻 主机资产** — 查看识别结果，低置信度服务可人工指认类型
3. **🔐 核查资产** — 发现主机一键转化为核查资产，补 SSH / WinRM / 数据库凭据
4. **📋 任务中心** — 实时进度、暂停 / 恢复 / 取消 / 删除任务、结果明细、CSV 导出
5. **报告** — 任务页一键下载合规报告

## 🔓 弱口令引擎

| 类别 | 协议 |
|:---|:---|
| 操作系统 | SSH · Telnet · SMB (Windows) · FTP |
| 数据库 | MySQL · SQL Server · Oracle · PostgreSQL · Redis · MongoDB |
| 中间件 / 应用 | Tomcat Manager · HTTP Basic · HTTP 表单（任意 Web 登录） |
| 网络设备 | SNMP v2c Community |

- **防锁定**：每（主机，端口，账户）尝试上限（默认 20，可配），超限自动跳过
- **命中即停**：账户级 / 服务级可配
- **精准判定**：认证失败与网络故障严格区分，无法自动判定标记“人工确认”
- **高性能**：goroutine 池默认 500 并发，可调至数万；单机即可支撑万级主机

## 🛡️ 等保基线规则库

| 规则包 | 核查项数 | 采集方式 |
|:---|:--:|:---|
| Linux（CentOS/Ubuntu/麒麟/统信） | 23 | SSH |
| Windows | 14 | WinRM (secedit) |
| MySQL / SQL Server / Oracle / PostgreSQL / Redis / MongoDB | 38 | SQL / 命令 |
| Nginx / Tomcat | 13 | SSH 读配置 |
| 华为 VRP / 思科 IOS | 16 | SSH 交互式 |

每条规则 = 等保 2.0 三级条款号 + 核查命令 + 比对算子 + 期望值 + 整改建议。机器无法判定（双因素、异地备份等）自动进入**人工核查清单**。

**加规则不用改代码** —— 规则库是 YAML：

```yaml
- id: LINUX-AUTH-02
  title: 口令使用期不大于90天
  control: 身份鉴别        # 等保控制点（报告按此聚合）
  ref: 8.1.4.1-b          # 等保条款号
  severity: medium
  command: "grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}'"
  op: "<="                # 比对算子：eq/ne/gt/ge/lt/le/in/contains/regex...
  expected: "90"
  when_empty: fail        # 空值策略
  remediation: "编辑 /etc/login.defs，设置 PASS_MAX_DAYS 90"
```

将 `rules/` 目录拷到运行目录即可覆盖内嵌规则（外部优先），改完重启生效。

## 📡 分布式探针

单机即可跑全部功能；跨机房或需提速时：

```bash
# 1. Web 控制台 → 探针管理 → 添加探针（生成令牌）
# 2. 页面下载对应平台探针程序，拷到目标机器，重命名为 starruler
# 3. 执行页面给出的启动命令：

starruler --probe --server http://中心IP:8080 --token <令牌>
```

- 扫描分片（/24 网段桶）在中心与各探针间**自动均衡认领**，干完再领、绝不重复
- 探针心跳失联后分片**自动回收重派**（断点续扫）
- 探针只发起**出站**连接、不监听端口，防火墙友好；结果实时回传统一落库

## 🧰 连通探测

控制台内置 Ping（ICMP）/ Telnet（TCP 端口）/ Curl（HTTP）三件套，目标连通性一页排查。

## 🌐 REST API（可对接 SOC / 工单）

```
GET    /api/dashboard               统计
GET    /api/hosts                   主机列表        GET /api/hosts/{ip}/services   服务明细
GET    /api/assets                  核查资产        POST /api/assets               新增（camelCase）
POST   /api/tasks                   创建任务（discover / discover_weakpwd / weakpwd / baseline）
POST   /api/tasks/{id}/pause        暂停            POST /api/tasks/{id}/resume    恢复
POST   /api/tasks/{id}/cancel       取消            DELETE /api/tasks/{id}         删除（含结果）
GET    /api/tasks/{id}/weak         弱口令结果      GET /api/tasks/{id}/baseline   基线结果
GET    /api/report/{id}             HTML 合规报告   GET /api/export/{id}?type=csv  CSV 导出
POST   /api/nettool                 连通探测（ping/telnet/curl）
GET/POST /api/probes …              探针管理        /probe/register|poll|report    探针信道
```

## ⚙️ 配置（环境变量）

| 变量 | 默认 | 说明 |
|:---|:---|:---|
| `STARRULER_ADDR` | `:8080` | Web 监听地址 |
| `STARRULER_DB` | `data/starruler.db` | SQLite 路径 |
| `STARRULER_RULES` | `rules` | 外部规则目录（存在则优先于内嵌） |
| `STARRULER_PROBES` | `probes` | 探针程序下载目录 |

## 🏗️ 自行构建

### 环境要求

| 项 | 要求 |
|:---|:---|
| **Go 版本** | **1.22 及以上**（代码使用了 Go 1.22 的路由增强等特性，低版本编译会报错） |
| 操作系统 | Windows / Linux / macOS 均可编译（纯 Go，无 CGO，可交叉编译任意目标平台） |
| 网络 | 首次构建需拉取依赖；国内网络建议配置下方代理 |

**安装 Go**：

- 官方下载：https://go.dev/dl/ （或 https://golang.org/dl/）
- 国内镜像：https://golang.google.cn/dl/ 或 https://mirrors.aliyun.com/golang/
- 安装后验证：`go version` 输出 ≥ `go1.22`

**国内网络加速（拉依赖超时时配置）**：

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

### 方式一：一键构建（Windows）

```powershell
git clone <本仓库>
cd starruler
.\build.ps1        # 自动：拉依赖 → 编译中心(Windows/Linux) → 4平台探针 → 同步到 dist\
```

### 方式二：手动编译

```bash
cd starruler

# 0. 首次构建先拉依赖（约1分钟）
go mod tidy
```

**编译 Windows 主程序（最常用，只要这一个即可运行全部功能）：**

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/starruler.exe .
```

**交叉编译 Linux 版中心与四平台探针：**

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/starruler-linux-amd64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o probes/probe-windows-amd64.exe .
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o probes/probe-linux-amd64 .
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o probes/probe-linux-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o probes/probe-windows-arm64.exe .
```

> Windows PowerShell 下请用 `$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"` 的方式设置变量后再执行 `go build`。

### 产物与说明

| 产物 | 位置 | 用途 |
|:---|:---|:---|
| `dist/starruler.exe` | dist | Windows 中心（双击运行） |
| `dist/starruler-linux-amd64` | dist | Linux 中心 |
| `probes/probe-*`（4个） | probes → 复制到 dist\probes\ | 探针程序（探针管理页下载用） |

- **修改了 Web 页面（web/index.html）或规则库（rules/）后**，重新执行编译即可 —— 前端与规则都内嵌在二进制中
- `-trimpath -ldflags "-s -w"`：去除路径与符号信息，产物更小更干净；`CGO_ENABLED=0`：纯静态编译，产物拷到任何机器免依赖运行
- 单个产物编译约 30~60 秒（首次缓存依赖后更快）

## 📁 目录结构

```
starruler/
├── main.go                  # 入口（中心 / --probe 探针双模式）
├── internal/
│   ├── discover/            #   存活探测 · 端口扫描 · 三层服务指纹
│   ├── auth/                #   14 种弱口令认证器（插件注册制）
│   ├── weakpwd/             #   爆破引擎（并发池/防锁定/命中即停）
│   ├── baseline/            #   采集器 ×8 · 比对算子
│   ├── rules/               #   规则装载（内嵌 + 外部优先）
│   ├── engine/              #   分片调度（均衡派发/失联回收/断点续扫）
│   ├── probe/               #   探针 Agent
│   ├── report/              #   HTML 合规报告生成
│   ├── api/                 #   REST API · 探针信道 · 连通探测
│   └── store/               #   SQLite 存储
├── rules/                   # 12 套三级等保规则包（YAML）
├── web/index.html           # Web 控制台（内嵌）
├── build.ps1                # 一键构建脚本
└── dist/ · probes/          # 构建产物
```

## ⚠️ 安全与合规声明

- **控制台未内置登录认证**：请仅部署于受控内网，通过防火墙限制访问来源，**切勿将端口暴露到公网**
- 本工具**仅限对自有、授权的网络与系统**使用。使用前请获得书面授权，并在 IPS/防火墙上对扫描源 IP 加白报备
- 大范围扫描前建议先用小网段验证，核心设备（网络设备、生产数据库）谨慎爆破
- 核查凭据与命中口令明文存储于本地 SQLite，请严格控制部署主机访问权限
- 生成报告为技术核查辅助材料，最终测评结论以权威测评机构为准

## 📄 License

[Apache-2.0](LICENSE)© 极客星空安全实验室
欢迎关注
![公众号](./公众号.png)
---

<div align="center">

**⭐ 如果星尺对你有帮助，欢迎 Star 支持**

</div>
