# 星尺 (Star ruler) 一键构建脚本（Windows PowerShell）
# 产物：
#   dist\starruler.exe              中心服务（Windows，内嵌Web与规则库）
#   dist\starruler-linux-amd64      Linux 中心/探针
#   probes\probe-windows-amd64.exe  Windows 探针（供Web下载）
#   probes\probe-linux-amd64        Linux 探针
#   probes\probe-linux-arm64        Linux ARM64 探针
#   probes\probe-windows-arm64.exe  Windows ARM64 探针
$ErrorActionPreference = "Stop"
$go = "C:\Program Files\Go\bin\go.exe"
$env:CGO_ENABLED = "0"

Write-Host "== 星尺 (Star ruler) 构建开始 ==" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path dist, probes | Out-Null

& $go mod tidy
$ldflags = "-s -w"

Write-Host "构建中心(Windows)..." -ForegroundColor Yellow
& $go build -trimpath -ldflags $ldflags -o dist\starruler.exe .

Write-Host "构建中心(Linux amd64)..." -ForegroundColor Yellow
$env:GOOS = "linux"; $env:GOARCH = "amd64"
& $go build -trimpath -ldflags $ldflags -o dist\starruler-linux-amd64 .

Write-Host "构建探针..." -ForegroundColor Yellow
$env:GOOS = "windows"; $env:GOARCH = "amd64"
& $go build -trimpath -ldflags $ldflags -o probes\probe-windows-amd64.exe .
$env:GOOS = "linux"; $env:GOARCH = "amd64"
& $go build -trimpath -ldflags $ldflags -o probes\probe-linux-amd64
$env:GOOS = "linux"; $env:GOARCH = "arm64"
& $go build -trimpath -ldflags $ldflags -o probes\probe-linux-arm64
$env:GOOS = "windows"; $env:GOARCH = "arm64"
& $go build -trimpath -ldflags $ldflags -o probes\probe-windows-arm64.exe
$env:GOOS = ""; $env:GOARCH = ""

# 探针同步到 dist（dist 目录即完整部署包）
Copy-Item probes\* dist\probes\ -Force

Write-Host "== 构建完成 ==" -ForegroundColor Green
Get-ChildItem dist, probes -File | Format-Table Name, @{L="MB";E={[math]::Round($_.Length/1MB,1)}}
Write-Host "运行中心: dist\starruler.exe  （控制台 http://localhost:8080）"
