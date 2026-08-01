#!/usr/bin/env pwsh
# precheck.ps1 — 本地预检脚本：用 clang + mock 内核头对 ksu_lkm_*.c 做语法/类型检查
# 用法: powershell -ExecutionPolicy Bypass -File precheck.ps1
# 依赖: clang 在 PATH 里（winget install LLVM.LLVM）

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$mock = Join-Path $PSScriptRoot "mock-kernel.h"
$tmp = Join-Path $env:TEMP "ksu_precheck"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$clang = (Get-Command clang -ErrorAction SilentlyContinue).Source
if (-not $clang) {
    Write-Host "[FAIL] clang 不在 PATH。先装: winget install LLVM.LLVM" -ForegroundColor Red
    exit 1
}

$failed = $false
foreach ($src in @("ksu_lkm_tp.c", "ksu_lkm_ft.c")) {
    $srcPath = Join-Path $root $src
    if (-not (Test-Path $srcPath)) { Write-Host "[SKIP] $src 不存在" -ForegroundColor Yellow; continue }

    # 把内核 include 替换为 mock 头
    $out = Join-Path $tmp ($src -replace '\.c$', '.pre.c')
    $content = Get-Content $srcPath -Raw
    $content = $content -replace '(?m)^\s*#\s*include\s*[<"].*$', ''
    $content = "#include `"$($mock -replace '\\', '/')`"`n`n" + $content
    Set-Content -Path $out -Value $content -Encoding UTF8

    Write-Host "=== 检查 $src ===" -ForegroundColor Cyan
    & $clang -fsyntax-only -Werror -Wall -Wextra -Wno-unused-parameter -Wno-unused-function `
        -Wno-missing-prototypes -Wno-missing-variable-declarations `
        -x c $out 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[PASS] $src 语法/类型检查通过" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $src 有编译错误，见上" -ForegroundColor Red
        $failed = $true
    }
}

if ($failed) { exit 1 } else { Write-Host "`n全部通过 ✔" -ForegroundColor Green }
