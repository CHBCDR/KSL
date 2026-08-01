#!/usr/bin/env pwsh
# godbolt-precheck.ps1 — 用 Compiler Explorer API 做 arm64 语法/类型预检
# 用法: powershell -ExecutionPolicy Bypass -File godbolt-precheck.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$mock = Join-Path $PSScriptRoot "mock-kernel.h"

$compilerId = "carm64g1020"
$api = "https://godbolt.org/api/compiler/$compilerId/compile"

function Check-Source($srcName) {
    $srcPath = Join-Path $root $srcName
    if (-not (Test-Path $srcPath)) {
        Write-Host "[SKIP] $srcName missing" -ForegroundColor Yellow
        return
    }

    $mockContent = Get-Content $mock -Raw
    $srcContent = Get-Content $srcPath -Raw

    # strip all #include lines (they reference real kernel headers)
    $srcContent = $srcContent -replace '(?m)^[ \t]*#include.*$', ''

    $combined = "/* auto-generated precheck: mock kernel + source */`n" + $mockContent + "`n`n" + $srcContent

    $body = @{
        source = $combined
        options = @{
            userArguments = "-fsyntax-only -Werror -Wall -Wno-unused-parameter -Wno-unused-function -Wno-missing-prototypes -Wno-unknown-warning-option"
            compilerOptions = @{
                executorRequest = $false
                skipAsm = $true
            }
            filters = @{
                execute = $false
            }
        }
    } | ConvertTo-Json -Depth 6

    Write-Host "=== $srcName (ARM64 GCC 10.2.0 via godbolt) ===" -ForegroundColor Cyan
    try {
        $resp = Invoke-RestMethod -Uri $api -Method Post -Body $body `
            -ContentType "application/json" -Headers @{"User-Agent"="openclaw"; "Accept"="application/json"}
    } catch {
        Write-Host "[ERR] API call failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $hasError = $false
    if ($null -ne $resp.code -and $resp.code -ne 0) { $hasError = $true }
    if ($resp.stderr) {
        foreach ($line in $resp.stderr) {
            if ($line.text -match "error:") {
                Write-Host $line.text -ForegroundColor Red
                $hasError = $true
            } elseif ($line.text -match "warning:") {
                Write-Host $line.text -ForegroundColor Yellow
            }
        }
    }
    if (-not $hasError) {
        Write-Host "[PASS] $srcName OK" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $srcName has errors" -ForegroundColor Red
    }
    Write-Host ""
}

Check-Source "ksu_lkm_sct.c"
Check-Source "ksu_lkm_tp.c"
