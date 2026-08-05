# SecureAssess — Phases 1–8 (authorized assessments only)
# Usage (PowerShell):
#   $env:SA_URL  = "https://dev.falaya.com/"
#   $env:SA_USER = "you@example.com"
#   $env:SA_PASS = "..."                  # never commit
#   $env:SA_USER2 = "account-b@..."       # optional Phase 5
#   $env:SA_PASS2 = "..."                 # optional Phase 5
#   .\scripts\run-falaya-phases.ps1
#
# Optional:
#   $env:SA_FOCUS   = "/api/,/app/"
#   $env:SA_OPENAPI = "https://dev.falaya.com/openapi.json"
#   $env:SA_OUT     = "reports"
#   $env:SA_FROM    = "1"   # start phase number
#   $env:SA_TO      = "8"   # end phase number

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Require-Env([string]$Name) {
  $v = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($v)) {
    throw "Missing required env var: $Name"
  }
  return $v
}

$url = Require-Env "SA_URL"
$user = Require-Env "SA_USER"
$pass = Require-Env "SA_PASS"
$out = if ($env:SA_OUT) { $env:SA_OUT } else { "reports" }
$from = if ($env:SA_FROM) { [int]$env:SA_FROM } else { 1 }
$to = if ($env:SA_TO) { [int]$env:SA_TO } else { 8 }
$focus = $env:SA_FOCUS
$openapi = $env:SA_OPENAPI
$user2 = $env:SA_USER2
$pass2 = $env:SA_PASS2

New-Item -ItemType Directory -Force -Path $out | Out-Null

function Invoke-Scan {
  param(
    [string]$Project,
    [string]$Profile,
    [string]$Mode = "active-safe",
    [string]$Types = "",
    [switch]$WithAuth,
    [switch]$WithAuth2,
    [switch]$WithFocus,
    [switch]$WithOpenApi
  )

  $args = @(
    "run", "scan", "--",
    "--url", $url,
    "--profile", $Profile,
    "--project", $Project,
    "--mode", $Mode,
    "--yes",
    "--out", $out
  )
  if ($WithAuth) {
    $args += @("--username", $user, "--password", $pass)
  }
  if ($WithAuth2) {
    if ([string]::IsNullOrWhiteSpace($user2) -or [string]::IsNullOrWhiteSpace($pass2)) {
      Write-Warning "Phase skipped extras: SA_USER2/SA_PASS2 not set — running Account A only."
    } else {
      $args += @("--username2", $user2, "--password2", $pass2)
    }
  }
  if ($Types) {
    $args += @("--types", $Types)
  }
  if ($WithFocus -and $focus) {
    $args += @("--focus", $focus)
  }
  if ($WithOpenApi -and $openapi) {
    $args += @("--openapi", $openapi)
  }

  Write-Host ""
  Write-Host "=== $Project (profile=$Profile mode=$Mode) ===" -ForegroundColor Cyan
  & npm @args
  if ($LASTEXITCODE -ne 0) {
    throw "Scan failed for $Project (exit $LASTEXITCODE)"
  }
}

function Invoke-Gate {
  $report = Get-ChildItem -Path $out -Filter *.json -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "sarif" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if (-not $report) {
    $report = Get-ChildItem -Path $out -Filter *.sarif.json -File -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 1
  }
  if (-not $report) {
    throw "No report JSON found under $out for ci:gate"
  }
  Write-Host ""
  Write-Host "=== Phase 8: CI gate on $($report.Name) ===" -ForegroundColor Cyan
  if ($report.Name -match "sarif") {
    & npm run ci:gate -- --sarif $report.FullName
  } else {
    & npm run ci:gate -- --json $report.FullName
  }
  return $LASTEXITCODE
}

Write-Host "SecureAssess phases $from..$to against $url" -ForegroundColor Green
Write-Host "Reports -> $out"

if ($from -le 1 -and $to -ge 1) {
  # Phase 1 — Smoke
  Invoke-Scan -Project "Falaya P1 smoke" -Profile "quick" -WithAuth
}

if ($from -le 2 -and $to -ge 2) {
  # Phase 2 — Standard recommended (default types = platform recommended via orchestrator when omitted)
  Invoke-Scan -Project "Falaya P2 standard" -Profile "standard" -WithAuth
}

if ($from -le 3 -and $to -ge 3) {
  # Phase 3 — Deep
  Invoke-Scan -Project "Falaya P3 deep" -Profile "deep" -WithAuth
}

if ($from -le 4 -and $to -ge 4) {
  # Phase 4 — Focused (uses SA_FOCUS / SA_OPENAPI when set)
  if (-not $focus -and -not $openapi) {
    Write-Warning "Phase 4: set SA_FOCUS and/or SA_OPENAPI for best results. Running focused profile with auth only."
  }
  Invoke-Scan -Project "Falaya P4 focused" -Profile "focused" -WithAuth -WithFocus -WithOpenApi
}

if ($from -le 5 -and $to -ge 5) {
  # Phase 5 — Dual-account BAC / IDOR emphasis
  Invoke-Scan -Project "Falaya P5 dual-account" -Profile "standard" -Mode "authenticated" `
    -Types "idor,bac,api_security,session_mgmt,jwt,cookie_security" `
    -WithAuth -WithAuth2
}

if ($from -le 6 -and $to -ge 6) {
  # Phase 6a — Passive
  Invoke-Scan -Project "Falaya P6a passive" -Profile "quick" -Mode "passive"
  # Phase 6b — Active-safe authed
  Invoke-Scan -Project "Falaya P6b active-safe" -Profile "quick" -Mode "active-safe" -WithAuth
  # Phase 6c — Authenticated
  Invoke-Scan -Project "Falaya P6c authenticated" -Profile "quick" -Mode "authenticated" -WithAuth
}

if ($from -le 7 -and $to -ge 7) {
  # Phase 7 — UI mirror: deep + broad types (plugins still limited to installed modules)
  Invoke-Scan -Project "Falaya P7 deep-all-types" -Profile "deep" -Mode "active-safe" `
    -Types "sqli,nosqli,xss,ssti,lfi,ssrf,idor,bac,jwt,csrf,session_mgmt,cookie_security,http_headers,cors,info_disclosure,open_redirect,api_security,security_misconfig,sensitive_data" `
    -WithAuth -WithAuth2 -WithFocus -WithOpenApi
}

$gateCode = 0
if ($from -le 8 -and $to -ge 8) {
  $gateCode = Invoke-Gate
}

Write-Host ""
Write-Host "Phases complete. Open dashboard: http://localhost:3847/dashboard.html" -ForegroundColor Green
Write-Host "Review HTML/PDF/SARIF under .\$out"
if ($gateCode -ne 0) {
  Write-Host "CI gate exit code: $gateCode (Confirmed High/Critical present or gate error)" -ForegroundColor Yellow
  exit $gateCode
}
exit 0
