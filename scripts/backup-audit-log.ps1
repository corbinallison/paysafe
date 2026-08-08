# Tollwarden audit-log offsite backup.
#
# Downloads the full tamper-evident audit log via the ADMIN_TOKEN-gated
# /v1/audit/export endpoint and writes a timestamped copy into a backup
# directory. Point -BackupDir at your MEGA sync folder and the MEGA desktop
# app handles the offsite upload automatically.
#
# Usage (PowerShell):
#   $env:TOLLWARDEN_ADMIN_TOKEN = "<your token>"
#   .\backup-audit-log.ps1 -BackupDir "C:\Users\you\MEGA\tollwarden-audit"
#
# Schedule daily via Windows Task Scheduler:
#   Program:  powershell.exe
#   Args:     -NoProfile -ExecutionPolicy Bypass -File "C:\dev\tollwarden\scripts\backup-audit-log.ps1" -BackupDir "C:\Users\you\MEGA\tollwarden-audit"
#   (Store the token machine-side:  [Environment]::SetEnvironmentVariable("TOLLWARDEN_ADMIN_TOKEN","<token>","User") )
#
# Safety property: files are timestamped and never overwritten, so the local
# history preserves every version — a rewritten server log can't silently
# replace old backups. Compare any backup's chain against audit-anchors.log.

param(
  [string]$BackupDir = "$PSScriptRoot\..\audit-backups",
  [string]$ServiceUrl = "https://tollwarden.com"
)

$ErrorActionPreference = "Stop"

$token = $env:TOLLWARDEN_ADMIN_TOKEN
if (-not $token) {
  Write-Error "TOLLWARDEN_ADMIN_TOKEN environment variable is not set."
  exit 1
}

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd'T'HHmmss'Z'")
$outFile = Join-Path $BackupDir "audit-$stamp.ndjson"

# Cache-buster: this host serves aggressively cached responses.
$uri = "$ServiceUrl/v1/audit/export?t=$stamp"

$resp = Invoke-WebRequest -Uri $uri -Headers @{ "X-Admin-Token" = $token } -UseBasicParsing
$resp.Content | Out-File -FilePath $outFile -Encoding utf8 -NoNewline

$lines = ($resp.Content -split "`n" | Where-Object { $_ }).Count
Write-Output "Backed up $lines audit records to $outFile"

# Sanity check: record count must never shrink vs the newest previous backup.
$prev = Get-ChildItem $BackupDir -Filter "audit-*.ndjson" |
  Where-Object { $_.Name -ne (Split-Path $outFile -Leaf) } |
  Sort-Object Name -Descending | Select-Object -First 1
if ($prev) {
  $prevLines = (Get-Content $prev.FullName | Where-Object { $_ }).Count
  if ($lines -lt $prevLines) {
    Write-Warning "ALERT: audit log SHRANK ($prevLines -> $lines records). Possible tampering — compare against audit-anchors.log immediately."
    exit 2
  }
}
