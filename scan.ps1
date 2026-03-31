#Requires -Version 5.1
<#
.SYNOPSIS
    VeryPay Supply Chain Scanner v1.0 — Windows PowerShell Edition
.DESCRIPTION
    Self-hosted, PCI-DSS compliant npm supply chain threat detection.
    Detects compromised npm packages (axios RAT) and other supply chain threats.
    Zero external API calls at runtime.
.EXAMPLE
    irm https://scan.dev.verypay.io/scan.ps1 | iex
.EXAMPLE
    .\scan.ps1 -ProjectDir "C:\Projects" -CI
#>
param(
    [string]$ProjectDir = $env:USERPROFILE,
    [switch]$CI,
    [switch]$AutoRemediate,
    [switch]$Json,
    [switch]$Yes,
    [switch]$Help
)

$ErrorActionPreference = "Continue"
$script:VERSION = "1.0"
$script:SCAN_DATE = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$script:SCAN_DATE_SHORT = (Get-Date).ToString("yyyyMMdd")
$script:REPORT_DIR = Join-Path $HOME ".verypay-scan"
$script:REPORT_FILE = Join-Path $HOME ".verypay-scan-report-$($script:SCAN_DATE_SHORT).json"

# --- State ---
$script:PASSED = 0; $script:FAILED = 0; $script:WARNINGS = 0
$script:LOCKFILES_FOUND = 0; $script:PROJECTS_FOUND = 0
$script:FINDINGS = @()
$script:CHECK_RESULTS = @()
$script:SCAN_START = Get-Date
$script:RG_CMD = $null

# --- IOC Data (embedded) ---
$script:C2_IP = "142.11.206.73"
$script:C2_DOMAIN = "sfrclak"
$script:MALICIOUS_PACKAGES = "plain-crypto-js"
$script:CONTENT_PATTERNS = @("_trans_1","_trans_2","OrDeR_7077","sfrclak","6202033","packages.npm.org/product")
$script:PROCESS_PATTERNS = @("wt","system.bat","node.*setup.js")
$script:INSTALL_SCRIPT_WHITELIST = @("esbuild","sharp","node-gyp","better-sqlite3","canvas","bcrypt","argon2","libsql","cpu-features","leveldown","sodium-native","keytar","node-sass","grpc","electron","puppeteer","playwright","turbo","swc","lightningcss","lmdb","msgpackr-extract")

$script:SNORT_RULES = @'
alert tcp any any -> 142.11.206.73 8000 (msg:"axios RAT C2 connection"; sid:1000001; rev:1;)
alert http any any -> any 8000 (msg:"axios RAT C2 beacon"; content:"POST"; http_method; content:"sfrclak.com"; http_header; content:"packages.npm.org/product"; http_client_body; sid:1000002; rev:1;)
alert http any any -> any 8000 (msg:"axios RAT stage2 download"; content:"POST"; http_method; content:"/6202033"; http_uri; sid:1000003; rev:1;)
'@

$script:YARA_RULE = @'
rule plain_crypto_js_malware {
  meta:
    description = "Detects plain-crypto-js malware setup.js"
    severity = "critical"
    date = "2026-03-31"
  strings:
    $s1 = "_trans_1" ascii
    $s2 = "_trans_2" ascii
    $s3 = "OrDeR_7077" ascii
    $s4 = "sfrclak" ascii nocase
    $s5 = "6202033" ascii
    $s6 = "packages.npm.org/product" ascii
    $s7 = "fs.unlink(__filename" ascii
  condition:
    5 of them
}
'@

# ============================================================================
# Output Helpers
# ============================================================================
function Write-Log { param([string]$Msg) if (-not $Json) { Write-Host $Msg } }
function Write-Ok { param([string]$Msg) if (-not $Json) { Write-Host "  ✅ $Msg" -ForegroundColor Green } }
function Write-Fail { param([string]$Msg) if (-not $Json) { Write-Host "  🔴 $Msg" -ForegroundColor Red } }
function Write-Warn { param([string]$Msg) if (-not $Json) { Write-Host "  ⚠️  $Msg" -ForegroundColor Yellow } }
function Write-Dim { param([string]$Msg) if (-not $Json) { Write-Host "  $Msg" -ForegroundColor DarkGray } }

# ============================================================================
# Help
# ============================================================================
if ($Help) {
    Write-Host @"
VeryPay Supply Chain Scanner v$($script:VERSION) (Windows)

Usage: .\scan.ps1 [OPTIONS]

Options:
  -ProjectDir <path>   Scope lockfile scan (default: %USERPROFILE%)
  -CI                  Non-interactive, JSON output only
  -AutoRemediate       Auto-execute kill + remove + block steps
  -Json                Output only JSON report
  -Yes                 Skip confirmation prompt
  -Help                Show this help

Examples:
  irm https://scan.dev.verypay.io/scan.ps1 | iex
  .\scan.ps1 -ProjectDir "C:\Projects" -CI
"@
    exit 0
}

if ($CI) { $Json = $true; $Yes = $true }

# ============================================================================
# Tool Setup
# ============================================================================
function Setup-Tools {
    if (Get-Command rg -ErrorAction SilentlyContinue) {
        $script:RG_CMD = "rg"
        Write-Dim "   Tools:     rg (system)"
    } else {
        $script:RG_CMD = $null
        Write-Dim "   Tools:     Select-String (fallback)"
    }
}

function Search-InFile {
    param([string]$Pattern, [string]$Path)
    if ($script:RG_CMD) {
        $result = & rg -l -F $Pattern $Path 2>$null
        return ($null -ne $result -and $result.Count -gt 0)
    } else {
        try {
            $result = Select-String -Path $Path -Pattern ([regex]::Escape($Pattern)) -Quiet -ErrorAction SilentlyContinue
            return $result
        } catch { return $false }
    }
}

function Find-Lockfiles {
    param([string]$Dir)
    $lockfileNames = @("package-lock.json","pnpm-lock.yaml","yarn.lock","bun.lock")
    Get-ChildItem -Path $Dir -Include $lockfileNames -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/]node_modules[\\/]' -and $_.FullName -notmatch '[\\/]\.git[\\/]' }
}

# ============================================================================
# Check Result Tracking
# ============================================================================
function Record-Check {
    param([int]$Id, [string]$Name, [string]$Layer, [string]$Status, [string]$Details = "")
    switch ($Status) {
        "pass" { $script:PASSED++; Write-Ok "[$Id/16] $Name" }
        "fail" { $script:FAILED++; Write-Fail "[$Id/16] $Name"; if ($Details) { Write-Fail "         └── $Details" } }
        "warn" { $script:WARNINGS++; Write-Warn "[$Id/16] $Name"; if ($Details) { Write-Warn "         └── $Details" } }
    }
    $script:CHECK_RESULTS += @{ id=$Id; name=$Name; layer=$Layer; status=$Status; details=$Details }
    if ($Status -eq "fail") {
        $script:FINDINGS += @{ check_id=$Id; check_name=$Name; severity="critical"; details=$Details }
    }
}

# ============================================================================
# LAYER 1: Package Audit (checks 1-5)
# ============================================================================
function Check-1-MaliciousAxios {
    Write-Log "`n  LAYER 1: Package Audit"
    $found = $false; $details = ""; $count = 0
    $lockfiles = Find-Lockfiles -Dir $ProjectDir
    $script:LOCKFILES_FOUND = @($lockfiles).Count

    if ($script:LOCKFILES_FOUND -eq 0) {
        Record-Check -Id 1 -Name "Scanning lockfiles for malicious axios versions" -Layer "Package Audit" -Status "pass" -Details "No lockfiles found"
        return
    }

    foreach ($lf in $lockfiles) {
        $script:PROJECTS_FOUND++
        $content = Get-Content $lf.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -and ($content -match 'axios') -and ($content -match '("1\.14\.1"|"0\.30\.4")')) {
            $found = $true; $count++
            $details = "INFECTED: $($lf.FullName) contains malicious axios version"
        }
        $status = if ($found) { "INFECTED" } else { "clean" }
        Write-Dim "         ├── $($lf.FullName)  $status"
    }
    Write-Dim "         └── Found $($script:LOCKFILES_FOUND) lockfiles, $count infected"

    if ($found) { Record-Check 1 "Malicious axios versions" "Package Audit" "fail" $details }
    else { Record-Check 1 "Malicious axios versions" "Package Audit" "pass" }
}

function Check-2-PlainCrypto {
    $found = $false; $details = ""
    $lockfiles = Find-Lockfiles -Dir $ProjectDir
    foreach ($lf in $lockfiles) {
        $content = Get-Content $lf.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match 'plain-crypto-js') {
            $found = $true
            $details = "FOUND: plain-crypto-js in $($lf.FullName)"
        }
    }
    if ($found) { Record-Check 2 "Scanning for plain-crypto-js" "Package Audit" "fail" $details }
    else { Record-Check 2 "Scanning for plain-crypto-js" "Package Audit" "pass" }
}

function Check-3-DropperDir {
    $found = $false; $details = ""
    $lockfiles = Find-Lockfiles -Dir $ProjectDir
    foreach ($lf in $lockfiles) {
        $projDir = Split-Path $lf.FullName
        $dropperPath = Join-Path $projDir "node_modules\plain-crypto-js"
        if (Test-Path $dropperPath) {
            $found = $true
            $details = "FOUND: $dropperPath EXISTS"
        }
    }
    if ($found) { Record-Check 3 "Checking node_modules for dropper directory" "Package Audit" "fail" $details }
    else { Record-Check 3 "Checking node_modules for dropper directory" "Package Audit" "pass" }
}

function Check-4-NpmCache {
    $cacheDir = Join-Path $env:APPDATA "npm-cache"
    if (-not (Test-Path $cacheDir)) {
        $cacheDir = Join-Path $env:LOCALAPPDATA "npm-cache"
    }
    if (-not (Test-Path $cacheDir)) {
        Record-Check 4 "Checking npm cache" "Package Audit" "pass" "No npm cache found"
        return
    }
    $found = $false
    try {
        $matches = Get-ChildItem -Path $cacheDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            Select-Object -First 500 |
            ForEach-Object {
                Select-String -Path $_.FullName -Pattern "plain-crypto-js|axios-1\.14\.1|axios-0\.30\.4" -Quiet -ErrorAction SilentlyContinue
            }
        if ($matches -contains $true) { $found = $true }
    } catch {}
    if ($found) { Record-Check 4 "Checking npm cache for compromised tarballs" "Package Audit" "fail" "Compromised package traces in npm cache" }
    else { Record-Check 4 "Checking npm cache for compromised tarballs" "Package Audit" "pass" }
}

function Check-5-InstallScripts {
    $found = $false; $suspects = @()
    $lockfiles = Find-Lockfiles -Dir $ProjectDir
    foreach ($lf in $lockfiles) {
        if ($lf.Name -ne "package-lock.json") { continue }
        $content = Get-Content $lf.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        $matches = [regex]::Matches($content, '"node_modules/([^"]+)"[^}]*?"hasInstallScript":\s*true')
        foreach ($m in $matches) {
            $pkg = $m.Groups[1].Value
            if ($pkg -notmatch "^($($script:INSTALL_SCRIPT_WHITELIST -join '|'))$") {
                $suspects += $pkg
                $found = $true
            }
        }
    }
    if ($found) { Record-Check 5 "Auditing hasInstallScript in lockfiles" "Package Audit" "warn" "Suspicious: $($suspects -join ', ')" }
    else { Record-Check 5 "Auditing hasInstallScript in lockfiles" "Package Audit" "pass" }
}

# ============================================================================
# LAYER 2: Host IOC Sweep (checks 6-10)
# ============================================================================
function Check-6-RatFiles {
    Write-Log "`n  LAYER 2: Host IOC Detection"
    $found = $false; $details = @()
    $paths = @(
        (Join-Path $env:PROGRAMDATA "wt.exe"),
        (Join-Path $env:PROGRAMDATA "system.bat"),
        (Join-Path $env:TEMP "6202033.vbs"),
        (Join-Path $env:TEMP "6202033.ps1")
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { $found = $true; $details += "$p EXISTS" }
    }
    if ($found) { Record-Check 6 "Checking RAT files on disk" "Host IOC" "fail" ($details -join "; ") }
    else { Record-Check 6 "Checking RAT files on disk" "Host IOC" "pass" }
}

function Check-7-Processes {
    $found = $false; $details = ""
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match 'wt' -or $_.ProcessName -match 'system' -or
            ($_.Path -and ($_.Path -match 'setup\.js' -or $_.Path -match 'system\.bat'))
        }
        # Filter out Windows Terminal (wt is legitimate)
        $suspicious = $procs | Where-Object {
            -not ($_.ProcessName -eq 'WindowsTerminal') -and
            ($_.Path -and ($_.Path -match 'ProgramData[\\/]wt\.exe' -or $_.Path -match 'system\.bat' -or $_.Path -match 'setup\.js'))
        }
        if ($suspicious) {
            $found = $true
            $details = "Suspicious processes: $($suspicious.ProcessName -join ', ')"
        }
    } catch {}
    if ($found) { Record-Check 7 "Checking running processes" "Host IOC" "fail" $details }
    else { Record-Check 7 "Checking running processes" "Host IOC" "pass" }
}

function Check-8-Network {
    $found = $false; $details = ""
    try {
        $conns = Get-NetTCPConnection -RemoteAddress $script:C2_IP -ErrorAction SilentlyContinue
        if ($conns) { $found = $true; $details = "Active connection to $($script:C2_IP)" }
    } catch {}
    if ($found) { Record-Check 8 "Checking network connections to C2" "Host IOC" "fail" $details }
    else { Record-Check 8 "Checking network connections to $($script:C2_IP)" "Host IOC" "pass" }
}

function Check-9-Dns {
    $found = $false; $details = ""
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -like "*$($script:C2_DOMAIN)*" }
        if ($dns) { $found = $true; $details = "DNS cache contains $($script:C2_DOMAIN)" }
    } catch {}
    if ($found) { Record-Check 9 "Checking DNS cache for C2 domain" "Host IOC" "fail" $details }
    else { Record-Check 9 "Checking DNS cache for $($script:C2_DOMAIN)" "Host IOC" "pass" }
}

function Check-10-Persistence {
    $found = $false; $details = ""
    try {
        $reg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftUpdate" -ErrorAction SilentlyContinue
        if ($reg) { $found = $true; $details = "Registry Run key 'MicrosoftUpdate' found" }
    } catch {}
    # Check scheduled tasks
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -match 'sfrclak|act\.mond|MicrosoftUpdate'
        }
        if ($tasks) { $found = $true; $details += " Suspicious scheduled tasks found" }
    } catch {}
    if ($found) { Record-Check 10 "Checking persistence mechanisms" "Host IOC" "fail" $details }
    else { Record-Check 10 "Checking persistence mechanisms" "Host IOC" "pass" }
}

# ============================================================================
# LAYER 3: Forensic Artifacts (checks 11-14)
# ============================================================================
function Check-11-HiddenLockfile {
    Write-Log "`n  LAYER 3: Forensic Artifacts"
    $found = $false; $details = ""
    $lockfiles = Find-Lockfiles -Dir $ProjectDir
    foreach ($lf in $lockfiles) {
        $projDir = Split-Path $lf.FullName
        $hidden = Join-Path $projDir "node_modules\.package-lock.json"
        if (Test-Path $hidden) {
            $content = Get-Content $hidden -Raw -ErrorAction SilentlyContinue
            if ($content -match 'plain-crypto-js') {
                $found = $true
                $details = "FOUND: plain-crypto-js in $hidden"
            }
        }
    }
    if ($found) { Record-Check 11 "Checking hidden lockfiles" "Forensic" "fail" $details }
    else { Record-Check 11 "Checking hidden lockfiles" "Forensic" "pass" }
}

function Check-12-NpmLogs {
    $logDir = Join-Path $HOME ".npm\_logs"
    if (-not (Test-Path $logDir)) {
        $logDir = Join-Path $env:APPDATA "npm-cache\_logs"
    }
    if (-not (Test-Path $logDir)) {
        Record-Check 12 "Checking npm logs" "Forensic" "pass" "No npm logs found"
        return
    }
    $found = $false
    try {
        $matches = Get-ChildItem $logDir -File -ErrorAction SilentlyContinue |
            ForEach-Object { Select-String -Path $_.FullName -Pattern "setup\.js|plain-crypto" -Quiet -ErrorAction SilentlyContinue }
        if ($matches -contains $true) { $found = $true }
    } catch {}
    if ($found) { Record-Check 12 "Checking npm logs for postinstall traces" "Forensic" "warn" "postinstall execution traces found" }
    else { Record-Check 12 "Checking npm logs for postinstall traces" "Forensic" "pass" }
}

function Check-13-ShellHistory {
    $found = $false; $details = ""
    $histPath = $null
    try { $histPath = (Get-PSReadLineOption).HistorySavePath } catch {}
    if ($histPath -and (Test-Path $histPath)) {
        $match = Select-String -Path $histPath -Pattern $script:C2_DOMAIN -Quiet -ErrorAction SilentlyContinue
        if ($match) { $found = $true; $details = "FOUND: $($script:C2_DOMAIN) in PSReadLine history" }
        $match2 = Select-String -Path $histPath -Pattern $script:C2_IP -Quiet -ErrorAction SilentlyContinue
        if ($match2) { $found = $true; $details += " FOUND: $($script:C2_IP) in history" }
    }
    if ($found) { Record-Check 13 "Checking shell history" "Forensic" "warn" $details }
    else { Record-Check 13 "Checking shell history" "Forensic" "pass" }
}

function Check-14-ShaiHulud {
    $found = $false; $details = ""
    try {
        $matches = Get-ChildItem -Path $ProjectDir -Recurse -Filter "shai-hulud*" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/]node_modules[\\/]' -and $_.FullName -notmatch '[\\/]\.git[\\/]' }
        if ($matches) { $found = $true; $details = "FOUND: Shai-Hulud artifacts" }
        $matches2 = Get-ChildItem -Path $ProjectDir -Recurse -Filter "s1ngularity*" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/]node_modules[\\/]' -and $_.FullName -notmatch '[\\/]\.git[\\/]' }
        if ($matches2) { $found = $true; $details += " FOUND: s1ngularity artifacts" }
    } catch {}
    if ($found) { Record-Check 14 "Checking for Shai-Hulud artifacts" "Forensic" "fail" $details }
    else { Record-Check 14 "Checking for Shai-Hulud artifacts" "Forensic" "pass" }
}

# ============================================================================
# LAYER 4: Content & Export (checks 15-16)
# ============================================================================
function Check-15-ContentScan {
    Write-Log "`n  LAYER 4: Content & Export"
    $found = $false; $details = ""
    $cacheDir = Join-Path $env:APPDATA "npm-cache\_cacache"
    if (-not (Test-Path $cacheDir)) { $cacheDir = Join-Path $HOME ".npm\_cacache" }

    if (Test-Path $cacheDir) {
        $pattern = $script:CONTENT_PATTERNS -join '|'
        try {
            $matches = Get-ChildItem $cacheDir -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object -First 200 |
                ForEach-Object { Select-String -Path $_.FullName -Pattern $pattern -Quiet -ErrorAction SilentlyContinue }
            if ($matches -contains $true) { $found = $true; $details = "Obfuscation signatures in npm cache" }
        } catch {}
    }
    if ($found) { Record-Check 15 "Content pattern scan (YARA-equivalent)" "Content" "fail" $details }
    else { Record-Check 15 "Content pattern scan (YARA-equivalent)" "Content" "pass" }
}

function Check-16-ExportRules {
    New-Item -ItemType Directory -Path $script:REPORT_DIR -Force -ErrorAction SilentlyContinue | Out-Null
    $script:SNORT_RULES | Out-File (Join-Path $script:REPORT_DIR "axios-c2.rules") -Encoding utf8
    $script:YARA_RULE | Out-File (Join-Path $script:REPORT_DIR "axios-malware.yar") -Encoding utf8
    Record-Check 16 "Exporting Snort + YARA rules" "Content" "pass" "Rules exported to $($script:REPORT_DIR)"
}

# ============================================================================
# Report Generation
# ============================================================================
function Generate-Report {
    $verdict = if ($script:FAILED -gt 0) { "INFECTED" } else { "CLEAN" }
    $duration = [math]::Round(((Get-Date) - $script:SCAN_START).TotalSeconds, 1)

    $report = @{
        scanner_version = $script:VERSION
        scan_date = $script:SCAN_DATE
        system = @{
            os = "windows"
            distro = "Windows $([System.Environment]::OSVersion.Version)"
            arch = $env:PROCESSOR_ARCHITECTURE
            platform = "windows-x64"
            container = "none"
            wsl = "no"
        }
        scan_scope = $ProjectDir
        scan_duration_seconds = $duration
        verdict = $verdict
        total_checks = 16
        passed = $script:PASSED
        failed = $script:FAILED
        warnings = $script:WARNINGS
        lockfiles_scanned = $script:LOCKFILES_FOUND
        projects_scanned = $script:PROJECTS_FOUND
        findings = $script:FINDINGS
        checks = $script:CHECK_RESULTS
        exported_rules = @{
            snort = Join-Path $script:REPORT_DIR "axios-c2.rules"
            yara = Join-Path $script:REPORT_DIR "axios-malware.yar"
        }
    }

    $report | ConvertTo-Json -Depth 5 | Out-File $script:REPORT_FILE -Encoding utf8
}

# ============================================================================
# Stage 1: Intro
# ============================================================================
function Show-Intro {
    Write-Log ""
    Write-Host "  🔒 VeryPay Supply Chain Scanner v$($script:VERSION)" -ForegroundColor Cyan
    Write-Log "  ───────────────────────────────────────────────────────"
    Write-Log "  This script performs security checks on your machine."
    Write-Log "  No data is sent externally. (PCI-DSS compliant)"
    Write-Log ""
    Write-Log "  ┌─ SYSTEM ──────────────────────────────────────────────┐"
    Write-Log "  │  OS:        Windows $([System.Environment]::OSVersion.Version) ($env:PROCESSOR_ARCHITECTURE)"
    Write-Log "  │  Platform:  windows-x64"
    Setup-Tools
    Write-Log "  └───────────────────────────────────────────────────────┘"
    Write-Log ""
    Write-Log "  ┌─ WHAT THIS SCRIPT WILL CHECK ──────────────────────────┐"
    Write-Log "  │  LAYER 1: Package Audit          [checks 1-5]          │"
    Write-Log "  │  LAYER 2: Host IOC Detection     [checks 6-10]         │"
    Write-Log "  │  LAYER 3: Forensic Artifacts     [checks 11-14]        │"
    Write-Log "  │  LAYER 4: Content & Export       [checks 15-16]        │"
    Write-Log "  └─────────────────────────────────────────────────────────┘"
    Write-Log ""
    Write-Log "  Scan scope: $ProjectDir"
    Write-Log ""

    if (-not $Yes) {
        $confirm = Read-Host "  Proceed with scan? [Y/n]"
        if ($confirm -match '^[Nn]') { Write-Log "  Scan cancelled."; exit 0 }
    }
}

# ============================================================================
# Stage 3: Results
# ============================================================================
function Show-Results {
    $duration = [math]::Round(((Get-Date) - $script:SCAN_START).TotalSeconds, 1)
    Write-Log ""
    if ($script:FAILED -gt 0) {
        Write-Log "  ╔══════════════════════════════════════════════════════════╗"
        Write-Host "  ║  🔴 INFECTED — $($script:FAILED) compromise indicator(s) detected          ║" -ForegroundColor Red
        Write-Log "  ╚══════════════════════════════════════════════════════════╝"
        Write-Log ""
        Write-Host "  FINDINGS:" -ForegroundColor Red
        foreach ($f in $script:FINDINGS) {
            Write-Host "  [$($f.check_id)] $($f.details)" -ForegroundColor Red
        }
    } else {
        Write-Log "  ╔══════════════════════════════════════════════════════════╗"
        Write-Host "  ║  ✅ CLEAN — No compromise indicators detected            ║" -ForegroundColor Green
        Write-Log "  ╚══════════════════════════════════════════════════════════╝"
    }
    Write-Log ""
    Write-Log "  Checks passed: $($script:PASSED)/16"
    if ($script:WARNINGS -gt 0) { Write-Log "  Warnings: $($script:WARNINGS)" }
    Write-Log "  Lockfiles scanned: $($script:LOCKFILES_FOUND)"
    Write-Log "  Projects scanned: $($script:PROJECTS_FOUND)"
    Write-Log "  Scan time: ${duration}s"
    Write-Log ""
    Write-Log "  📄 Report: $($script:REPORT_FILE)"
    Write-Log "  📋 Snort rules: $(Join-Path $script:REPORT_DIR 'axios-c2.rules')"
    Write-Log "  📋 YARA rule: $(Join-Path $script:REPORT_DIR 'axios-malware.yar')"
    Write-Log ""
    Write-Log "  PCI-DSS: Covers 5.2, 6.3.2, 6.5.4, 10.2, 11.4, 11.5, 12.10"
}

# ============================================================================
# Stage 4: Remediation
# ============================================================================
function Show-Remediation {
    if ($script:FAILED -eq 0) { return }
    Write-Log ""
    Write-Host "  ⚠️  IMMEDIATE ACTIONS REQUIRED:" -ForegroundColor Yellow
    Write-Log ""
    Write-Log "  1. ISOLATE — Disconnect this machine from the network"
    Write-Log ""
    Write-Log "  2. KILL active RAT processes:"
    Write-Log "     Stop-Process -Name wt -Force -ErrorAction SilentlyContinue"
    Write-Log ""
    Write-Log "  3. REMOVE persistence & files:"
    Write-Log '     Remove-Item "$env:PROGRAMDATA\wt.exe" -Force'
    Write-Log '     Remove-Item "$env:PROGRAMDATA\system.bat" -Force'
    Write-Log '     Remove-Item "$env:TEMP\6202033.vbs" -Force'
    Write-Log '     Remove-Item "$env:TEMP\6202033.ps1" -Force'
    Write-Log '     Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftUpdate"'
    Write-Log '     Remove-Item "node_modules\plain-crypto-js" -Recurse -Force'
    Write-Log ""
    Write-Log "  4. BLOCK C2 at host level:"
    Write-Log '     Add-Content "$env:windir\System32\drivers\etc\hosts" "0.0.0.0 sfrclak.com"'
    Write-Log ""
    Write-Log "  5. ROTATE credentials (assume ALL compromised):"
    Write-Log "     □ npm tokens, SSH keys, AWS/GCP credentials"
    Write-Log "     □ .env files, Git credentials, Browser sessions"
    Write-Log ""
    Write-Log "  6. CLEAN install:"
    Write-Log "     Remove-Item node_modules,package-lock.json -Recurse -Force"
    Write-Log "     npm cache clean --force"
    Write-Log "     npm ci --ignore-scripts"
    Write-Log ""

    if ($AutoRemediate) {
        Write-Host "  Auto-remediating steps 2-4..." -ForegroundColor Yellow
        Stop-Process -Name wt -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $env:PROGRAMDATA "wt.exe") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $env:PROGRAMDATA "system.bat") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $env:TEMP "6202033.vbs") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $env:TEMP "6202033.ps1") -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MicrosoftUpdate" -ErrorAction SilentlyContinue
        try { Add-Content "$env:windir\System32\drivers\etc\hosts" "`n0.0.0.0 sfrclak.com" -ErrorAction Stop }
        catch { Write-Warn "Could not modify hosts file (run as Administrator)" }
        Write-Ok "Auto-remediation complete (steps 2-4)"
        Write-Log "  Steps 5-6 MUST be done manually (PCI-DSS requirement)"
    } elseif (-not $Yes) {
        $confirm = Read-Host "  Apply auto-remediation now? [y/N]"
        if ($confirm -match '^[Yy]') {
            $script:AutoRemediate = $true
            Show-Remediation
        }
    }
}

# ============================================================================
# Main
# ============================================================================
if (-not $Json) { Show-Intro; Write-Log ""; Write-Log "  STAGE 2: SCANNING" }
else { Setup-Tools }

Check-1-MaliciousAxios
Check-2-PlainCrypto
Check-3-DropperDir
Check-4-NpmCache
Check-5-InstallScripts
Check-6-RatFiles
Check-7-Processes
Check-8-Network
Check-9-Dns
Check-10-Persistence
Check-11-HiddenLockfile
Check-12-NpmLogs
Check-13-ShellHistory
Check-14-ShaiHulud
Check-15-ContentScan
Check-16-ExportRules

Generate-Report

if ($Json) {
    Get-Content $script:REPORT_FILE
} else {
    Show-Results
    Show-Remediation
}

if ($script:FAILED -gt 0) { exit 1 }
exit 0
