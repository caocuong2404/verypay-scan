---
status: done
created: 2026-03-31
updated: 2026-03-31
project: axios-scan
type: security-tooling
mode: fast
checks: 16
---

# scan.dev.verypay.io — Self-Hosted Supply Chain Scanner

## Problem Statement

VeryPay is a PCI-DSS fintech. Third-party SaaS scanners (Aikido, Socket) are not acceptable for production security tooling. The team needs a **self-hosted, zero-dependency scanner** that:

1. Detects compromised npm packages on developer workstations, VMs, and CI runners
2. Checks for active RAT infections (axios-specific IOCs + generic supply chain IOCs)
3. Provides actionable reports
4. Runs on macOS, Linux (Ubuntu VMs), and Windows
5. Hostable as a simple web page at `scan.dev.verypay.io`

## Architecture Decision

**NOT building:** A real-time install wrapper (Aikido's approach — MITM proxy, shell aliases).

**Building:** A **detection scanner** — one-shot scripts that check existing environments for compromise indicators. Self-hosted, no external API calls at runtime, consumable via curl one-liner.

## Intelligence Summary (from research)

| Source | Key Insight |
|--------|-------------|
| axios attack analysis | 10 deterministic IOC file paths per OS, C2 at `sfrclak.com:8000` |
| Aikido safe-chain source | Malware DB is flat JSON array `{package_name, version, reason}` at public URL |
| Socket/StepSecurity | `hasInstallScript` in lockfile + phantom dependency = high signal |
| npm provenance | Missing OIDC `trustedPublisher` in registry metadata = compromised publish |
| CyberDesserts/CISA | 454K+ malicious packages in 2025, Shai-Hulud worm, chalk/debug compromise |
| opensourcemalware.com | Full YARA rule, Snort signatures, obfuscation patterns (`_trans_1`, `OrDeR_7077`) |

## PCI-DSS Compliance Mapping

| PCI-DSS Req | Requirement | How Scanner Addresses |
|-------------|------------|----------------------|
| **5.2** | Deploy anti-malware on all systems | Scanner detects malware IOCs on endpoints |
| **6.3.2** | Inventory custom & third-party software | Lockfile audit inventories all dependencies |
| **6.5.4** | Protect against supply chain attacks | IOC detection for known compromised packages |
| **10.2** | Audit trail for security events | JSON report saved per scan with timestamps |
| **11.4** | Deploy IDS/IPS | Exported Snort rules for network team (check #16) |
| **11.5** | File integrity monitoring | Content pattern scan detects malicious code regardless of path (check #15) |
| **12.10** | Incident response plan | Stage 4 remediation steps with credential rotation checklist |

## Solution Design

### OS Detection (production-grade)

```bash
detect_os() → $OS, $DISTRO, $VER, $ARCH, $PLATFORM, $PKG, $CONTAINER
```

| Environment | `$OS` | `$DISTRO` | `$PLATFORM` | Extra |
|-------------|-------|-----------|-------------|-------|
| MacBook M-series | `macos` | `macOS 15.3.1` | `macos-arm64` | Rosetta detected |
| MacBook Intel | `macos` | `macOS 14.2` | `macos-x64` | — |
| Ubuntu 22.04 VM | `linux` | `Ubuntu 22.04` | `linux-x64` | `$PKG=apt` |
| Ubuntu ARM | `linux` | `Ubuntu 24.04` | `linux-arm64` | — |
| RHEL 9 server | `linux` | `RHEL 9.3` | `linux-x64` | `$PKG=yum` |
| Alpine (Docker) | `linux` | `Alpine 3.19` | `linux-x64` | `$CONTAINER=docker` |
| WSL2 Ubuntu | `wsl` | `WSL Ubuntu 22.04` | `wsl-x64` | Checks BOTH Linux + Windows IOCs |
| Git Bash Windows | `windows` | `MINGW64_NT` | `windows-x64` | — |

Detection method:
- `uname -s` → kernel (Darwin/Linux/MINGW)
- `/etc/os-release` → distro + version (standard on all modern Linux)
- `sw_vers` → macOS version
- `/proc/version` → WSL detection (`microsoft` string)
- `/.dockerenv` or `/proc/1/cgroup` → container detection
- `sysctl.proc_translated` → Rosetta detection (Apple Silicon)

### Tool Strategy (progressive fallback + self-hosted bundle)

```
Priority: rg > ag > grep    (content search)
          fd > find          (file discovery)

Source:   system binary → scan.dev.verypay.io/tools/$PLATFORM/ → builtin fallback
Verify:   SHA-256 checksum from scan.dev.verypay.io/checksums.sha256
Cleanup:  /tmp/.verypay-scan-tools/ removed on exit (trap EXIT)
```

Hosted tool bundle on `scan.dev.verypay.io`:

```
tools/
├── macos-arm64/rg, fd        # Apple Silicon Mac
├── macos-x64/rg, fd          # Intel Mac
├── linux-x64/rg, fd          # Ubuntu/RHEL VMs
├── linux-arm64/rg, fd        # ARM servers
├── windows-x64/rg.exe, fd.exe
└── checksums.sha256           # SHA-256 integrity (PCI-DSS)
```

Size: ~8MB per platform. All served from internal infra, zero external downloads.

### Lockfile Format Support

| Format | File | Type | Search Method |
|--------|------|------|---------------|
| npm | `package-lock.json` | JSON | `rg -F "plain-crypto-js"` |
| pnpm | `pnpm-lock.yaml` | YAML | `rg -F "plain-crypto-js"` |
| yarn classic | `yarn.lock` | text | `rg -F "plain-crypto-js"` |
| yarn berry | `.yarn/install-state.gz` | gzip | `zcat \| rg` |
| bun ≥1.2 | `bun.lock` | JSON | `rg -F "plain-crypto-js"` |
| bun <1.2 | `bun.lockb` | binary | `bun bun.lockb \| rg` (if bun available) |
| hidden npm | `node_modules/.package-lock.json` | JSON | forensic artifact, survives cleanup |

Discovery (narrow scope, no `find /`):

```bash
# fd: glob exact names, skip .git + node_modules
fd -t f -g '{package-lock.json,pnpm-lock.yaml,yarn.lock,bun.lock}' "$PROJECT_DIR" \
  --exclude node_modules --exclude .git

# find fallback: same pattern
find "$PROJECT_DIR" \( -name "package-lock.json" -o -name "pnpm-lock.yaml" \
  -o -name "yarn.lock" -o -name "bun.lock" \) \
  -not -path "*/node_modules/*" -not -path "*/.git/*"
```

### 4-Layer Scanner (16 checks)

```
Layer 1: Package Audit [checks 1-5]
├── Parse package-lock.json / pnpm-lock.yaml / yarn.lock / bun.lock
├── Check against embedded IOC list (axios + Shai-Hulud + chalk/debug)
├── Flag packages with hasInstallScript that are phantom dependencies
└── Check npm cache (~/.npm/_cacache) for compromised tarballs

Layer 2: Host IOC Sweep [checks 6-10]
├── macOS: /Library/Caches/com.apple.act.mond, /private/tmp/.??????
├── Linux: /tmp/ld.py, /tmp/.??????
├── Windows: %PROGRAMDATA%\wt.exe, system.bat, %TEMP%\6202033.*, registry
├── All: network connections to 142.11.206.73, sfrclak.com
└── All: DNS cache, persistence mechanisms

Layer 3: Forensic Artifacts [checks 11-14]
├── node_modules/.package-lock.json (hidden lockfile, survives cleanup)
├── npm logs (~/.npm/_logs) for postinstall execution traces
├── Shell history for C2 communication
└── Shai-Hulud worm artifacts

Layer 4: Content & Export [checks 15-16]
├── YARA-equivalent content pattern scan (grep, no binary needed)
└── Export Snort rules + YARA rules for infra/network team
```

### All 16 Checks — Cross-OS Compatibility

Primary tools: `rg` + `fd` (auto-downloaded if missing). Fallback: `grep` + `find`.

| # | Check | macOS (`scan.sh`) | Linux (`scan.sh`) | Windows (`scan.ps1`) |
|---|-------|-------------------|-------------------|---------------------|
| 1 | Lockfile: malicious axios | `rg -F "1.14.1"` in lockfiles | same | `rg` or `Select-String` |
| 2 | Lockfile: plain-crypto-js | `rg -Fl "plain-crypto-js"` | same | `rg` or `Select-String` |
| 3 | node_modules dropper dir | `test -d` | same | `Test-Path` |
| 4 | npm cache tarballs | `fd -e tgz . ~/.npm/_cacache` | same | `fd` or `Get-ChildItem $env:APPDATA\npm-cache` |
| 5 | hasInstallScript anomalies | `rg "hasInstallScript.*true"` in lockfile | same | `rg` or `Select-String` |
| 6 | RAT files on disk | `test -f` on known paths (per OS) | `test -f /tmp/ld.py` + `/tmp/.??????` | `Test-Path` on `wt.exe`, `system.bat`, `6202033.*` |
| 7 | Running processes | `pgrep -f com.apple.act.mond` | `pgrep -f ld.py` | `Get-Process` + path filter |
| 8 | Network connections | `lsof -i @142.11.206.73` | `ss -tnp \| rg 142.11.206.73` | `Get-NetTCPConnection -RemoteAddress 142.11.206.73` |
| 9 | DNS cache | `dscacheutil -cachedump \| rg sfrclak` | `rg sfrclak /var/log/syslog` | `Get-DnsClientCache \| Where Entry -like *sfrclak*` |
| 10 | Persistence | `launchctl list \| rg act.mond` | `crontab -l` + `systemctl list-units` | `Get-ItemProperty HKCU:\...\Run -Name MicrosoftUpdate` |
| 11 | Hidden lockfile | `rg "plain-crypto-js"` in `node_modules/.package-lock.json` | same | `rg` or `Select-String` |
| 12 | npm logs postinstall | `rg -l "setup.js\|plain-crypto" ~/.npm/_logs/` | same | `rg` or `Select-String` in npm cache logs |
| 13 | Shell history | `rg sfrclak ~/.zsh_history ~/.bash_history` | same | `Select-String` on PSReadLine history |
| 14 | Shai-Hulud artifacts | `fd -g 'shai-hulud*'` + `fd -g 's1ngularity*'` | same | `fd` or `Get-ChildItem -Recurse -Filter shai-hulud*` |
| 15 | Content pattern scan | `rg -l "_trans_1\|OrDeR_7077\|sfrclak"` in npm cache + node_modules | same | `rg` or `Select-String -Pattern` |
| 16 | Export Snort/YARA rules | Write `.rules` + `.yar` to report dir | same | same |

### Linux `--server` Mode (4 extra checks, narrow scope)

| # | Check | Command | Scope |
|---|-------|---------|-------|
| S1 | Docker containers | `docker inspect` → get WORKDIR → `grep lockfile` + `test -d node_modules/plain-crypto-js` (NO `find /`) | O(1) per container |
| S2 | systemd services | `systemctl list-units --type=service \| grep -E "act.mond\|ld.py"` | instant |
| S3 | Cron jobs | `for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u; done \| grep sfrclak` | instant |
| S4 | journalctl history | `journalctl --since "7 days ago" \| grep -E "sfrclak\|142.11.206.73"` | bounded |

### Deliverables

```
axios-scan/
├── scan.sh                    # macOS + Linux scanner (bash)
├── scan.ps1                   # Windows scanner (PowerShell)
├── ioc-db.json                # Embedded IOC database
├── www/
│   ├── index.html             # Landing page for scan.dev.verypay.io
│   └── report.html            # Client-side report viewer
├── tools/                     # Self-hosted static binaries (rg + fd)
│   ├── macos-arm64/rg, fd
│   ├── macos-x64/rg, fd
│   ├── linux-x64/rg, fd
│   ├── linux-arm64/rg, fd
│   ├── windows-x64/rg.exe, fd.exe
│   └── checksums.sha256
├── caddy/
│   └── Caddyfile              # Caddy config for scan.dev.verypay.io
└── plans/
    └── plan.md                # This file
```

### IOC Database Format (`ioc-db.json`)

```json
{
  "version": "2026-03-31",
  "packages": [
    {"name": "axios", "versions": ["1.14.1", "0.30.4"], "threat": "RAT dropper via plain-crypto-js", "severity": "critical"},
    {"name": "plain-crypto-js", "versions": ["*"], "threat": "Cross-platform RAT", "severity": "critical"},
    {"name": "@ctrl/tinycolor", "versions": ["4.1.1", "4.1.2"], "threat": "Shai-Hulud credential stealer", "severity": "critical"}
  ],
  "file_iocs": {
    "macos": [
      "/Library/Caches/com.apple.act.mond",
      "/private/tmp/.??????",
      "/tmp/.??????.scpt"
    ],
    "linux": [
      "/tmp/ld.py",
      "/tmp/.??????"
    ],
    "windows": [
      "%PROGRAMDATA%\\wt.exe",
      "%PROGRAMDATA%\\system.bat",
      "%TEMP%\\6202033.vbs",
      "%TEMP%\\6202033.ps1"
    ]
  },
  "network_iocs": {
    "ips": ["142.11.206.73"],
    "domains": ["sfrclak.com"],
    "ports": [8000],
    "url_paths": ["/6202033"],
    "post_bodies": ["packages.npm.org/product0", "packages.npm.org/product1", "packages.npm.org/product2"],
    "user_agent": "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
  },
  "registry_iocs": {
    "windows": ["HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftUpdate"]
  },
  "process_iocs": {
    "patterns": ["com.apple.act.mond", "ld.py", "nohup.*python3", "system.bat", "node.*setup.js", "osascript.*/tmp"]
  },
  "dns_check": {
    "macos": "dscacheutil -cachedump 2>/dev/null | grep sfrclak",
    "linux": "grep sfrclak /var/log/syslog 2>/dev/null",
    "windows": "Get-DnsClientCache | Where-Object Entry -like *sfrclak*"
  },
  "content_patterns": {
    "description": "YARA-equivalent patterns — dropper obfuscation signatures",
    "patterns": ["_trans_1", "_trans_2", "OrDeR_7077", "sfrclak", "6202033", "packages\\.npm\\.org/product"],
    "scan_paths": {
      "npm_cache": ["~/.npm/_cacache/"],
      "node_modules": ["node_modules/plain-crypto-js/", "node_modules/.package-lock.json"]
    }
  },
  "snort_rules": [
    "alert http any any -> any 8000 (msg:\"axios RAT C2 beacon\"; content:\"POST\"; http_method; content:\"sfrclak.com\"; http_header; content:\"packages.npm.org/product\"; http_client_body; sid:1000001; rev:1;)",
    "alert http any any -> any 8000 (msg:\"axios RAT stage2 download\"; content:\"POST\"; http_method; content:\"/6202033\"; http_uri; sid:1000002; rev:1;)"
  ],
  "yara_rule": "rule plain_crypto_js_malware { meta: description = \"Detects plain-crypto-js malware setup.js\" severity = \"critical\" strings: $s1 = \"_trans_1\" ascii $s2 = \"_trans_2\" ascii $s3 = \"OrDeR_7077\" ascii $s4 = \"sfrclak\" ascii nocase $s5 = \"6202033\" ascii $s6 = \"packages.npm.org/product\" ascii $s7 = \"fs.unlink(__filename\" ascii condition: 5 of them }"
}
```

## Phases

### Phase 1: Core Scanner Scripts
**Effort:** 2-3 hours | **Priority:** Critical

Build `scan.sh` (macOS/Linux) and `scan.ps1` (Windows).

#### Script UX Flow (4 stages):

```
┌──────────────────────────────────────────────────────────────┐
│  STAGE 1: INTRO & DISCLOSURE                                 │
│                                                              │
│  🔒 VeryPay Supply Chain Scanner v1.0                        │
│  ─────────────────────────────────────────────────────────── │
│  This script will perform the following checks on your       │
│  machine. No data is sent externally. (PCI-DSS compliant)    │
│                                                              │
│  ┌─ SYSTEM ──────────────────────────────────────────────┐   │
│  │  OS:        macOS 15.3.1 (arm64)                      │   │
│  │  Platform:  macos-arm64                               │   │
│  │  Container: no                                        │   │
│  │  WSL:       no                                        │   │
│  │  Tools:     rg (system) + fd (downloaded, ✅ SHA-256)  │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─ WHAT THIS SCRIPT WILL CHECK ──────────────────────────┐ │
│  │                                                         │ │
│  │  LAYER 1: Package Audit                                 │ │
│  │  [1] Scan lockfiles for axios@1.14.1, axios@0.30.4      │ │
│  │  [2] Scan lockfiles for plain-crypto-js (any version)   │ │
│  │  [3] Check node_modules/ for plain-crypto-js directory  │ │
│  │  [4] Check npm cache for compromised tarballs           │ │
│  │  [5] Check lockfiles for hasInstallScript anomalies     │ │
│  │                                                         │ │
│  │  LAYER 2: Host IOC Detection                            │ │
│  │  [6] Check for RAT files on disk (OS-specific paths)    │ │
│  │  [7] Check running processes for malware patterns       │ │
│  │  [8] Check active network connections to C2 server      │ │
│  │  [9] Check DNS cache for C2 domain resolution           │ │
│  │  [10] Check persistence mechanisms (registry/launchd)   │ │
│  │                                                         │ │
│  │  LAYER 3: Forensic Artifacts                            │ │
│  │  [11] Check hidden lockfile (node_modules/.package-lock) │ │
│  │  [12] Check npm logs for postinstall execution traces   │ │
│  │  [13] Check shell history for C2 communication          │ │
│  │  [14] Check for Shai-Hulud worm artifacts               │ │
│  │                                                         │ │
│  │  LAYER 4: Content & Export                              │ │
│  │  [15] Content pattern scan (YARA-equiv, no binary deps) │ │
│  │  [16] Export Snort + YARA rules for network/infra team  │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  Scan scope: ~/Projects (override with --project-dir)        │
│  OS detected: macOS arm64                                    │
│                                                              │
│  Proceed with scan? [Y/n] ▊                                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  STAGE 2: LIVE SCAN WITH STATUS                              │
│                                                              │
│  LAYER 1: Package Audit                                      │
│  [1/16] Scanning lockfiles for malicious axios versions      │
│         ├── ~/Projects/app-a/package-lock.json     ✅ clean  │
│         ├── ~/Projects/app-b/pnpm-lock.yaml        ✅ clean  │
│         └── Found 2 lockfiles, 0 infected                    │
│  [2/16] Scanning for plain-crypto-js                  ✅ OK  │
│  [3/16] Checking node_modules for dropper directory   ✅ OK  │
│  [4/16] Checking npm cache (~/.npm/_cacache)          ✅ OK  │
│  [5/16] Auditing hasInstallScript in lockfiles        ✅ OK  │
│                                                              │
│  LAYER 2: Host IOC Detection                                 │
│  [6/16] Checking RAT files on disk                    ✅ OK  │
│  [7/16] Checking running processes                    ✅ OK  │
│  [8/16] Checking network connections to 142.11.206.73 ✅ OK  │
│  [9/16] Checking DNS cache for sfrclak.com            ✅ OK  │
│  [10/16] Checking persistence mechanisms              ✅ OK  │
│                                                              │
│  LAYER 3: Forensic Artifacts                                 │
│  [11/16] Checking hidden lockfiles                    ✅ OK  │
│  [12/16] Checking npm logs for postinstall traces     ✅ OK  │
│  [13/16] Checking shell history                       ✅ OK  │
│  [14/16] Checking for Shai-Hulud artifacts            ✅ OK  │
│                                                              │
│  LAYER 4: Content & Export                                   │
│  [15/16] Content pattern scan (YARA-equivalent)       ✅ OK  │
│  [16/16] Exporting Snort + YARA rules                 ✅ OK  │
│                                                              │
│  Scan completed in 3.8 seconds                               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  STAGE 3: RESULTS                                            │
│                                                              │
│  ╔══════════════════════════════════════════════════════════╗ │
│  ║  ✅ CLEAN — No compromise indicators detected           ║ │
│  ╚══════════════════════════════════════════════════════════╝ │
│                                                              │
│  Checks passed: 16/16                                        │
│  Lockfiles scanned: 2                                        │
│  Projects scanned: 2                                         │
│  OS: macOS arm64                                             │
│  Scan time: 3.8s                                             │
│                                                              │
│  📄 Report: ~/.verypay-scan-report-20260331.json             │
│  📋 Snort rules: ~/.verypay-scan/axios-c2.rules              │
│  📋 YARA rule: ~/.verypay-scan/axios-malware.yar             │
│                                                              │
│  PCI-DSS: Covers 5.2, 6.3.2, 6.5.4, 10.2, 11.4, 11.5, 12.10│
│                                                              │
│  ─── OR if infected: ───────────────────────────────────     │
│                                                              │
│  ╔══════════════════════════════════════════════════════════╗ │
│  ║  🔴 INFECTED — 3 compromise indicators detected         ║ │
│  ╚══════════════════════════════════════════════════════════╝ │
│                                                              │
│  FINDINGS:                                                   │
│  🔴 [6]  /Library/Caches/com.apple.act.mond EXISTS (RAT)    │
│  🔴 [8]  Active connection to 142.11.206.73:8000            │
│  🟡 [15] Content match: OrDeR_7077 in ~/.npm/_cacache/...   │
│                                                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  STAGE 4: REMEDIATION (only shown if infected)               │
│                                                              │
│  ⚠️  IMMEDIATE ACTIONS REQUIRED:                             │
│                                                              │
│  1. ISOLATE — Disconnect this machine from the network       │
│                                                              │
│  2. KILL active RAT processes:                               │
│     macOS:   $ pkill -f com.apple.act.mond                   │
│     Linux:   $ pkill -f ld.py                                │
│     Windows: Stop-Process -Name wt -Force                    │
│                                                              │
│  3. REMOVE persistence:                                      │
│     macOS:   $ rm -f /Library/Caches/com.apple.act.mond      │
│     Linux:   $ rm -f /tmp/ld.py                              │
│     Windows: Remove-ItemProperty -Path                       │
│              "HKCU:\...\Run" -Name "MicrosoftUpdate"         │
│              Remove-Item "$env:PROGRAMDATA\wt.exe" -Force    │
│              Remove-Item "$env:PROGRAMDATA\system.bat" -Force│
│              $ rm -rf node_modules/plain-crypto-js           │
│                                                              │
│  4. BLOCK C2 at host level:                                  │
│     macOS/Linux:                                             │
│     $ echo "0.0.0.0 sfrclak.com" | sudo tee -a /etc/hosts   │
│     Windows:                                                 │
│     Add-Content $env:windir\System32\drivers\etc\hosts       │
│       "0.0.0.0 sfrclak.com"                                 │
│                                                              │
│  5. DEPLOY exported rules to network infrastructure:         │
│     $ cp ~/.verypay-scan/axios-c2.rules /etc/snort/rules/    │
│     → Gives infra team IDS coverage (PCI-DSS 11.4)          │
│                                                              │
│  6. ROTATE credentials (assume ALL compromised):             │
│     □ npm tokens      (npm token revoke && npm token create) │
│     □ SSH keys        (~/.ssh/id_rsa, id_ed25519)            │
│     □ AWS credentials (~/.aws/credentials)                   │
│     □ GCP credentials (~/.config/gcloud/)                    │
│     □ Git credentials (git credential reject)                │
│     □ .env files      (all API keys in project .env files)   │
│     □ Browser tokens  (logout all sessions)                  │
│                                                              │
│  7. CLEAN install:                                           │
│     $ rm -rf node_modules package-lock.json                  │
│     $ npm cache clean --force                                │
│     $ npm ci --ignore-scripts                                │
│                                                              │
│  8. REPORT to security team with the scan report:            │
│     ~/.verypay-scan-report-20260331.json                     │
│                                                              │
│  Run with --auto-remediate to execute steps 2-4 automatically│
│  (steps 5-8 MUST be done manually — PCI-DSS requirement)     │
│                                                              │
│  Apply auto-remediation now? [y/N] ▊                         │
└──────────────────────────────────────────────────────────────┘
```

#### Script flags:
- `--project-dir <path>` — scope lockfile scan (default: `$HOME`)
- `--server` — Linux VM mode: adds Docker (narrow scope), systemd, cron checks
- `--ci` — non-interactive, JSON output only, no prompts
- `--auto-remediate` — auto-execute kill + remove + block steps
- `--json` — output only JSON report (for piping)
- `-y` — skip confirmation prompt (for automation)

### Phase 2: Web Landing Page
**Effort:** 1 hour | **Priority:** High

Build `www/index.html`:
- Static page explaining the threat and how to scan
- One-liner copy buttons per OS
- Client-side report viewer (paste JSON, renders findings)
- No backend needed — pure static files served by Caddy

### Phase 3: Caddy Deployment
**Effort:** 30 min | **Priority:** Medium

- Serve via existing Caddy at `scan.dev.verypay.io`
- Static files (html + scripts) deployed to Caddy's file root
- IOC database in `ioc-db.json` (easy to update without code changes)

### Phase 4: CI/CD Integration (Optional)
**Effort:** 1 hour | **Priority:** Low

- Jenkins shared library step: `scanSupplyChain()`
- Runs `scan.sh --ci --project-dir .` in pipeline
- Fails build if exit code > 0
- Posts results to Teams webhook

## NOT Building (YAGNI)

- ❌ Real-time npm install wrapper (use Verdaccio blocking instead)
- ❌ Central reporting dashboard with database (JSON file reports are sufficient)
- ❌ Full automated remediation (PCI-DSS requires human for credential ops)
- ❌ Continuous monitoring daemon (one-shot scan is appropriate)
- ❌ Custom malware feed server (embed IOCs directly in scripts)
- ❌ YARA binary dependency (grep patterns give same detection for these specific IOCs)
- ❌ Snort deployment (export rules only — infra team deploys)

## Success Criteria

1. Developer runs `curl -sSL scan.dev.verypay.io/scan.sh | bash` → clean/infected verdict in <5 seconds
2. Linux VM admin runs `curl -sSL scan.dev.verypay.io/scan.sh | bash -s -- --server` → scans projects + containers
3. Windows dev runs `irm scan.dev.verypay.io/scan.ps1 | iex` → same result
4. Zero external API calls at runtime (PCI-DSS: no data leaves the network)
5. IOC database updatable without code changes
6. Snort + YARA rules exported for network team (PCI-DSS 11.4 + 11.5)
7. All 16 checks work on macOS, Linux, and Windows

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| False negatives (new attack not in IOC list) | IOC DB is separate file, update within minutes |
| Script hosted on internal domain could be MITM'd | Serve over HTTPS, checksum verification |
| Developers ignore results | Integrate into CI pipeline (Phase 4) |
| IOC list grows stale | Add `--check-update` flag that compares ioc-db.json version |
| Docker scan too slow | Narrow scope: `docker inspect` WORKDIR → check lockfile only, NO `find /` |
| Windows lacks grep | PowerShell `Select-String` used as equivalent for all checks |
