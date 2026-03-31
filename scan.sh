#!/usr/bin/env bash
# ============================================================================
# VeryPay Supply Chain Scanner v1.0
# Self-hosted, PCI-DSS compliant npm supply chain threat detection
# Zero external API calls at runtime
# ============================================================================
set -uo pipefail

VERSION="1.0"
SCAN_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCAN_DATE_SHORT=$(date -u +"%Y%m%d")
REPORT_DIR="$HOME/.verypay-scan"
REPORT_FILE="$HOME/.verypay-scan-report-${SCAN_DATE_SHORT}.json"
TOOLS_DIR="/tmp/.verypay-scan-tools"
TOOLS_URL="https://scan.dev.verypay.io/tools"

# --- Defaults ---
PROJECT_DIR="$HOME"
SERVER_MODE=false
CI_MODE=false
AUTO_REMEDIATE=false
JSON_ONLY=false
YES_MODE=false

# --- State ---
OS="" DISTRO="" ARCH="" PLATFORM="" CONTAINER="" PKG="" ROSETTA=""
RG_CMD="" FD_CMD=""
TOTAL_CHECKS=16 PASSED=0 FAILED=0 WARNINGS=0
LOCKFILES_FOUND=0 PROJECTS_FOUND=0
declare -a FINDINGS=()
declare -a CHECK_RESULTS=()
SCAN_START=0

# --- IOC Data (embedded, no external reads) ---
MALICIOUS_AXIOS_VERSIONS="1.14.1|0.30.4"
MALICIOUS_PACKAGES="plain-crypto-js"
MALICIOUS_TINYCOLOR="@ctrl/tinycolor"
MALICIOUS_TINYCOLOR_VERSIONS="4.1.1|4.1.2"
C2_IP="142.11.206.73"
C2_DOMAIN="sfrclak"
C2_PORT="8000"
CONTENT_PATTERNS="_trans_1|_trans_2|OrDeR_7077|sfrclak|6202033|packages\.npm\.org/product"
PROCESS_PATTERNS="com.apple.act.mond|ld\.py|nohup.*python3|system\.bat|node.*setup\.js|osascript.*/tmp"
INSTALL_SCRIPT_WHITELIST="esbuild|sharp|node-gyp|better-sqlite3|canvas|bcrypt|argon2|libsql|cpu-features|fsevents|leveldown|sodium-native|keytar|node-sass|grpc|electron|puppeteer|playwright|turbo|swc|lightningcss|lmdb|msgpackr-extract|aws-sdk|husky|patch-package|core-js|core-js-pure|es5-ext|ejs|nan|re2|protobufjs|utf-8-validate|bufferutil|prisma|@prisma/client|@prisma/engines|cypress|msw|nx|nodemon|deasync|docsify|@parcel/watcher|@fortawesome/.*|vite/node_modules/esbuild|@apollo/protobufjs|@nestjs/core|sqlite3|@nestjs/.*|better-sqlite3|node-pre-gyp|@mapbox/node-pre-gyp|cpu-features|lz4-napi|snappy|dtrace-provider|kerberos|mongodb-client-encryption|@mongodb-js/.*|node-rdkafka|zeromq|farmhash|xxhash-addon|gl|microtime"

SNORT_RULES='alert tcp any any -> 142.11.206.73 8000 (msg:"axios RAT C2 connection"; sid:1000001; rev:1;)
alert http any any -> any 8000 (msg:"axios RAT C2 beacon"; content:"POST"; http_method; content:"sfrclak.com"; http_header; content:"packages.npm.org/product"; http_client_body; sid:1000002; rev:1;)
alert http any any -> any 8000 (msg:"axios RAT stage2 download"; content:"POST"; http_method; content:"/6202033"; http_uri; sid:1000003; rev:1;)'

YARA_RULE='rule plain_crypto_js_malware {
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
}'

# ============================================================================
# Colors & Output
# ============================================================================
if [[ -t 1 ]] && [[ "${CI_MODE}" == "false" ]]; then
  RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[0;33m'
  BLUE='\033[0;34m' CYAN='\033[0;36m' BOLD='\033[1m'
  DIM='\033[2m' NC='\033[0m'
else
  RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
fi

setup_colors() {
  if [[ "${CI_MODE}" == "true" ]] || [[ "${JSON_ONLY}" == "true" ]]; then
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
  fi
}

log()  { [[ "${JSON_ONLY}" == "true" ]] && return; echo -e "$*"; }
info() { log "${BLUE}ℹ${NC}  $*"; }
ok()   { log "${GREEN}[PASS]${NC} $*"; }
warn() { log "${YELLOW}[WARN]${NC} $*"; }
fail() { log "${RED}[FAIL]${NC} $*"; }
dim()  { log "${DIM}$*${NC}"; }

# ============================================================================
# Argument Parsing
# ============================================================================
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project-dir) PROJECT_DIR="$2"; shift 2 ;;
      --server)      SERVER_MODE=true; shift ;;
      --ci)          CI_MODE=true; YES_MODE=true; JSON_ONLY=true; shift ;;
      --auto-remediate) AUTO_REMEDIATE=true; shift ;;
      --json)        JSON_ONLY=true; shift ;;
      -y)            YES_MODE=true; shift ;;
      -h|--help)     usage; exit 0 ;;
      *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
  setup_colors
}

usage() {
  cat <<EOF
VeryPay Supply Chain Scanner v${VERSION}

Usage: scan.sh [OPTIONS]

Options:
  --project-dir <path>   Scope lockfile scan (default: \$HOME)
  --server               Linux VM mode: Docker, systemd, cron, journalctl checks
  --ci                   Non-interactive, JSON output only
  --auto-remediate       Auto-execute kill + remove + block steps
  --json                 Output only JSON report
  -y                     Skip confirmation prompt
  -h, --help             Show this help

Examples:
  curl -sSL https://scan.dev.verypay.io/scan.sh | bash
  curl -sSL https://scan.dev.verypay.io/scan.sh | bash -s -- --server
  curl -sSL https://scan.dev.verypay.io/scan.sh | bash -s -- --ci --project-dir .
EOF
}

# ============================================================================
# OS Detection
# ============================================================================
detect_os() {
  local kernel
  kernel=$(uname -s)
  ARCH=$(uname -m)
  case "$kernel" in
    Darwin)
      OS="macos"
      DISTRO="macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
      [[ "$ARCH" == "arm64" ]] && PLATFORM="macos-arm64" || PLATFORM="macos-x64"
      sysctl -n sysctl.proc_translated 2>/dev/null | grep -q 1 && ROSETTA="yes" || ROSETTA="no"
      ;;
    Linux)
      OS="linux"
      [[ "$ARCH" == "aarch64" ]] && PLATFORM="linux-arm64" || PLATFORM="linux-x64"
      if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO="${NAME:-Linux} ${VERSION_ID:-}"
      else
        DISTRO="Linux"
      fi
      if grep -qi microsoft /proc/version 2>/dev/null; then
        OS="wsl"
        DISTRO="WSL ${DISTRO}"
      fi
      [ -f /.dockerenv ] && CONTAINER="docker"
      grep -q 'docker\|containerd' /proc/1/cgroup 2>/dev/null && CONTAINER="docker"
      command -v apt >/dev/null 2>&1 && PKG="apt"
      command -v yum >/dev/null 2>&1 && PKG="yum"
      command -v apk >/dev/null 2>&1 && PKG="apk"
      ;;
    MINGW*|MSYS*)
      OS="windows"; PLATFORM="windows-x64"; DISTRO="$kernel"
      ;;
    *)
      OS="unknown"; PLATFORM="unknown"; DISTRO="$kernel"
      ;;
  esac
}

# ============================================================================
# Tool Setup (progressive fallback)
# ============================================================================
setup_tools() {
  # ripgrep
  if command -v rg >/dev/null 2>&1; then
    RG_CMD="rg"
    dim "   Tools:     rg (system)"
  else
    RG_CMD="grep"
    dim "   Tools:     grep (fallback)"
  fi

  # fd
  if command -v fd >/dev/null 2>&1; then
    FD_CMD="fd"
  elif command -v fdfind >/dev/null 2>&1; then
    FD_CMD="fdfind"
  else
    FD_CMD=""
  fi
}

# Search helper: uses rg if available, grep otherwise
search_file() {
  local pattern="$1" file="$2"
  if [[ "$RG_CMD" == "rg" ]]; then
    rg -l -F "$pattern" "$file" 2>/dev/null
  else
    grep -rl -F "$pattern" "$file" 2>/dev/null
  fi
}

search_pattern() {
  local pattern="$1" file="$2"
  if [[ "$RG_CMD" == "rg" ]]; then
    rg -l "$pattern" "$file" 2>/dev/null
  else
    grep -rl -E "$pattern" "$file" 2>/dev/null
  fi
}

# Find lockfiles helper
find_lockfiles() {
  local dir="$1"
  if [[ -n "$FD_CMD" ]]; then
    $FD_CMD -t f -g '{package-lock.json,pnpm-lock.yaml,yarn.lock,bun.lock}' "$dir" \
      --exclude node_modules --exclude .git 2>/dev/null
  else
    find "$dir" \( -name "package-lock.json" -o -name "pnpm-lock.yaml" \
      -o -name "yarn.lock" -o -name "bun.lock" \) \
      -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null
  fi
}

# ============================================================================
# Check Result Tracking
# ============================================================================
record_check() {
  local id="$1" name="$2" layer="$3" status="$4" details="${5:-}"
  case "$status" in
    pass) ((PASSED++)); ok "[${id}/16] ${name}" ;;
    fail) ((FAILED++)); fail "[${id}/16] ${name}"; [[ -n "$details" ]] && fail "         └── ${details}" ;;
    warn) ((WARNINGS++)); warn "[${id}/16] ${name}"; [[ -n "$details" ]] && warn "         └── ${details}" ;;
  esac
  CHECK_RESULTS+=("{\"id\":${id},\"name\":\"${name}\",\"layer\":\"${layer}\",\"status\":\"${status}\",\"details\":\"$(echo "$details" | sed 's/"/\\"/g')\"}")
  if [[ "$status" == "fail" ]]; then
    FINDINGS+=("{\"check_id\":${id},\"check_name\":\"${name}\",\"severity\":\"critical\",\"details\":\"$(echo "$details" | sed 's/"/\\"/g')\"}")
  fi
}

# ============================================================================
# LAYER 1: Package Audit (checks 1-5)
# ============================================================================
check_1_malicious_axios() {
  log "\n  ${BOLD}LAYER 1: Package Audit${NC}"
  local found=false details="" count=0
  local lockfiles
  lockfiles=$(find_lockfiles "$PROJECT_DIR")
  if [[ -z "$lockfiles" ]]; then
    LOCKFILES_FOUND=0
  else
    LOCKFILES_FOUND=$(echo "$lockfiles" | wc -l | tr -d ' ')
  fi

  if [[ "$LOCKFILES_FOUND" -eq 0 ]]; then
    record_check 1 "Scanning lockfiles for malicious axios versions" "Package Audit" "pass" "No lockfiles found in ${PROJECT_DIR}"
    return
  fi

  while IFS= read -r lf; do
    [[ -z "$lf" ]] && continue
    local dir
    dir=$(dirname "$lf")
    PROJECTS_FOUND=$((PROJECTS_FOUND + 1))
    # Check for axios specifically at malicious versions
    # Must match patterns like: axios@1.14.1, "axios": "1.14.1", axios: 1.14.1, axios@0.30.4
    local lf_infected=false
    if [[ "$RG_CMD" == "rg" ]]; then
      if rg -q 'axios@(1\.14\.1|0\.30\.4)|"axios":\s*"(1\.14\.1|0\.30\.4)"|axios:\s+(1\.14\.1|0\.30\.4)' "$lf" 2>/dev/null; then
        lf_infected=true
      fi
    else
      if grep -qE 'axios@(1\.14\.1|0\.30\.4)|"axios":\s*"(1\.14\.1|0\.30\.4)"|axios:\s+(1\.14\.1|0\.30\.4)' "$lf" 2>/dev/null; then
        lf_infected=true
      fi
    fi
    if $lf_infected; then
      found=true
      details="INFECTED: ${lf} contains malicious axios version"
      ((count++))
    fi
    dim "         ├── ${lf}  $(if $lf_infected; then echo "${RED}[!] INFECTED${NC}"; else echo "${GREEN}[+] clean${NC}"; fi)"
  done <<< "$lockfiles"
  dim "         └── Found ${LOCKFILES_FOUND} lockfiles, ${count} infected"

  if $found; then
    record_check 1 "Malicious axios versions" "Package Audit" "fail" "$details"
  else
    record_check 1 "Malicious axios versions" "Package Audit" "pass"
  fi
}

check_2_plain_crypto() {
  local found=false details=""
  local lockfiles
  lockfiles=$(find_lockfiles "$PROJECT_DIR")

  while IFS= read -r lf; do
    [[ -z "$lf" ]] && continue
    if search_file "$MALICIOUS_PACKAGES" "$lf" >/dev/null 2>&1; then
      found=true
      details="FOUND: plain-crypto-js referenced in ${lf}"
    fi
  done <<< "$lockfiles"

  if $found; then
    record_check 2 "Scanning for plain-crypto-js" "Package Audit" "fail" "$details"
  else
    record_check 2 "Scanning for plain-crypto-js" "Package Audit" "pass"
  fi
}

check_3_dropper_dir() {
  local found=false details=""
  local lockfiles
  lockfiles=$(find_lockfiles "$PROJECT_DIR")

  while IFS= read -r lf; do
    [[ -z "$lf" ]] && continue
    local project_dir
    project_dir=$(dirname "$lf")
    if [[ -d "${project_dir}/node_modules/plain-crypto-js" ]]; then
      found=true
      details="FOUND: ${project_dir}/node_modules/plain-crypto-js EXISTS"
    fi
  done <<< "$lockfiles"

  if $found; then
    record_check 3 "Checking node_modules for dropper directory" "Package Audit" "fail" "$details"
  else
    record_check 3 "Checking node_modules for dropper directory" "Package Audit" "pass"
  fi
}

check_4_npm_cache() {
  local found=false details=""
  local cache_dir="$HOME/.npm/_cacache"
  [[ ! -d "$cache_dir" ]] && { record_check 4 "Checking npm cache" "Package Audit" "pass" "No npm cache found"; return; }

  if search_pattern "plain-crypto-js|axios-1\.14\.1|axios-0\.30\.4" "$cache_dir" >/dev/null 2>&1; then
    found=true
    details="FOUND: Compromised package traces in npm cache"
  fi

  if $found; then
    record_check 4 "Checking npm cache for compromised tarballs" "Package Audit" "fail" "$details"
  else
    record_check 4 "Checking npm cache for compromised tarballs" "Package Audit" "pass"
  fi
}

check_5_install_scripts() {
  local found=false details="" suspects=""
  local lockfiles
  lockfiles=$(find_lockfiles "$PROJECT_DIR")

  while IFS= read -r lf; do
    [[ -z "$lf" ]] && continue
    [[ "$(basename "$lf")" != "package-lock.json" ]] && continue
    local matches
    matches=$(grep -B5 '"hasInstallScript": true' "$lf" 2>/dev/null | grep '"node_modules/' | sed 's/.*"node_modules\///;s/".*//' || true)
    while IFS= read -r pkg; do
      [[ -z "$pkg" ]] && continue
      if ! echo "$pkg" | grep -qiE "^(${INSTALL_SCRIPT_WHITELIST})$"; then
        suspects="${suspects}${pkg}, "
        found=true
      fi
    done <<< "$matches"
  done <<< "$lockfiles"

  if $found; then
    record_check 5 "Auditing hasInstallScript in lockfiles" "Package Audit" "warn" "Suspicious packages with install scripts: ${suspects%,*}"
  else
    record_check 5 "Auditing hasInstallScript in lockfiles" "Package Audit" "pass"
  fi
}

# ============================================================================
# LAYER 2: Host IOC Sweep (checks 6-10)
# ============================================================================
check_6_rat_files() {
  log "\n  ${BOLD}LAYER 2: Host IOC Detection${NC}"
  local found=false details=""

  case "$OS" in
    macos)
      [[ -f "/Library/Caches/com.apple.act.mond" ]] && { found=true; details="/Library/Caches/com.apple.act.mond EXISTS (RAT binary)"; }
      # Check for 6-char hidden files in /tmp
      local hidden
      hidden=$(find /private/tmp /tmp -maxdepth 1 -name '.??????' -type f 2>/dev/null | head -5)
      [[ -n "$hidden" ]] && { found=true; details="${details} Hidden files in /tmp: ${hidden}"; }
      ;;
    linux|wsl)
      [[ -f "/tmp/ld.py" ]] && { found=true; details="/tmp/ld.py EXISTS (RAT dropper)"; }
      local hidden
      hidden=$(find /tmp -maxdepth 1 -name '.??????' -type f 2>/dev/null | head -5)
      [[ -n "$hidden" ]] && { found=true; details="${details} Hidden files in /tmp: ${hidden}"; }
      # WSL: also check Windows paths
      if [[ "$OS" == "wsl" ]]; then
        local win_programdata="/mnt/c/ProgramData"
        [[ -f "${win_programdata}/wt.exe" ]] && { found=true; details="${details} ${win_programdata}/wt.exe EXISTS"; }
        [[ -f "${win_programdata}/system.bat" ]] && { found=true; details="${details} ${win_programdata}/system.bat EXISTS"; }
      fi
      ;;
  esac

  if $found; then
    record_check 6 "Checking RAT files on disk" "Host IOC" "fail" "$details"
  else
    record_check 6 "Checking RAT files on disk" "Host IOC" "pass"
  fi
}

check_7_processes() {
  local found=false details=""

  if command -v pgrep >/dev/null 2>&1; then
    local matches
    matches=$(pgrep -fa "com\.apple\.act\.mond|ld\.py|nohup.*python3|system\.bat|node.*setup\.js|osascript.*/tmp" 2>/dev/null | grep -v "$$" | grep -v "scan\.sh" || true)
    if [[ -n "$matches" ]]; then
      found=true
      details="Suspicious processes: $(echo "$matches" | head -3 | tr '\n' '; ')"
    fi
  fi

  if $found; then
    record_check 7 "Checking running processes" "Host IOC" "fail" "$details"
  else
    record_check 7 "Checking running processes" "Host IOC" "pass"
  fi
}

check_8_network() {
  local found=false details=""

  case "$OS" in
    macos)
      if command -v lsof >/dev/null 2>&1; then
        local conns
        conns=$(lsof -i "@${C2_IP}" 2>/dev/null || true)
        [[ -n "$conns" ]] && { found=true; details="Active connection to ${C2_IP}"; }
      fi
      ;;
    linux|wsl)
      if command -v ss >/dev/null 2>&1; then
        local conns
        conns=$(ss -tnp 2>/dev/null | grep "$C2_IP" || true)
        [[ -n "$conns" ]] && { found=true; details="Active connection to ${C2_IP}"; }
      elif command -v netstat >/dev/null 2>&1; then
        local conns
        conns=$(netstat -tnp 2>/dev/null | grep "$C2_IP" || true)
        [[ -n "$conns" ]] && { found=true; details="Active connection to ${C2_IP}"; }
      fi
      ;;
  esac

  if $found; then
    record_check 8 "Checking network connections to C2" "Host IOC" "fail" "$details"
  else
    record_check 8 "Checking network connections to ${C2_IP}" "Host IOC" "pass"
  fi
}

check_9_dns() {
  local found=false details=""

  case "$OS" in
    macos)
      if command -v dscacheutil >/dev/null 2>&1; then
        local dns
        dns=$(dscacheutil -cachedump 2>/dev/null | grep -i "$C2_DOMAIN" || true)
        [[ -n "$dns" ]] && { found=true; details="DNS cache contains ${C2_DOMAIN}"; }
      fi
      ;;
    linux|wsl)
      if [[ -f /var/log/syslog ]]; then
        local dns
        dns=$(grep -i "$C2_DOMAIN" /var/log/syslog 2>/dev/null | tail -3 || true)
        [[ -n "$dns" ]] && { found=true; details="syslog contains ${C2_DOMAIN} DNS resolution"; }
      fi
      ;;
  esac

  if $found; then
    record_check 9 "Checking DNS cache for C2 domain" "Host IOC" "fail" "$details"
  else
    record_check 9 "Checking DNS cache for ${C2_DOMAIN}" "Host IOC" "pass"
  fi
}

check_10_persistence() {
  local found=false details=""

  case "$OS" in
    macos)
      if command -v launchctl >/dev/null 2>&1; then
        local la
        la=$(launchctl list 2>/dev/null | grep -i "act.mond" || true)
        [[ -n "$la" ]] && { found=true; details="launchctl persistence: act.mond service found"; }
      fi
      # Check LaunchAgents/LaunchDaemons plist files
      local plist_matches
      plist_matches=$(grep -rl "act.mond\|sfrclak\|plain-crypto" ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null || true)
      [[ -n "$plist_matches" ]] && { found=true; details="${details} Suspicious plist: ${plist_matches}"; }
      ;;
    linux|wsl)
      local cron_match
      cron_match=$(crontab -l 2>/dev/null | grep -iE "sfrclak|${C2_IP}|ld\.py|plain-crypto" || true)
      [[ -n "$cron_match" ]] && { found=true; details="Crontab persistence found"; }
      if command -v systemctl >/dev/null 2>&1; then
        local svc
        svc=$(systemctl list-units --type=service 2>/dev/null | grep -iE "act.mond|ld\.py" || true)
        [[ -n "$svc" ]] && { found=true; details="${details} systemd persistence found"; }
      fi
      ;;
  esac

  if $found; then
    record_check 10 "Checking persistence mechanisms" "Host IOC" "fail" "$details"
  else
    record_check 10 "Checking persistence mechanisms" "Host IOC" "pass"
  fi
}

# ============================================================================
# LAYER 3: Forensic Artifacts (checks 11-14)
# ============================================================================
check_11_hidden_lockfile() {
  log "\n  ${BOLD}LAYER 3: Forensic Artifacts${NC}"
  local found=false details=""
  local lockfiles
  lockfiles=$(find_lockfiles "$PROJECT_DIR")

  while IFS= read -r lf; do
    [[ -z "$lf" ]] && continue
    local project_dir hidden_lf
    project_dir=$(dirname "$lf")
    hidden_lf="${project_dir}/node_modules/.package-lock.json"
    if [[ -f "$hidden_lf" ]]; then
      if search_file "$MALICIOUS_PACKAGES" "$hidden_lf" >/dev/null 2>&1; then
        found=true
        details="FOUND: plain-crypto-js in hidden lockfile ${hidden_lf}"
      fi
    fi
  done <<< "$lockfiles"

  if $found; then
    record_check 11 "Checking hidden lockfiles" "Forensic" "fail" "$details"
  else
    record_check 11 "Checking hidden lockfiles" "Forensic" "pass"
  fi
}

check_12_npm_logs() {
  local found=false details=""
  local log_dir="$HOME/.npm/_logs"
  [[ ! -d "$log_dir" ]] && { record_check 12 "Checking npm logs for postinstall traces" "Forensic" "pass" "No npm logs found"; return; }

  if search_pattern "setup\.js|plain-crypto" "$log_dir" >/dev/null 2>&1; then
    found=true
    details="FOUND: postinstall execution traces in npm logs"
  fi

  if $found; then
    record_check 12 "Checking npm logs for postinstall traces" "Forensic" "warn" "$details"
  else
    record_check 12 "Checking npm logs for postinstall traces" "Forensic" "pass"
  fi
}

check_13_shell_history() {
  local found=false details=""
  local history_files=("$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.local/share/fish/fish_history")

  for hf in "${history_files[@]}"; do
    [[ ! -f "$hf" ]] && continue
    if grep -qi "$C2_DOMAIN" "$hf" 2>/dev/null; then
      found=true
      details="FOUND: ${C2_DOMAIN} in shell history ${hf}"
    fi
    if grep -qi "$C2_IP" "$hf" 2>/dev/null; then
      found=true
      details="${details} FOUND: ${C2_IP} in ${hf}"
    fi
  done

  if $found; then
    record_check 13 "Checking shell history" "Forensic" "warn" "$details"
  else
    record_check 13 "Checking shell history" "Forensic" "pass"
  fi
}

check_14_shai_hulud() {
  local found=false details=""

  # Search for shai-hulud workflow files
  if [[ -n "$FD_CMD" ]]; then
    local matches
    matches=$($FD_CMD -g 'shai-hulud*' "$PROJECT_DIR" --exclude node_modules --exclude .git 2>/dev/null || true)
    [[ -n "$matches" ]] && { found=true; details="FOUND: Shai-Hulud artifacts: ${matches}"; }
    matches=$($FD_CMD -g 's1ngularity*' "$PROJECT_DIR" --exclude node_modules --exclude .git 2>/dev/null || true)
    [[ -n "$matches" ]] && { found=true; details="${details} FOUND: s1ngularity artifacts: ${matches}"; }
  else
    local matches
    matches=$(find "$PROJECT_DIR" -name 'shai-hulud*' -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -5 || true)
    [[ -n "$matches" ]] && { found=true; details="FOUND: Shai-Hulud artifacts: ${matches}"; }
    matches=$(find "$PROJECT_DIR" -name 's1ngularity*' -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -5 || true)
    [[ -n "$matches" ]] && { found=true; details="${details} FOUND: s1ngularity artifacts: ${matches}"; }
  fi

  if $found; then
    record_check 14 "Checking for Shai-Hulud artifacts" "Forensic" "fail" "$details"
  else
    record_check 14 "Checking for Shai-Hulud artifacts" "Forensic" "pass"
  fi
}

# ============================================================================
# LAYER 4: Content & Export (checks 15-16)
# ============================================================================
check_15_content_scan() {
  log "\n  ${BOLD}LAYER 4: Content & Export${NC}"
  local found=false details=""

  # Scan npm cache
  local cache_dir="$HOME/.npm/_cacache"
  if [[ -d "$cache_dir" ]]; then
    if search_pattern "$CONTENT_PATTERNS" "$cache_dir" >/dev/null 2>&1; then
      found=true
      details="FOUND: Obfuscation signatures in npm cache"
    fi
  fi

  # Scan node_modules for known malicious dirs
  local lockfiles
  lockfiles=$(find_lockfiles "$PROJECT_DIR")
  while IFS= read -r lf; do
    [[ -z "$lf" ]] && continue
    local project_dir
    project_dir=$(dirname "$lf")
    local nm_dir="${project_dir}/node_modules"
    [[ ! -d "$nm_dir" ]] && continue
    # Only scan plain-crypto-js dir and .package-lock.json, not entire node_modules
    if [[ -d "${nm_dir}/plain-crypto-js" ]]; then
      if search_pattern "$CONTENT_PATTERNS" "${nm_dir}/plain-crypto-js" >/dev/null 2>&1; then
        found=true
        details="${details} FOUND: Malicious patterns in ${nm_dir}/plain-crypto-js"
      fi
    fi
  done <<< "$lockfiles"

  if $found; then
    record_check 15 "Content pattern scan (YARA-equivalent)" "Content" "fail" "$details"
  else
    record_check 15 "Content pattern scan (YARA-equivalent)" "Content" "pass"
  fi
}

check_16_export_rules() {
  mkdir -p "$REPORT_DIR" 2>/dev/null

  echo "$SNORT_RULES" > "${REPORT_DIR}/axios-c2.rules"
  echo "$YARA_RULE" > "${REPORT_DIR}/axios-malware.yar"

  record_check 16 "Exporting Snort + YARA rules" "Content" "pass" "Rules exported to ${REPORT_DIR}/"
}

# ============================================================================
# Server Mode Checks (S1-S4)
# ============================================================================
run_server_checks() {
  log "\n  ${BOLD}SERVER MODE: Additional Checks${NC}"

  # S1: Docker containers
  if command -v docker >/dev/null 2>&1; then
    local containers
    containers=$(docker ps -q 2>/dev/null || true)
    if [[ -n "$containers" ]]; then
      local docker_found=false
      while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local workdir
        workdir=$(docker inspect --format '{{.Config.WorkingDir}}' "$cid" 2>/dev/null || echo "/app")
        # Check for plain-crypto-js in container
        if docker exec "$cid" test -d "${workdir}/node_modules/plain-crypto-js" 2>/dev/null; then
          docker_found=true
          warn "  [S1] Container ${cid}: node_modules/plain-crypto-js FOUND"
        fi
        # Check lockfile in container
        if docker exec "$cid" grep -q "plain-crypto-js" "${workdir}/package-lock.json" 2>/dev/null; then
          docker_found=true
          warn "  [S1] Container ${cid}: plain-crypto-js in lockfile"
        fi
      done <<< "$containers"
      if $docker_found; then
        FINDINGS+=("{\"check_id\":\"S1\",\"check_name\":\"Docker containers\",\"severity\":\"critical\",\"details\":\"Compromised packages in containers\"}")
        ((FAILED++))
      else
        ok "  [S1] Docker containers: clean"
      fi
    else
      dim "  [S1] Docker: no running containers"
    fi
  else
    dim "  [S1] Docker: not installed"
  fi

  # S2: systemd services
  if command -v systemctl >/dev/null 2>&1; then
    local svc_match
    svc_match=$(systemctl list-units --type=service 2>/dev/null | grep -iE "act\.mond|ld\.py" || true)
    if [[ -n "$svc_match" ]]; then
      fail "  [S2] Suspicious systemd services: ${svc_match}"
      FINDINGS+=("{\"check_id\":\"S2\",\"check_name\":\"systemd services\",\"severity\":\"critical\",\"details\":\"${svc_match}\"}")
      ((FAILED++))
    else
      ok "  [S2] systemd services: clean"
    fi
  fi

  # S3: Cron jobs
  local cron_found=false
  while IFS=: read -r user _; do
    [[ -z "$user" ]] && continue
    local cron_match
    cron_match=$(crontab -l -u "$user" 2>/dev/null | grep -iE "sfrclak|${C2_IP}|ld\.py|plain-crypto" || true)
    if [[ -n "$cron_match" ]]; then
      cron_found=true
      fail "  [S3] Cron for user ${user}: ${cron_match}"
    fi
  done < /etc/passwd 2>/dev/null
  if $cron_found; then
    FINDINGS+=("{\"check_id\":\"S3\",\"check_name\":\"Cron jobs\",\"severity\":\"critical\",\"details\":\"C2 references in crontab\"}")
    ((FAILED++))
  else
    ok "  [S3] Cron jobs: clean"
  fi

  # S4: journalctl
  if command -v journalctl >/dev/null 2>&1; then
    local journal_match
    journal_match=$(journalctl --since "7 days ago" --no-pager 2>/dev/null | grep -iE "sfrclak|${C2_IP}" | tail -5 || true)
    if [[ -n "$journal_match" ]]; then
      warn "  [S4] journalctl: C2 references in last 7 days"
      FINDINGS+=("{\"check_id\":\"S4\",\"check_name\":\"journalctl\",\"severity\":\"high\",\"details\":\"C2 references in system logs\"}")
      ((WARNINGS++))
    else
      ok "  [S4] journalctl: clean (last 7 days)"
    fi
  fi
}

# ============================================================================
# Report Generation
# ============================================================================
generate_report() {
  local verdict="CLEAN"
  [[ "$FAILED" -gt 0 ]] && verdict="INFECTED"

  local scan_end
  scan_end=$(date +%s)
  local duration=$((scan_end - SCAN_START))

  local checks_json
  checks_json=$(printf '%s,' "${CHECK_RESULTS[@]}" | sed 's/,$//')
  local findings_json
  findings_json=$(printf '%s,' "${FINDINGS[@]}" | sed 's/,$//')
  [[ -z "$findings_json" ]] && findings_json=""

  cat > "$REPORT_FILE" <<EOF
{
  "scanner_version": "${VERSION}",
  "scan_date": "${SCAN_DATE}",
  "system": {
    "os": "${OS}",
    "distro": "${DISTRO}",
    "arch": "${ARCH}",
    "platform": "${PLATFORM}",
    "container": "${CONTAINER:-none}",
    "wsl": "$([ "$OS" = "wsl" ] && echo "yes" || echo "no")"
  },
  "scan_scope": "${PROJECT_DIR}",
  "scan_duration_seconds": ${duration},
  "verdict": "${verdict}",
  "total_checks": ${TOTAL_CHECKS},
  "passed": ${PASSED},
  "failed": ${FAILED},
  "warnings": ${WARNINGS},
  "lockfiles_scanned": ${LOCKFILES_FOUND},
  "projects_scanned": ${PROJECTS_FOUND},
  "findings": [${findings_json}],
  "checks": [${checks_json}],
  "exported_rules": {
    "snort": "${REPORT_DIR}/axios-c2.rules",
    "yara": "${REPORT_DIR}/axios-malware.yar"
  }
}
EOF
}

# ============================================================================
# Stage 1: Intro & Disclosure
# ============================================================================
show_intro() {
  log ""
  log "  ${BOLD}VeryPay Supply Chain Scanner v${VERSION}${NC}"
  log "  ───────────────────────────────────────────────────────"
  log "  This script will perform the following checks on your"
  log "  machine. No data is sent externally. (PCI-DSS compliant)"
  log ""
  log "  ┌─ SYSTEM ──────────────────────────────────────────────┐"
  log "  │  OS:        ${DISTRO} (${ARCH})"
  log "  │  Platform:  ${PLATFORM}"
  log "  │  Container: ${CONTAINER:-no}"
  [[ "$OS" == "wsl" ]] && log "  │  WSL:       yes"
  setup_tools
  log "  └───────────────────────────────────────────────────────┘"
  log ""
  log "  ┌─ WHAT THIS SCRIPT WILL CHECK ──────────────────────────┐"
  log "  │                                                         │"
  log "  │  LAYER 1: Package Audit                                 │"
  log "  │  [1]  Scan lockfiles for axios@1.14.1, axios@0.30.4     │"
  log "  │  [2]  Scan lockfiles for plain-crypto-js (any version)  │"
  log "  │  [3]  Check node_modules/ for plain-crypto-js directory │"
  log "  │  [4]  Check npm cache for compromised tarballs          │"
  log "  │  [5]  Check lockfiles for hasInstallScript anomalies    │"
  log "  │                                                         │"
  log "  │  LAYER 2: Host IOC Detection                            │"
  log "  │  [6]  Check for RAT files on disk (OS-specific paths)   │"
  log "  │  [7]  Check running processes for malware patterns      │"
  log "  │  [8]  Check active network connections to C2 server     │"
  log "  │  [9]  Check DNS cache for C2 domain resolution          │"
  log "  │  [10] Check persistence mechanisms (launchd/cron/systemd)│"
  log "  │                                                         │"
  log "  │  LAYER 3: Forensic Artifacts                            │"
  log "  │  [11] Check hidden lockfile (node_modules/.package-lock) │"
  log "  │  [12] Check npm logs for postinstall execution traces   │"
  log "  │  [13] Check shell history for C2 communication          │"
  log "  │  [14] Check for Shai-Hulud worm artifacts               │"
  log "  │                                                         │"
  log "  │  LAYER 4: Content & Export                              │"
  log "  │  [15] Content pattern scan (YARA-equiv, no binary deps) │"
  log "  │  [16] Export Snort + YARA rules for network/infra team  │"
  log "  │                                                         │"
  log "  └─────────────────────────────────────────────────────────┘"
  log ""
  log "  Scan scope: ${PROJECT_DIR}"
  [[ "$SERVER_MODE" == "true" ]] && log "  Server mode: ON (+Docker, systemd, cron, journalctl)"
  log ""

  if [[ "$YES_MODE" == "false" ]]; then
    read -rp "  Proceed with scan? [Y/n] " confirm
    if [[ "$confirm" =~ ^[Nn] ]]; then
      log "  Scan cancelled."
      exit 0
    fi
  fi
}

# ============================================================================
# Stage 3: Results
# ============================================================================
show_results() {
  local scan_end
  scan_end=$(date +%s)
  local duration=$((scan_end - SCAN_START))

  log ""
  if [[ "$FAILED" -gt 0 ]]; then
    log "  ╔══════════════════════════════════════════════════════════╗"
    log "  ║  ${RED}${BOLD}INFECTED -- ${FAILED} compromise indicator(s) detected${NC}          ║"
    log "  ╚══════════════════════════════════════════════════════════╝"
    log ""
    log "  ${BOLD}FINDINGS:${NC}"
    for finding in "${FINDINGS[@]}"; do
      local check_id check_name details
      check_id=$(echo "$finding" | grep -o '"check_id":[0-9]*' | cut -d: -f2)
      details=$(echo "$finding" | sed 's/.*"details":"\([^"]*\)".*/\1/')
      fail "  [${check_id}] ${details}"
    done
  else
    log "  ╔══════════════════════════════════════════════════════════╗"
    log "  ║  ${GREEN}${BOLD}CLEAN -- No compromise indicators detected${NC}               ║"
    log "  ╚══════════════════════════════════════════════════════════╝"
  fi

  log ""
  log "  Checks passed: ${PASSED}/${TOTAL_CHECKS}"
  [[ "$WARNINGS" -gt 0 ]] && log "  Warnings: ${WARNINGS}"
  log "  Lockfiles scanned: ${LOCKFILES_FOUND}"
  log "  Projects scanned: ${PROJECTS_FOUND}"
  log "  OS: ${DISTRO} (${ARCH})"
  log "  Scan time: ${duration}s"
  log ""
  log "  Report: ${REPORT_FILE}"
  log "  Snort rules: ${REPORT_DIR}/axios-c2.rules"
  log "  YARA rule: ${REPORT_DIR}/axios-malware.yar"
  log ""
  log "  PCI-DSS: Covers 5.2, 6.3.2, 6.5.4, 10.2, 11.4, 11.5, 12.10"
}

# ============================================================================
# Stage 4: Remediation
# ============================================================================
show_remediation() {
  [[ "$FAILED" -eq 0 ]] && return

  log ""
  log "  ${BOLD}IMMEDIATE ACTIONS REQUIRED:${NC}"
  log ""
  log "  1. ${BOLD}ISOLATE${NC} — Disconnect this machine from the network"
  log ""
  log "  2. ${BOLD}KILL${NC} active RAT processes:"
  case "$OS" in
    macos) log "     \$ pkill -f com.apple.act.mond" ;;
    linux|wsl) log "     \$ pkill -f ld.py" ;;
  esac
  log ""
  log "  3. ${BOLD}REMOVE${NC} persistence:"
  case "$OS" in
    macos) log "     \$ rm -f /Library/Caches/com.apple.act.mond" ;;
    linux|wsl) log "     \$ rm -f /tmp/ld.py" ;;
  esac
  log "     \$ rm -rf node_modules/plain-crypto-js"
  log ""
  log "  4. ${BOLD}BLOCK${NC} C2 at host level:"
  log "     \$ echo \"0.0.0.0 sfrclak.com\" | sudo tee -a /etc/hosts"
  log ""
  log "  5. ${BOLD}DEPLOY${NC} exported rules to network infrastructure:"
  log "     \$ cp ${REPORT_DIR}/axios-c2.rules /etc/snort/rules/"
  log ""
  log "  6. ${BOLD}ROTATE${NC} credentials (assume ALL compromised):"
  log "     □ npm tokens      (npm token revoke && npm token create)"
  log "     □ SSH keys        (~/.ssh/id_rsa, id_ed25519)"
  log "     □ AWS credentials (~/.aws/credentials)"
  log "     □ GCP credentials (~/.config/gcloud/)"
  log "     □ Git credentials (git credential reject)"
  log "     □ .env files      (all API keys in project .env files)"
  log "     □ Browser tokens  (logout all sessions)"
  log ""
  log "  7. ${BOLD}CLEAN${NC} install:"
  log "     \$ rm -rf node_modules package-lock.json"
  log "     \$ npm cache clean --force"
  log "     \$ npm ci --ignore-scripts"
  log ""
  log "  8. ${BOLD}REPORT${NC} to security team with the scan report:"
  log "     ${REPORT_FILE}"
  log ""

  if [[ "$AUTO_REMEDIATE" == "true" ]]; then
    log "  ${BOLD}Auto-remediating steps 2-4...${NC}"
    case "$OS" in
      macos)
        pkill -f "com.apple.act.mond" 2>/dev/null || true
        rm -f /Library/Caches/com.apple.act.mond 2>/dev/null || true
        ;;
      linux|wsl)
        pkill -f "ld.py" 2>/dev/null || true
        rm -f /tmp/ld.py 2>/dev/null || true
        ;;
    esac
    # Block C2
    if ! grep -q "sfrclak.com" /etc/hosts 2>/dev/null; then
      echo "0.0.0.0 sfrclak.com" | sudo tee -a /etc/hosts >/dev/null 2>&1 || warn "  Could not modify /etc/hosts (need sudo)"
    fi
    ok "  Auto-remediation complete (steps 2-4)"
    log "  Steps 5-8 MUST be done manually (PCI-DSS requirement)"
  else
    if [[ "$YES_MODE" == "false" ]]; then
      read -rp "  Apply auto-remediation now? [y/N] " confirm
      if [[ "$confirm" =~ ^[Yy] ]]; then
        AUTO_REMEDIATE=true
        show_remediation
      fi
    fi
  fi
}

# ============================================================================
# Cleanup
# ============================================================================
cleanup() {
  rm -rf "$TOOLS_DIR" 2>/dev/null || true
}

# ============================================================================
# Main
# ============================================================================
main() {
  parse_args "$@"
  trap cleanup EXIT

  detect_os
  SCAN_START=$(date +%s)

  # Stage 1: Intro
  if [[ "$JSON_ONLY" != "true" ]]; then
    show_intro
    log ""
    log "  ${BOLD}STAGE 2: SCANNING${NC}"
  else
    setup_tools >/dev/null 2>&1
  fi

  # Stage 2: Run checks
  check_1_malicious_axios
  check_2_plain_crypto
  check_3_dropper_dir
  check_4_npm_cache
  check_5_install_scripts
  check_6_rat_files
  check_7_processes
  check_8_network
  check_9_dns
  check_10_persistence
  check_11_hidden_lockfile
  check_12_npm_logs
  check_13_shell_history
  check_14_shai_hulud
  check_15_content_scan
  check_16_export_rules

  # Server mode extras
  [[ "$SERVER_MODE" == "true" ]] && run_server_checks

  # Generate report
  generate_report

  # Stage 3: Results
  if [[ "$JSON_ONLY" == "true" ]]; then
    cat "$REPORT_FILE"
  else
    show_results
    # Stage 4: Remediation
    show_remediation
  fi

  # Exit code: 0 = clean, 1 = infected
  [[ "$FAILED" -gt 0 ]] && exit 1
  exit 0
}

main "$@"
