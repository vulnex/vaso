#!/usr/bin/env bash
# VASO Quick Scan — Zero-dependency critical security check
# Runs 5 critical checks without Node.js/npm
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

SCORE=100
FINDINGS=0

fail() { echo -e "  ${RED}[x]${NC} $1"; SCORE=$((SCORE - $2)); FINDINGS=$((FINDINGS + 1)); }
pass() { echo -e "  ${GREEN}[+]${NC} $1"; }
info() { echo -e "  ${CYAN}[i]${NC} $1"; }

echo -e "\n${BOLD}VASO Quick Scan${NC}"
echo -e "${CYAN}Zero-dependency critical security check${NC}\n"

# Detect OpenClaw installation, resolved as OpenClaw (and `vaso scan`) do:
# OPENCLAW_HOME replaces the home directory, OPENCLAW_STATE_DIR is the state
# directory (no fallback), OPENCLAW_CONFIG_PATH the config file — `~` in the
# last two is the effective home. Otherwise the first existing of
# ~/.openclaw/{openclaw,clawdbot}.json and ~/.clawdbot/{openclaw,clawdbot}.json.
trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  printf '%s' "${v%"${v##*[![:space:]]}"}"
}
expand_tilde() {
  case "$1" in
    "~") printf '%s' "$2" ;;
    "~/"*) printf '%s/%s' "$2" "${1#"~/"}" ;;
    *) printf '%s' "$1" ;;
  esac
}
first_config() {
  local n
  for n in openclaw.json clawdbot.json; do
    if [ -e "$1/$n" ]; then printf '%s' "$1/$n"; return 0; fi
  done
  return 1
}

EFFECTIVE_HOME="$HOME"
OC_HOME=$(trim "${OPENCLAW_HOME:-}")
[ -n "$OC_HOME" ] && EFFECTIVE_HOME=$(expand_tilde "$OC_HOME" "$HOME")
OC_STATE=$(trim "${OPENCLAW_STATE_DIR:-}")
OC_CONFIG=$(trim "${OPENCLAW_CONFIG_PATH:-}")
[ -n "$OC_CONFIG" ] && OC_CONFIG=$(expand_tilde "$OC_CONFIG" "$EFFECTIVE_HOME")

if [ -n "$OC_STATE" ]; then
  INSTALL_DIR=$(expand_tilde "$OC_STATE" "$EFFECTIVE_HOME")
  MAIN_CONFIG="$OC_CONFIG"
  [ -n "$MAIN_CONFIG" ] || MAIN_CONFIG=$(first_config "$INSTALL_DIR") || MAIN_CONFIG="$INSTALL_DIR/openclaw.json"
elif [ -n "$OC_CONFIG" ]; then
  INSTALL_DIR="$EFFECTIVE_HOME/.openclaw"
  if [ ! -e "$INSTALL_DIR" ] && [ -e "$EFFECTIVE_HOME/.clawdbot" ]; then INSTALL_DIR="$EFFECTIVE_HOME/.clawdbot"; fi
  MAIN_CONFIG="$OC_CONFIG"
elif MAIN_CONFIG=$(first_config "$EFFECTIVE_HOME/.openclaw" || first_config "$EFFECTIVE_HOME/.clawdbot"); then
  INSTALL_DIR="${MAIN_CONFIG%/*}"
else
  INSTALL_DIR="$EFFECTIVE_HOME/.openclaw"
  MAIN_CONFIG="$INSTALL_DIR/openclaw.json"
fi

if [ ! -e "$INSTALL_DIR" ] && [ ! -e "$MAIN_CONFIG" ]; then
  echo -e "${YELLOW}No OpenClaw installation found.${NC}"
  exit 0
fi

echo -e "Agent: ${BOLD}OpenClaw${NC} ($INSTALL_DIR)\n"

# OpenClaw reads one config file (JSON5) and the .env beside it — other files
# in the state dir configure nothing. The config is turned into
# `dotted.path=value` lines with comments dropped (`//` and `/* */`), so a
# check matches a setting where it really is — not a commented-out line, not
# an address in an unrelated list, and not past a nested `{ … }` before the
# key it wants. (`$include` files are left to `vaso scan`.)
CONFIGS=()
[ -f "$MAIN_CONFIG" ] && CONFIGS+=("$MAIN_CONFIG")
ENV_FILE="$INSTALL_DIR/.env"

# A config that exists but can't be read would pass every check unseen:
# stop instead of printing a clean grade (exit 2, as `vaso` does when it
# cannot run)
UNREADABLE=()
for f in "$MAIN_CONFIG" "$ENV_FILE"; do
  if [ -e "$f" ] && { [ ! -f "$f" ] || [ ! -r "$f" ]; }; then UNREADABLE+=("$f"); fi
done
if [ ${#UNREADABLE[@]} -gt 0 ]; then
  for f in "${UNREADABLE[@]}"; do
    echo -e "  ${RED}[!]${NC} Cannot read $f — not a readable file"
  done
  echo -e "\n${YELLOW}Scan incomplete: run as the file's owner (or fix its permissions), or use \`vaso scan\`.${NC}\n"
  exit 2
fi

# OpenClaw's own container test (isContainerEnvironment): bind "auto" — and
# an unset bind — listen on 0.0.0.0 inside a container, loopback elsewhere
in_container() {
  local f
  if [ -n "$(trim "${FLY_MACHINE_ID:-}")" ] && [ -n "$(trim "${FLY_APP_NAME:-}")" ]; then return 0; fi
  for f in /.dockerenv /run/.containerenv /var/run/.containerenv; do
    [ -e "$f" ] && return 0
  done
  if [ -r /proc/1/cgroup ] && grep -qE '/docker/|cri-containerd-[0-9a-f]|containerd/[0-9a-f]{64}|/kubepods[/.]|(^|[^[:alnum:]_])lxc([^[:alnum:]_]|$)' /proc/1/cgroup 2>/dev/null; then
    return 0
  fi
  return 1
}

# JSON / JSON5: a character-level walk keeping a stack of open objects and
# arrays (array elements get `[]` in the path). POSIX awk, no gawk extensions.
FLATTEN_JSON='
function flush() { if (bare != "") { last = bare; have = 1; bare = "" } }
function path(   p, j) { p = ""; for (j = 1; j <= n; j++) if (st[j] != "") p = (p == "" ? st[j] : p "." st[j]); return p }
function emit(k,   p) { p = path(); if (k != "") p = (p == "" ? k : p "." k); print p "=" last }
function value() { flush(); if (have) { emit(pending); have = 0; pending = "" } }
{ s = s $0 "\n" }
END {
  n = 0; instr = ""; blk = 0; bare = ""; have = 0; pending = ""; q = "\047"
  L = length(s)
  for (i = 1; i <= L; i++) {
    c = substr(s, i, 1)
    if (blk) { if (c == "*" && substr(s, i + 1, 1) == "/") { blk = 0; i++ } continue }
    if (instr != "") {
      if (c == "\\") { buf = buf substr(s, i + 1, 1); i++ }
      else if (c == instr) { instr = ""; last = buf; have = 1 }
      else buf = buf c
      continue
    }
    if (c == "/" && substr(s, i + 1, 1) == "/") { flush(); while (i <= L && substr(s, i, 1) != "\n") i++; continue }
    if (c == "/" && substr(s, i + 1, 1) == "*") { flush(); blk = 1; i++; continue }
    if (c == "\"" || c == q) { flush(); instr = c; buf = ""; continue }
    if (c == ":") { flush(); if (have) { pending = last; have = 0 } continue }
    if (c == "{" || c == "[") {
      flush(); have = 0
      name = pending; if (name == "" && n > 0 && arr[n]) name = "[]"
      n++; st[n] = name; arr[n] = (c == "["); pending = ""
      continue
    }
    if (c == "}" || c == "]") { value(); if (n > 0) n--; pending = ""; continue }
    if (c == ",") { value(); continue }
    if (c == " " || c == "\t" || c == "\n" || c == "\r") { flush(); continue }
    bare = bare c
  }
}'

flatten() { awk "$FLATTEN_JSON" "$1"; }

# Whether any config has a `path=value` line matching an extended regex
config_matches() {
  local f lines
  for f in ${CONFIGS[@]+"${CONFIGS[@]}"}; do
    # captured first: with pipefail, `grep -q` closing a pipe early could
    # fail the pipeline on SIGPIPE and hide a match
    lines=$(flatten "$f" 2>/dev/null) || true
    grep -qE "$1" <<<"$lines" && return 0
  done
  return 1
}

# The last value a config sets for a dotted path (JSON5: a repeated key
# wins); fails when the path isn't set
config_value() {
  local f lines v found=1
  for f in ${CONFIGS[@]+"${CONFIGS[@]}"}; do
    lines=$(flatten "$f" 2>/dev/null) || true
    v=$(awk -v k="$1" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2); f = 1 } END { if (f) print v; exit !f }' <<<"$lines") && { printf '%s' "$v"; found=0; }
  done
  return $found
}
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
# Whether a config sets anything under a dotted prefix (a gateway section)
config_has() {
  local f lines
  for f in ${CONFIGS[@]+"${CONFIGS[@]}"}; do
    lines=$(flatten "$f" 2>/dev/null) || true
    awk -v k="$1" 'index($0, k ".") == 1 { f = 1 } END { exit !f }' <<<"$lines" && return 0
  done
  return 1
}

# Check 1: Gateway binding (0.0.0.0)
echo -e "${BOLD}Checking gateway binding...${NC}"
# 2026.x: gateway.bind = "loopback" | "lan" | "tailnet" | "custom" | "auto"
# (unset: "auto" inside a container, else loopback); older: gateway.host
GW_MODE=$(config_value gateway.mode) || true
GW_HOST=$(config_value gateway.host) || true
GW_TS=$(config_value gateway.tailscale.mode) || true
BIND_SET=0
GW_BIND=$(config_value gateway.bind) && BIND_SET=1
GW_BIND=$(lower "$(trim "$GW_BIND")")
EXPOSED=""
if [ "$GW_MODE" = "remote" ]; then
  : # a client of a gateway on another host: no listener here
elif grep -qE '^(0\.0\.0\.0|::|\[::\]|\*)(:[0-9]+)?$' <<<"$(trim "$GW_HOST")"; then
  EXPOSED="gateway.host $GW_HOST"
elif [ "$GW_TS" = "serve" ] || [ "$GW_TS" = "funnel" ]; then
  : # Tailscale serve/funnel keeps the gateway itself on loopback
elif [ "$BIND_SET" -eq 1 ]; then
  case "$GW_BIND" in
    lan|all|0.0.0.0|::|"[::]") EXPOSED="bind $GW_BIND" ;;
    auto)
      if in_container; then EXPOSED="bind auto, in a container"
      else info "Gateway bind \"auto\" listens on loopback here (0.0.0.0 inside a container)"; fi ;;
  esac
elif config_has gateway && { [ -z "$GW_TS" ] || [ "$GW_TS" = "off" ]; } && in_container; then
  EXPOSED="bind unset = auto, in a container"
fi
if [ -n "$EXPOSED" ]; then
  fail "Gateway bound to all interfaces (0.0.0.0 — $EXPOSED)" 12
else
  pass "Gateway not bound to 0.0.0.0"
fi

# Check 2: API key exposure
echo -e "${BOLD}Checking for exposed API keys...${NC}"
# In the files OpenClaw reads; documentation placeholders (sk-your-key-here,
# AKIA…EXAMPLE, xxxx masks) are not keys
KEY_FILES=()
for f in ${CONFIGS[@]+"${CONFIGS[@]}"} "$ENV_FILE"; do
  [ -f "$f" ] && KEY_FILES+=("$f")
done
KEYS=""
if [ ${#KEY_FILES[@]} -gt 0 ]; then
  KEYS=$(grep -ohE '(sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})' "${KEY_FILES[@]}" 2>/dev/null) || true
fi
KEYS=$(grep -vE 'x{4,}|X{4,}|\*{3,}|EXAMPLE(KEY)?$' <<<"$KEYS" | grep -viE '(^|[-_.<{:/])(your|example|sample|dummy|placeholder|changeme|change[-_]me|replace|insert|redacted|fake)($|[-_.>}])') || true
if [ -n "$KEYS" ]; then
  fail "API keys found in config files" 12
else
  pass "No exposed API keys found"
fi

# Check 3: File permissions
echo -e "${BOLD}Checking file permissions...${NC}"
PERM_ISSUES=0
for f in ${CONFIGS[@]+"${CONFIGS[@]}"} "$ENV_FILE"; do
  [ -f "$f" ] || continue
  # GNU stat first: on Linux `stat -f` is filesystem status and "succeeds".
  # -L judges a symlinked config by the file it points to.
  PERMS=$(stat -L -c '%a' "$f" 2>/dev/null || stat -L -f '%Lp' "$f" 2>/dev/null) || PERMS=""
  # Owner-only (no group/other bits: 600, 400, 700, 500…) is restrictive
  if ! [[ "$PERMS" =~ ^[0-7]+$ ]] || [ $(( 8#$PERMS & 8#077 )) -ne 0 ]; then
    PERM_ISSUES=$((PERM_ISSUES + 1))
  fi
done
if [ "$PERM_ISSUES" -gt 0 ]; then
  fail "$PERM_ISSUES config file(s) have overly permissive permissions" 5
else
  pass "All config files have restrictive permissions"
fi

# Check 4: Sandbox disabled
echo -e "${BOLD}Checking sandbox status...${NC}"
# `sandbox: false|"off"`, or 2026.x `agents.defaults.sandbox.mode: "off"`
if config_matches '(^|\.)sandbox=(false|disabled|off|none)$|(^|\.)sandbox\.mode=(off|disabled|none)$'; then
  fail "Sandbox is disabled — skills run without isolation" 12
else
  pass "Sandbox is not explicitly disabled"
fi

# Check 5: Auth bypass
echo -e "${BOLD}Checking auth configuration...${NC}"
if config_matches '(^|\.)bypass=true$|(^|\.)auth\.mode=none$'; then
  fail "Authentication bypass is enabled" 12
else
  pass "Auth bypass is not enabled"
fi

# Results
echo ""
GRADE="F"
[ "$SCORE" -ge 60 ] && GRADE="D"
[ "$SCORE" -ge 70 ] && GRADE="C"
[ "$SCORE" -ge 80 ] && GRADE="B"
[ "$SCORE" -ge 90 ] && GRADE="A"

if [ "$FINDINGS" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}Score: $SCORE/100 ($GRADE) — All checks passed${NC}"
else
  COLOR=$RED
  [ "$SCORE" -ge 70 ] && COLOR=$YELLOW
  [ "$SCORE" -ge 90 ] && COLOR=$GREEN
  echo -e "${COLOR}${BOLD}Score: $SCORE/100 ($GRADE) — $FINDINGS finding(s)${NC}"
fi
echo ""

# Non-zero on findings, like `vaso scan` (every check here is critical-class)
[ "$FINDINGS" -eq 0 ] || exit 1
