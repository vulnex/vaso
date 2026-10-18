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

# Detect OpenClaw installation
# OpenClaw's relocation variables: OPENCLAW_STATE_DIR is the state directory
# itself, OPENCLAW_HOME replaces the home directory
DIRS=()
[ -n "${OPENCLAW_STATE_DIR:-}" ] && DIRS+=("$OPENCLAW_STATE_DIR")
DIRS+=("${OPENCLAW_HOME:-$HOME}/.openclaw" "$HOME/.clawdbot" "$HOME/.moltbot" "/etc/openclaw")
INSTALL_DIR=""
for d in "${DIRS[@]}"; do
  if [ -d "$d" ]; then INSTALL_DIR="$d"; break; fi
done

if [ -z "$INSTALL_DIR" ]; then
  echo -e "${YELLOW}No OpenClaw installation found.${NC}"
  exit 0
fi

echo -e "Agent: ${BOLD}OpenClaw${NC} ($INSTALL_DIR)\n"

# Top-level config files, each turned into `dotted.path=value` lines with
# comments dropped (JSON5 `//` and `/* */`, YAML `#`), so a check matches a
# setting where it really is — not a commented-out line, not an address in an
# unrelated list, and not past a nested `{ … }` before the key it wants
CONFIGS=()
for f in "$INSTALL_DIR"/*.json "$INSTALL_DIR"/*.json5 "$INSTALL_DIR"/*.yaml "$INSTALL_DIR"/*.yml; do
  [ -f "$f" ] && CONFIGS+=("$f")
done

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

# YAML: block mappings by indentation; `- ` list items are entered as their
# keys. Flow-style values are kept as written.
FLATTEN_YAML='
function unq(v,   a) { a = substr(v, 1, 1); if (length(v) > 1 && (a == "\"" || a == q) && substr(v, length(v), 1) == a) return substr(v, 2, length(v) - 2); return v }
BEGIN { q = "\047"; keyre = "^(\"[^\"]*\"|" q "[^" q "]*" q "|[^:\"" q "]+)[ \t]*:([ \t]|$)" }
{
  line = $0; out = ""; instr = ""
  for (i = 1; i <= length(line); i++) {
    c = substr(line, i, 1)
    if (instr != "") { if (c == instr) instr = ""; out = out c; continue }
    if (c == "\"" || c == q) { instr = c; out = out c; continue }
    if (c == "#" && (i == 1 || substr(line, i - 1, 1) ~ /[ \t]/)) break
    out = out c
  }
  sub(/[ \t\r]+$/, "", out)
  if (out ~ /^[ \t]*$/ || out ~ /^---/) next
  match(out, /^[ \t]*/); ind = RLENGTH; body = substr(out, ind + 1)
  while (body ~ /^- /) { body = substr(body, 3); ind += 2; sub(/^[ \t]*/, "", body) }
  if (!match(body, keyre)) next
  key = substr(body, 1, RLENGTH); sub(/[ \t]*:[ \t]*$/, "", key); key = unq(key)
  val = substr(body, RLENGTH + 1); sub(/^[ \t]+/, "", val)
  while (n > 0 && ind <= sind[n]) n--
  if (val == "") { n++; st[n] = key; sind[n] = ind; next }
  p = ""; for (j = 1; j <= n; j++) p = (p == "" ? st[j] : p "." st[j])
  print (p == "" ? key : p "." key) "=" unq(val)
}'

flatten() {
  case "$1" in
    *.yaml|*.yml) awk "$FLATTEN_YAML" "$1" ;;
    *) awk "$FLATTEN_JSON" "$1" ;;
  esac
}

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

# Check 1: Gateway binding (0.0.0.0)
echo -e "${BOLD}Checking gateway binding...${NC}"
# 2026.x: gateway.bind = "loopback" | "lan" | "all" | "auto"; older: an address
if config_matches '^gateway\.(bind|host)=(0\.0\.0\.0|lan|all|auto|::|\[::\])(:[0-9]+)?$'; then
  fail "Gateway bound to all interfaces (0.0.0.0 / bind lan|all|auto)" 12
else
  pass "Gateway not bound to 0.0.0.0"
fi

# Check 2: API key exposure
echo -e "${BOLD}Checking for exposed API keys...${NC}"
if grep -rqE --exclude-dir=node_modules --exclude-dir=.git '(sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})' "$INSTALL_DIR" 2>/dev/null; then
  fail "API keys found in config files" 12
else
  pass "No exposed API keys found"
fi

# Check 3: File permissions
echo -e "${BOLD}Checking file permissions...${NC}"
PERM_ISSUES=0
for f in ${CONFIGS[@]+"${CONFIGS[@]}"} "$INSTALL_DIR"/.env; do
  [ -f "$f" ] || continue
  # GNU stat first: on Linux `stat -f` is filesystem status and "succeeds"
  PERMS=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)
  if [ "${PERMS:-644}" != "600" ] && [ "${PERMS:-644}" != "400" ]; then
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
