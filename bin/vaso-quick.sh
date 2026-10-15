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

# Top-level config files, each flattened to one line so a nested key
# (`sandbox: { mode: "off" }`, JSON5 or YAML, over several lines) still matches
CONFIGS=()
for f in "$INSTALL_DIR"/*.json "$INSTALL_DIR"/*.json5 "$INSTALL_DIR"/*.yaml "$INSTALL_DIR"/*.yml; do
  [ -f "$f" ] && CONFIGS+=("$f")
done
config_matches() {
  local f
  for f in ${CONFIGS[@]+"${CONFIGS[@]}"}; do
    tr '\n\r\t' '   ' < "$f" 2>/dev/null | grep -qE "$1" && return 0
  done
  return 1
}
# A key, quoted or not (JSON, JSON5, YAML)
K() { printf '["\x27]?%s["\x27]?[[:space:]]*:[[:space:]]*' "$1"; }

# Check 1: Gateway binding (0.0.0.0)
echo -e "${BOLD}Checking gateway binding...${NC}"
# 2026.x: gateway.bind = "loopback" | "lan" | "all" | "auto"; older: an address
if config_matches "0\.0\.0\.0|$(K bind)[\"']?(lan|all|auto|::)[\"']?([[:space:],}]|$)"; then
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
if config_matches "$(K sandbox)(false|[\"'](disabled|off|none)[\"'])|$(K sandbox)(\{[^}]*)?$(K mode)[\"']?(off|disabled|none)"; then
  fail "Sandbox is disabled — skills run without isolation" 12
else
  pass "Sandbox is not explicitly disabled"
fi

# Check 5: Auth bypass
echo -e "${BOLD}Checking auth configuration...${NC}"
if config_matches "$(K bypass)true|$(K auth)(\{[^}]*)?$(K mode)[\"']?none"; then
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
