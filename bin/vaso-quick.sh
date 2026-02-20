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
DIRS=("$HOME/.openclaw" "$HOME/.clawdbot" "$HOME/.moltbot" "/etc/openclaw")
INSTALL_DIR=""
for d in "${DIRS[@]}"; do
  if [ -d "$d" ]; then INSTALL_DIR="$d"; break; fi
done

if [ -z "$INSTALL_DIR" ]; then
  echo -e "${YELLOW}No OpenClaw installation found.${NC}"
  exit 0
fi

echo -e "Agent: ${BOLD}OpenClaw${NC} ($INSTALL_DIR)\n"

# Check 1: Gateway binding (0.0.0.0)
echo -e "${BOLD}Checking gateway binding...${NC}"
if grep -rq '0\.0\.0\.0' "$INSTALL_DIR"/*.json "$INSTALL_DIR"/*.yaml 2>/dev/null; then
  fail "Gateway bound to 0.0.0.0 — exposed to all interfaces" 12
else
  pass "Gateway not bound to 0.0.0.0"
fi

# Check 2: API key exposure
echo -e "${BOLD}Checking for exposed API keys...${NC}"
if grep -rqE '(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})' "$INSTALL_DIR" 2>/dev/null; then
  fail "API keys found in config files" 12
else
  pass "No exposed API keys found"
fi

# Check 3: File permissions
echo -e "${BOLD}Checking file permissions...${NC}"
PERM_ISSUES=0
for f in "$INSTALL_DIR"/*.json "$INSTALL_DIR"/*.yaml "$INSTALL_DIR"/.env 2>/dev/null; do
  [ -f "$f" ] || continue
  PERMS=$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null)
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
if grep -rqE '"sandbox"\s*:\s*(false|"disabled"|"off")' "$INSTALL_DIR" 2>/dev/null; then
  fail "Sandbox is disabled — skills run without isolation" 12
else
  pass "Sandbox is not explicitly disabled"
fi

# Check 5: Auth bypass
echo -e "${BOLD}Checking auth configuration...${NC}"
if grep -rqE '"bypass"\s*:\s*true|"mode"\s*:\s*"none"' "$INSTALL_DIR" 2>/dev/null; then
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
