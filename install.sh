#!/usr/bin/env bash
# VASO Installer — Linux, macOS, WSL
# Usage: curl -fsSL https://raw.githubusercontent.com/vulnex/vaso/main/install.sh | bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

MIN_NODE_MAJOR=20
REPO="vulnex/vaso"
FALLBACK_REF="main"

info()  { echo -e "${CYAN}>${NC} $1"; }
ok()    { echo -e "${GREEN}>${NC} $1"; }
warn()  { echo -e "${YELLOW}>${NC} $1"; }
fail()  { echo -e "${RED}>${NC} $1"; exit 1; }

banner() {
  echo -e "${BOLD}"
  cat <<'EOF'
██╗   ██╗ █████╗ ███████╗ ██████╗
██║   ██║██╔══██╗██╔════╝██╔═══██╗
██║   ██║███████║███████╗ ██║   ██║
╚██╗ ██╔╝██╔══██║╚════██║██║   ██║
 ╚████╔╝ ██║  ██║███████║╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝
EOF
  echo -e "${NC}  ${CYAN}VULNEX Agent Security Observer — Installer${NC}"
  echo ""
}

detect_platform() {
  local uname_s
  uname_s=$(uname -s)
  case "$uname_s" in
    Linux*)
      if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
        PLATFORM="wsl"
      else
        PLATFORM="linux"
      fi
      ;;
    Darwin*)
      PLATFORM="macos"
      ;;
    *)
      fail "Unsupported platform: $uname_s (VASO supports Linux, macOS, and WSL)"
      ;;
  esac
  ok "Platform: $PLATFORM ($(uname -m))"
}

check_node() {
  if ! command -v node &>/dev/null; then
    return 1
  fi

  local version
  version=$(node --version 2>/dev/null | sed 's/^v//')
  local major
  major=$(echo "$version" | cut -d. -f1)

  if [ "$major" -lt "$MIN_NODE_MAJOR" ] 2>/dev/null; then
    warn "Node.js $version found but VASO requires v${MIN_NODE_MAJOR}+"
    return 1
  fi

  ok "Node.js v${version} found"
  return 0
}

check_npm() {
  if ! command -v npm &>/dev/null; then
    fail "npm not found. Install Node.js ${MIN_NODE_MAJOR}+ which includes npm."
  fi
  local version
  version=$(npm --version 2>/dev/null)
  ok "npm v${version} found"
}

install_node_prompt() {
  echo ""
  warn "Node.js ${MIN_NODE_MAJOR}+ is required but not found."
  echo ""
  info "Install Node.js using one of these methods:"
  echo ""
  echo "  nvm (recommended):"
  echo "    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash"
  echo "    nvm install --lts"
  echo ""

  case "$PLATFORM" in
    macos)
      echo "  Homebrew:"
      echo "    brew install node"
      echo ""
      ;;
    linux|wsl)
      echo "  Package manager (Debian/Ubuntu):"
      echo "    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -"
      echo "    sudo apt-get install -y nodejs"
      echo ""
      echo "  Package manager (Fedora/RHEL):"
      echo "    sudo dnf install nodejs"
      echo ""
      ;;
  esac

  echo "  Direct download:"
  echo "    https://nodejs.org/en/download/"
  echo ""
  fail "Install Node.js ${MIN_NODE_MAJOR}+ and re-run this script."
}

resolve_version() {
  if [ -n "${VASO_VERSION:-}" ]; then
    VERSION="$VASO_VERSION"
    info "Using VASO_VERSION=${VERSION}"
    return
  fi

  local tag
  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name"[^"]*"([^"]+)".*/\1/' || true)

  if [ -n "$tag" ]; then
    VERSION="$tag"
    ok "Latest VASO release: ${VERSION}"
    return
  fi

  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/tags" 2>/dev/null \
    | grep -m1 '"name"' \
    | sed -E 's/.*"name"[^"]*"([^"]+)".*/\1/' || true)

  if [ -n "$tag" ]; then
    VERSION="$tag"
    warn "No published Release found; using latest tag ${VERSION}"
    return
  fi

  VERSION="$FALLBACK_REF"
  warn "No releases or tags found; falling back to ${VERSION} (untagged build)"
}

install_vaso() {
  local ver_no_v="${VERSION#v}"
  local tarball_url="https://github.com/${REPO}/releases/download/${VERSION}/vaso-${ver_no_v}.tgz"
  local git_spec="github:${REPO}#${VERSION}"

  # Detect if we need sudo for global npm install
  local npm_prefix
  npm_prefix=$(npm config get prefix 2>/dev/null)
  local NPM=(npm)
  if [ -n "$npm_prefix" ] && [ ! -w "$npm_prefix/lib" ] 2>/dev/null; then
    warn "Global npm directory requires elevated permissions (using sudo)."
    NPM=(sudo npm)
  fi

  # Prefer the self-contained release tarball. `npm install -g github:...#<tag>`
  # is broken on npm 11+ for VASO: the global git-dependency install path
  # mishandles the package (ignores files[], leaves an unusable install), and
  # a source build at install time needs a toolchain the checkout lacks. The
  # prebuilt tarball asset installs cleanly with no build step. Fall back to the
  # git ref only when there's no release tarball (e.g. the `main` fallback).
  if [ "$VERSION" != "$FALLBACK_REF" ]; then
    info "Installing VASO from release tarball: ${tarball_url}"
    echo ""
    if "${NPM[@]}" install -g "$tarball_url"; then
      return
    fi
    warn "Tarball install failed; falling back to git install (${git_spec})."
  fi

  info "Installing VASO from ${git_spec}..."
  echo ""
  "${NPM[@]}" install -g "$git_spec"
}

verify_install() {
  echo ""
  if ! command -v vaso &>/dev/null; then
    # npm bin might not be in PATH
    local npm_bin
    npm_bin=$(npm config get prefix 2>/dev/null)/bin
    if [ -x "$npm_bin/vaso" ]; then
      warn "vaso installed to ${npm_bin}/vaso but it's not in your PATH."
      echo ""
      info "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
      echo "    export PATH=\"${npm_bin}:\$PATH\""
      echo ""
      info "Then reload your shell or run:"
      echo "    source ~/.bashrc  # or ~/.zshrc"
      return
    fi
    fail "Installation failed — 'vaso' command not found."
  fi

  local installed_version
  installed_version=$(vaso --version 2>/dev/null || echo "unknown")
  echo ""
  ok "VASO v${installed_version} installed successfully"
  echo ""
  info "Get started:"
  echo "    vaso scan         # Scan all detected AI agents"
  echo "    vaso detect       # List installed agents"
  echo "    vaso mcp scan     # Scan MCP server configs"
  echo "    vaso --help       # Full command reference"
  echo ""
}

# ── Main ──

banner
detect_platform

if ! check_node; then
  install_node_prompt
fi

check_npm
resolve_version
install_vaso
verify_install
