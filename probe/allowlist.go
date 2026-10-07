package main

import (
	"path/filepath"
	"strings"
)

var commandAllowlist = map[string]bool{
	"netstat":      true,
	"ss":           true,
	"ps":           true,
	"docker":       true,
	"launchctl":    true,
	"which":        true,
	"openclaw":     true,
	"nanoclaw":     true,
	"picoclaw":     true,
	"ironclaw":     true,
	"nanobot":      true,
	"zeroclaw":     true,
	"nemoclaw":     true,
	"hermes":       true,
	"lyrie":        true,
	"lyrie-shield": true,
	"claude":       true,
	"codex":        true,
	"opencode":     true,
	"gemini":       true,
	"qwen":         true,
	"copilot":      true,
	"cursor-agent": true,
	// v1.0.0 agents — version/which probes (Devin CLI, Windsurf / Devin Desktop)
	"devin":         true,
	"windsurf":      true,
	"devin-desktop": true,
	// Atomic Agent — version/which probe
	"atomic-agent": true,
	// Abacus.AI CLI (alias abacus) — version/which probe
	"abacusai": true,
	"abacus":   true,
	// NVIDIA OpenShell — version/which probe and read-only gateway queries
	// (sandbox list, per-sandbox and global policy get)
	"openshell": true,
	"cat":       true,
	"uname":     true,
	"hostname":  true,
	"ls":        true,
	"stat":      true,
	"id":        true,
	"crontab":   true,
	"pip":       true,
	"pip3":      true,
	"python":    true,
	"python3":   true,
	// macOS info-only inspection commands. Used by claude-desktop and
	// chatgpt-desktop adapters to read app metadata: defaults reads the
	// CFBundleShortVersionString from app Info.plists and converts user
	// preference plists to text; codesign verifies the bundle signature.
	// plutil converts binary plists to XML so the JS plist parser can
	// consume them through the snapshot transport (which is utf-8 / JSON
	// lossy for raw binary file content).
	"defaults": true,
	"codesign": true,
	"plutil":   true,
}

// IsAllowed returns true if the command base name is in the allowlist.
func IsAllowed(cmd string) bool {
	return commandAllowlist[filepath.Base(cmd)]
}

// installOnRunTargets maps an allowlisted command to the package directory of
// a wrapper that installs software when run. The Abacus.AI npm shim
// (@abacus-ai/cli) downloads a ~130 MB native binary into $HOME whenever its
// cache is missing — always the case under the isolated HOME used for version
// queries — so it is never executed; its version comes from package.json.
var installOnRunTargets = map[string]string{
	"abacusai": "node_modules/@abacus-ai/cli/",
	"abacus":   "node_modules/@abacus-ai/cli/",
}

// InstallsOnRun reports whether running the resolved binary for cmd would
// install software instead of just answering.
func InstallsOnRun(cmd, resolved string) bool {
	marker, ok := installOnRunTargets[filepath.Base(cmd)]
	if !ok {
		return false
	}
	real, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		real = resolved
	}
	return strings.Contains(filepath.ToSlash(real), marker)
}
