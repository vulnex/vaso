package main

import "path/filepath"

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
	"cat":          true,
	"uname":        true,
	"hostname":     true,
	"ls":           true,
	"stat":         true,
	"id":           true,
	"crontab":      true,
	"pip":          true,
	"pip3":         true,
	"python":       true,
	"python3":      true,
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
