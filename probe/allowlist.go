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
}

// IsAllowed returns true if the command base name is in the allowlist.
func IsAllowed(cmd string) bool {
	return commandAllowlist[filepath.Base(cmd)]
}
