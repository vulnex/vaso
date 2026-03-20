package main

import "path/filepath"

var commandAllowlist = map[string]bool{
	"netstat":  true,
	"ss":       true,
	"ps":       true,
	"docker":   true,
	"launchctl": true,
	"which":    true,
	"openclaw": true,
	"nanoclaw": true,
	"picoclaw": true,
	"ironclaw": true,
	"nanobot":  true,
	"zeroclaw": true,
	"nemoclaw": true,
	"cat":      true,
	"uname":    true,
	"hostname": true,
	"ls":       true,
	"stat":     true,
	"id":       true,
	"crontab":  true,
}

// IsAllowed returns true if the command base name is in the allowlist.
func IsAllowed(cmd string) bool {
	return commandAllowlist[filepath.Base(cmd)]
}
