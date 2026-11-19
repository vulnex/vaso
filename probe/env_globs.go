package main

import (
	"os"
	"path/filepath"
	"strings"
)

// envGlobRefused: p, the expansion of raw, a manifest glob rooted at an
// environment variable (`${OPENCLAW_STATE_DIR}/**/*.json5`), would walk a
// place no tree is walked from — the filesystem root, the home or a
// directory above it, another user's home, a credential store.
// OPENCLAW_STATE_DIR=/ walked the whole filesystem, and =$HOME shipped every
// *.json5 in the home. An OS directory is not refused here: the agent's own
// variable names that tree (a systemd StateDirectory, /var/lib/openclaw),
// as local scans read it. A glob reaching only one level below such a place
// (`${CODEX_HOME}/*.config.toml`) names its files and is kept, unless the
// place is the root. homes are the scanned homes (an --all-users probe's
// too); envTreeRefusal in src/core/skill-root-scope.ts is the local twin.
func envGlobRefused(raw, p string, homes []string) bool {
	if !envPathPrefix.MatchString(raw) || !hasGlobMeta(p) {
		return false
	}
	base := filepath.Clean(globBase(p))
	if base == string(filepath.Separator) {
		return true
	}
	if !strings.Contains(p, "**") {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) || filepath.Clean(home) == string(filepath.Separator) {
		return true
	}
	own, all := scopeHomes(home, homes)
	for l := range pathScope(base, own, all) {
		if !strings.HasPrefix(l, "system:") {
			return true
		}
	}
	return false
}
