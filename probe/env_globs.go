package main

import (
	"os"
	"path/filepath"
	"strings"
)

// envGlobRefused: p, the expansion of raw, a manifest glob rooted at an
// environment variable (`${OPENCLAW_STATE_DIR}/**/*.json5`), would walk a
// place no tree is walked from — the filesystem root, the home or a
// directory above it, an OS directory, another user's home, a credential
// store (treeAllowed). OPENCLAW_STATE_DIR=/ walked the whole filesystem, and
// =$HOME shipped every *.json5 in the home. A glob reaching only one level
// below such a place (`${CODEX_HOME}/*.config.toml`) names its files and is
// kept, unless the place is the root.
func envGlobRefused(raw, p string) bool {
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
	return err != nil || !treeAllowed(base, home)
}
