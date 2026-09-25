package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInExcludedDirOnlyBelowPatternBase(t *testing.T) {
	cases := []struct {
		pattern, match string
		want           bool
	}{
		{"/home/u/.claude/skills/**", "/home/u/.claude/skills/x/node_modules/a/index.js", true},
		{"/home/u/.claude/skills/**", "/home/u/.claude/skills/x/.git/config", true},
		{"/home/u/.claude/skills/**", "/home/u/.claude/skills/x/src/index.js", false},
		// A user or path segment named "build" above the glob base doesn't count
		{"/home/build/.claude/skills/**", "/home/build/.claude/skills/x/SKILL.md", false},
		// A pattern that names node_modules on purpose (npm package version globs)
		{"/home/u/.nvm/versions/node/*/lib/node_modules/@google/gemini-cli/package.json",
			"/home/u/.nvm/versions/node/v22/lib/node_modules/@google/gemini-cli/package.json", false},
	}
	for _, c := range cases {
		if got := inExcludedDir(c.pattern, c.match); got != c.want {
			t.Errorf("inExcludedDir(%q, %q) = %v, want %v", c.pattern, c.match, got, c.want)
		}
	}
}

func TestCollectFileMetadataOnlyAndBudget(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	code := write("a.js", "console.log(1)")
	img := write("logo.png", "PNGDATA")
	big := write("b.js", "0123456789")

	c := &collector{budget: 20}
	if e := c.collectFile(code, false); e.Content != "console.log(1)" || e.ContentOmitted {
		t.Fatalf("code file content not collected: %+v", e)
	}
	if e := c.collectFile(img, false); e.Content != "" || !e.ContentOmitted || e.Mode != 0o600 {
		t.Fatalf("binary asset should be metadata-only: %+v", e)
	}
	if e := c.collectFile(code, true); !e.ContentOmitted || e.Content != "" {
		t.Fatalf("metadata-only request returned content: %+v", e)
	}
	// 14 bytes spent of 20; a 10-byte file no longer fits
	if e := c.collectFile(big, false); !e.ContentOmitted || !c.truncated {
		t.Fatalf("budget not enforced: %+v truncated=%v", e, c.truncated)
	}
}
