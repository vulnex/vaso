package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An agent's own skills directory (a manifest glob's static base) linked out
// of the home or into a credential store is refused like a config-derived
// tree, with the links that lead there recorded; linked inside the home it
// is walked as before.
func TestLinkedDefaultSkillBasesAreRefusedOutsideTheHome(t *testing.T) {
	home := setupHome(t)
	outside := filepath.Join(filepath.Dir(home), "elsewhere")
	write(t, filepath.Join(outside, "skills", "o", "SKILL.md"), "OUTSIDE-CANARY\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "id_canary"), "SSH-CANARY\n", 0o600)
	write(t, filepath.Join(home, "dotfiles", "codex", "skills", "c", "SKILL.md"), "# c\n", 0o644)
	mustSymlink(t, outside, filepath.Join(home, ".picoclaw", "workspace"))
	mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(home, ".claude", "skills"))
	mustSymlink(t, filepath.Join(home, "dotfiles", "codex"), filepath.Join(home, ".codex"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{
		"~/.picoclaw/workspace/skills/**", "~/.claude/skills/**", "~/.codex/skills/**", "~/.qwen/skills/**",
	}}, false)
	for _, p := range []string{filepath.Join(home, ".picoclaw", "workspace", "skills"), filepath.Join(home, ".claude", "skills")} {
		if snap.ConfigTrees[p] != treeRefused {
			t.Errorf("%s: %q, want refused", p, snap.ConfigTrees[p])
		}
	}
	if snap.Symlinks[filepath.Join(home, ".picoclaw", "workspace")] != outside {
		t.Errorf("the link out of the home is not recorded: %v", snap.Symlinks)
	}
	if snap.Symlinks[filepath.Join(home, ".claude", "skills")] != filepath.Join(home, ".ssh") {
		t.Errorf("the link into ~/.ssh is not recorded: %v", snap.Symlinks)
	}
	if _, ok := snap.ConfigTrees[filepath.Join(home, ".codex", "skills")]; ok {
		t.Errorf("a link inside the home is refused")
	}
	if e := snap.Files[filepath.Join(home, ".codex", "skills", "c", "SKILL.md")]; e.Content == "" {
		t.Errorf("skill behind an in-home link not collected")
	}
	// a default tree that is no link stays the probe's own: nothing recorded
	if _, ok := snap.ConfigTrees[filepath.Join(home, ".qwen", "skills")]; ok {
		t.Errorf("an absent default tree is recorded")
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("content behind a refused link shipped: %s", p)
		}
	}
}

// Either spelling of a linked home (/home → /var/home) is the home: a config
// tree written with the other one is walked.
func TestTreeAllowedTakesEitherSpellingOfALinkedHome(t *testing.T) {
	home := setupHome(t)
	linkHome := filepath.Join(filepath.Dir(home), "link-home")
	mustSymlink(t, home, linkHome)
	if err := os.MkdirAll(filepath.Join(home, "ws", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p, home string
		want    bool
	}{
		{filepath.Join(home, "ws", "skills"), linkHome, true},
		{filepath.Join(linkHome, "ws", "skills"), home, true},
		{filepath.Join(linkHome, ".ssh"), home, false},
		{linkHome, home, false},
		{filepath.Dir(home), linkHome, false},
	} {
		if got := treeAllowed(c.p, c.home); got != c.want {
			t.Errorf("treeAllowed(%s, %s) = %v, want %v", c.p, c.home, got, c.want)
		}
	}
}

// A refused config tree that is a link to the home itself records the link,
// so the CLI names the home as the reason, as a local scan does.
func TestRefusedConfigTreeRecordsItsLink(t *testing.T) {
	home := setupHome(t)
	mustSymlink(t, home, filepath.Join(home, "linkhome"))
	writeExtraDirs(t, home, "~/linkhome")
	snap := Collect(extraDirsManifest(), false)
	base := filepath.Join(home, "linkhome")
	if snap.ConfigTrees[base] != treeRefused {
		t.Fatalf("%s: %q, want refused", base, snap.ConfigTrees[base])
	}
	if snap.Symlinks[base] != home {
		t.Errorf("link of the refused tree not recorded: %v", snap.Symlinks)
	}
}
