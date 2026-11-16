package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An agent's own skills directory (a manifest glob's static base) linked out
// of the home is walked as a config-derived tree (disguised, capped) where a
// skills tree may be walked — another volume, a home-manager store — and
// refused, with the links that lead there recorded, in an OS directory or a
// credential store; linked inside the home it is walked as before.
func TestLinkedDefaultSkillBasesOutsideTheHome(t *testing.T) {
	home := setupHome(t)
	outside := allowedOutside(t)
	write(t, filepath.Join(outside, "skills", "o", "SKILL.md"), "# outside skill\n", 0o644)
	write(t, filepath.Join(outside, "vol", "claude", "skills", "v", "SKILL.md"), "# volume skill\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "id_canary"), "SSH-CANARY\n", 0o600)
	write(t, filepath.Join(home, "dotfiles", "codex", "skills", "c", "SKILL.md"), "# c\n", 0o644)
	mustSymlink(t, outside, filepath.Join(home, ".picoclaw", "workspace"))
	mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(home, ".claude", "skills"))
	mustSymlink(t, filepath.Join(home, "dotfiles", "codex"), filepath.Join(home, ".codex"))
	mustSymlink(t, filepath.Join(outside, "vol", "claude"), filepath.Join(home, ".cfgvol"))
	mustSymlink(t, "/etc", filepath.Join(home, ".gemini", "skills"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{
		"~/.picoclaw/workspace/skills/**", "~/.claude/skills/**", "~/.codex/skills/**", "~/.qwen/skills/**",
		"~/.cfgvol/skills/**", "~/.gemini/skills/**",
	}}, false)
	for _, p := range []string{filepath.Join(home, ".picoclaw", "workspace", "skills"), filepath.Join(home, ".cfgvol", "skills")} {
		if snap.ConfigTrees[p] != treeCollected {
			t.Errorf("%s: %q, want collected", p, snap.ConfigTrees[p])
		}
	}
	if e := snap.Files[filepath.Join(home, ".picoclaw", "workspace", "skills", "o", "SKILL.md")]; e.Content == "" {
		t.Errorf("skill behind a link out of the home not collected")
	}
	if e := snap.Files[filepath.Join(home, ".cfgvol", "skills", "v", "SKILL.md")]; e.Content == "" {
		t.Errorf("skill behind a linked parent directory not collected")
	}
	for _, p := range []string{filepath.Join(home, ".claude", "skills"), filepath.Join(home, ".gemini", "skills")} {
		if snap.ConfigTrees[p] != treeRefused {
			t.Errorf("%s: %q, want refused", p, snap.ConfigTrees[p])
		}
	}
	if snap.Symlinks[filepath.Join(home, ".claude", "skills")] != filepath.Join(home, ".ssh") {
		t.Errorf("the link into ~/.ssh is not recorded: %v", snap.Symlinks)
	}
	if snap.Symlinks[filepath.Join(home, ".gemini", "skills")] != "/etc" {
		t.Errorf("the link into /etc is not recorded: %v", snap.Symlinks)
	}
	if _, ok := snap.ConfigTrees[filepath.Join(home, ".codex", "skills")]; ok {
		t.Errorf("a link inside the home is walked as a config tree")
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
		if strings.HasPrefix(p, filepath.Join(home, ".gemini")) && e.Content != "" {
			t.Errorf("content under /etc shipped: %s", p)
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

// A metadata glob's matches behind a linked folder (Copilot's
// session-state/<id> → ~/sess) are recorded, metadata only, when the link
// stays inside the home and outside credential stores; never otherwise.
func TestLinkedFoldersOfMetadataGlobsAreFollowedInsideTheHome(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, "sess", "events.jsonl"), "SESSION-CANARY\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "id_canary"), "SSH-CANARY\n", 0o600)
	outside := filepath.Join(filepath.Dir(home), "elsewhere")
	write(t, filepath.Join(outside, "events.jsonl"), "OUTSIDE-CANARY\n", 0o644)
	state := filepath.Join(home, ".copilot", "session-state")
	mustSymlink(t, filepath.Join(home, "sess"), filepath.Join(state, "in"))
	mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(state, "ssh"))
	mustSymlink(t, outside, filepath.Join(state, "out"))
	snap := Collect(ProbeManifest{MetadataGlobPatterns: []string{"~/.copilot/session-state/*", "~/.copilot/session-state/*/*"}}, false)
	e, ok := snap.Files[filepath.Join(state, "in", "events.jsonl")]
	if !ok || !e.Exists || e.Mode != 0o644 || e.Content != "" {
		t.Errorf("file behind an in-home link: %+v (recorded %v), want metadata", e, ok)
	}
	for _, p := range []string{filepath.Join(state, "ssh", "id_canary"), filepath.Join(state, "out", "events.jsonl")} {
		if _, ok := snap.Files[p]; ok {
			t.Errorf("%s recorded behind a link out of the home or into a store", p)
		}
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("content shipped: %s", p)
		}
	}
}
