package main

import (
	"path/filepath"
	"testing"
)

// A skill linked to where no skills tree is walked is not read, but whether
// it is a directory is recorded (its mode): the CLI reports a skill there
// not scanned, as a local scan does.
func TestRefusedSkillLinkRecordsItIsADirectory(t *testing.T) {
	home := setupHome(t)
	skills := filepath.Join(home, ".claude", "skills")
	write(t, filepath.Join(skills, "own", "SKILL.md"), "# own\n", 0o644)
	mustSymlink(t, "/usr/share", filepath.Join(skills, "share"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	if _, ok := snap.DirectoryModes[filepath.Join(skills, "share")]; !ok {
		t.Errorf("refused skill link's mode not recorded: %v", snap.DirectoryModes)
	}
	if _, listed := snap.Directories[filepath.Join(skills, "share")]; listed {
		t.Error("refused skill link listed")
	}
}

// A dangling link a config tree's wildcard matches in the home is no
// directory there: its name is not recorded as a match.
func TestWildcardNamesSkipDanglingLinks(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, "myws", "skills", "x", "SKILL.md"), "# x\n", 0o644)
	write(t, filepath.Join(home, "workspace-ok", "skills", "y", "SKILL.md"), "# y\n", 0o644)
	mustSymlink(t, filepath.Join(home, "nothere"), filepath.Join(home, "workspace-lnk"))
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{"agents": {"defaults": {"workspace": "`+filepath.Join(home, "myws")+`"}}}`, 0o644)
	req := ConfigRootRequest{
		Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "../workspace-*/skills/**"},
	}
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{req}}, false)
	names := snap.WildcardNames[filepath.Join(home, "workspace-*")]
	if len(names) != 1 || names[0] != "workspace-ok" {
		t.Errorf("wildcard names %v, want [workspace-ok]", names)
	}
}
