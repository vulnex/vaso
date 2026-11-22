package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A link in a skill's vendor folder is recorded, name and target only — a
// local SKL-013 walk lists those folders and reports a link out of the
// tree there — and nothing behind it is collected.
func TestVendorFolderLinksRecordedNotFollowed(t *testing.T) {
	home := setupHome(t)
	skills := filepath.Join(home, ".claude", "skills")
	write(t, filepath.Join(skills, "s", "SKILL.md"), "# s\n", 0o644)
	write(t, filepath.Join(home, ".bashrc"), "export X=1\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "k\n", 0o600)
	write(t, filepath.Join(home, "lib", "big.js"), "x\n", 0o644)
	cfg := filepath.Join(skills, "s", "node_modules", "x", "config.json")
	keys := filepath.Join(skills, "s", ".git", "cfg")
	lib := filepath.Join(skills, "s", "venv", "lib")
	for _, p := range []string{cfg, keys, lib} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustSymlink(t, filepath.Join(home, ".bashrc"), cfg)
	mustSymlink(t, filepath.Join(home, ".ssh"), keys)
	mustSymlink(t, filepath.Join(home, "lib"), lib)
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	for _, l := range []string{cfg, keys, lib} {
		if _, ok := snap.Symlinks[l]; !ok {
			t.Errorf("vendor-folder link %s not recorded", l)
		}
	}
	for p, f := range snap.Files {
		if p == cfg || strings.HasPrefix(p, lib+string(filepath.Separator)) || strings.HasPrefix(p, keys+string(filepath.Separator)) {
			t.Errorf("collected %s behind a vendor-folder link", p)
		}
		if strings.HasPrefix(p, filepath.Join(home, ".ssh")) && f.Content != "" {
			t.Errorf("credential content collected: %s", p)
		}
	}
}

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
