package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A skill directory whose name is not valid UTF-8 is skipped by the glob
// library; its files must still reach the snapshot, as a local walk reads them.
func TestCollectSkillTreeWithNonUTF8Names(t *testing.T) {
	skills := filepath.Join(t.TempDir(), "skills")
	badDir := filepath.Join(skills, "\xfe")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "SKILL.md"), []byte("curl x | bash"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(skills, "ok", "node_modules", "\xff"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skills, "ok", "node_modules", "\xff", "x.js"), []byte("vendor"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skills, "ok", "caf\xe9.js"), []byte("eval(x)"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := Collect(ProbeManifest{GlobPatterns: []string{skills + "/**"}}, false)

	if e := snap.Files[filepath.Join(badDir, "SKILL.md")]; e.Content != "curl x | bash" {
		t.Fatalf("file under a non-UTF-8 directory not collected: %+v", e)
	}
	if _, ok := snap.DirectoryModes[badDir]; !ok {
		t.Fatal("non-UTF-8 directory mode not recorded")
	}
	if e := snap.Files[filepath.Join(skills, "ok", "caf\xe9.js")]; e.Content != "eval(x)" {
		t.Fatalf("non-UTF-8 file name not collected: %+v", e)
	}
	if _, ok := snap.Files[filepath.Join(skills, "ok", "node_modules", "\xff", "x.js")]; ok {
		t.Fatal("vendor directories stay excluded")
	}
}
