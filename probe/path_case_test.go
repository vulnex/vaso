package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// caseInsensitiveDir reports whether dir's filesystem opens a name in other
// letters (macOS APFS by default; most Linux filesystems don't).
func caseInsensitiveDir(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

func makeEntries(t *testing.T, dir string, n int) {
	t.Helper()
	for i := 0; i < n/100+1; i++ {
		d := filepath.Join(dir, "d"+strconv.Itoa(i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 100; j++ {
			if err := os.WriteFile(filepath.Join(d, strconv.Itoa(j)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A skills directory that is itself a link — an agent's default one linked
// out of the home, or one a config sets — is capped like the directory it
// leads to: counted from where it leads, recorded `limit`, nothing shipped.
func TestLinkedTreeRootsAreCappedLikeTheirTarget(t *testing.T) {
	home := setupHome(t)
	big := filepath.Join(allowedOutside(t), "big")
	makeEntries(t, big, maxConfigTreeEntries)
	mustSymlink(t, big, filepath.Join(home, ".claude", "skills"))
	mustSymlink(t, big, filepath.Join(home, "biglink"))
	writeExtraDirs(t, home, "~/biglink", big)
	m := extraDirsManifest()
	m.GlobPatterns = []string{"~/.claude/skills/**"}
	start := time.Now()
	snap := Collect(m, false)
	for _, p := range []string{filepath.Join(home, ".claude", "skills"), filepath.Join(home, "biglink"), big} {
		if snap.ConfigTrees[p] != treeLimit {
			t.Errorf("%s: %q, want limit", p, snap.ConfigTrees[p])
		}
	}
	for p := range snap.Files {
		if strings.HasPrefix(p, big) || strings.HasPrefix(p, filepath.Join(home, ".claude")) || strings.HasPrefix(p, filepath.Join(home, "biglink")) {
			t.Fatalf("collected %s from a capped tree", p)
		}
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("counting took %s", d)
	}
	if n := countTreeEntries(filepath.Join(home, "biglink"), home, 50); n != 51 {
		t.Errorf("count through a linked root stops past the limit: %d", n)
	}
}

func TestCanonicalCaseSpellsAsStored(t *testing.T) {
	dir := allowedOutside(t)
	if err := os.MkdirAll(filepath.Join(dir, "Fx", "hu"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := canonicalCase(filepath.Join(dir, "Fx", "hu", "missing")); got != filepath.Join(dir, "Fx", "hu", "missing") {
		t.Errorf("stored spelling changed: %s", got)
	}
	if !caseInsensitiveDir(t, dir) {
		if got := canonicalCase(filepath.Join(dir, "FX", "HU")); got != filepath.Join(dir, "FX", "HU") {
			t.Errorf("case-sensitive filesystem: %s respelled", got)
		}
		return
	}
	if got := canonicalCase(filepath.Join(dir, "FX", "HU")); got != filepath.Join(dir, "Fx", "hu") {
		t.Errorf("canonicalCase = %s, want %s", got, filepath.Join(dir, "Fx", "hu"))
	}
	if got := resolveExisting(filepath.Join(dir, "fX", "Hu", "a", "b")); got != filepath.Join(dir, "Fx", "hu", "a", "b") {
		t.Errorf("resolveExisting = %s", got)
	}
}

// On a case-insensitive filesystem the home written in other letters (or a
// directory above it) is the home: refused like the home, never walked, and
// where it resolves is recorded so the CLI names it the home too. A link in
// a skills tree to the home so spelled is not followed either.
func TestHomeInOtherLettersIsTheHome(t *testing.T) {
	base := allowedOutside(t)
	if !caseInsensitiveDir(t, base) {
		t.Skip("case-sensitive filesystem")
	}
	home := filepath.Join(base, "fx", "hu")
	write(t, filepath.Join(home, "Documents", "diary.txt"), "DIARY-CANARY\n", 0o644)
	write(t, filepath.Join(home, ".claude", "skills", "own", "SKILL.md"), "# own\n", 0o644)
	mustSymlink(t, filepath.Join(base, "FX", "HU"), filepath.Join(home, ".claude", "skills", "homelink"))
	t.Setenv("HOME", home)
	upper := filepath.Join(base, "FX", "hu")
	parent := filepath.Join(base, "FX")
	writeExtraDirs(t, home, upper, parent)
	m := extraDirsManifest()
	m.GlobPatterns = []string{"~/.claude/skills/**"}
	snap := Collect(m, false)
	for _, p := range []string{upper, parent} {
		if snap.ConfigTrees[p] != treeRefused {
			t.Errorf("%s: %q, want refused", p, snap.ConfigTrees[p])
		}
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("home content shipped: %s", p)
		}
	}
	if got := snap.ResolvedDirs[upper]; got != home {
		t.Errorf("resolvedDirs[%s] = %q, want %s (%v)", upper, got, home, snap.ResolvedDirs)
	}
	if !treeAllowed(filepath.Join(base, "FX", "HU", "team"), home) {
		t.Error("a folder in the home spelled in other letters refused")
	}
}
