//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCollectFileSkipsFIFOsAndDevices(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.js")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo unsupported:", err)
	}
	zero := filepath.Join(dir, "zero.js")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	c := &collector{budget: 1 << 20}
	done := make(chan [2]FileEntry, 1)
	go func() { done <- [2]FileEntry{c.collectFile(fifo, false), c.collectFile(zero, false)} }()
	select {
	case got := <-done:
		for i, e := range got {
			if !e.Exists || !e.ContentOmitted || e.Content != "" {
				t.Fatalf("entry %d: want exists + content omitted, got %+v", i, e)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collectFile blocked on a FIFO or /dev/zero")
	}
}

func TestGlobFollowsSkillLinksOutsideTheTree(t *testing.T) {
	base := t.TempDir()
	base, _ = filepath.EvalSymlinks(base)
	skills := filepath.Join(base, "skills")
	checkout := filepath.Join(base, "checkout", "linked")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(skills, "local"), 0o755))
	must(os.MkdirAll(filepath.Join(checkout, "lib"), 0o755))
	must(os.WriteFile(filepath.Join(skills, "local", "index.js"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(checkout, "index.js"), []byte("eval(x)"), 0o644))
	must(os.WriteFile(filepath.Join(checkout, "lib", "util.js"), []byte("y"), 0o644))
	must(os.Symlink(checkout, filepath.Join(skills, "linked")))
	must(os.Symlink(filepath.Join(skills, "local"), filepath.Join(skills, "alias")))       // into the tree
	must(os.Symlink(filepath.Join(base, "checkout"), filepath.Join(checkout, "lib", "up"))) // back up: cycle

	snap := Collect(ProbeManifest{GlobPatterns: []string{skills + "/**"}}, false)

	linked := filepath.Join(skills, "linked", "lib", "util.js")
	if e, ok := snap.Files[linked]; !ok || e.Content != "y" {
		t.Fatalf("file behind an outside link not collected under the link path: %+v", e)
	}
	if _, ok := snap.Files[filepath.Join(skills, "alias", "index.js")]; ok {
		t.Fatal("a link back into the tree was walked twice")
	}
	for p := range snap.Files {
		if strings.Contains(p, "/up/") {
			t.Fatalf("followed a link to a parent of a walked tree: %s", p)
		}
	}
	if snap.Symlinks[filepath.Join(skills, "linked")] != checkout {
		t.Fatalf("link target not recorded: %v", snap.Symlinks)
	}
}
