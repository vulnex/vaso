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
	must(os.Symlink(filepath.Join(skills, "local"), filepath.Join(skills, "alias")))        // into the tree
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

func TestRootResolvesSystemBinariesBeforeUserDirs(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// A planted `which` in a user's bin dir
	if err := os.WriteFile(filepath.Join(bin, "which"), []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	homes := []UserHome{{Username: "eve", Path: home}}

	orig := runningAsRoot
	defer func() { runningAsRoot = orig }()

	runningAsRoot = func() bool { return false }
	if got := resolveBinary("which", buildAugmentedPath(homes, "/usr/bin:/bin")); got != filepath.Join(bin, "which") {
		t.Fatalf("non-root: user dir first, got %s", got)
	}
	runningAsRoot = func() bool { return true }
	path := buildAugmentedPath(homes, "/usr/bin:/bin")
	if got := resolveBinary("which", path); got != "/usr/bin/which" {
		t.Fatalf("root: system which must win, got %s", got)
	}
	// Commands run as root get a PATH without user-writable dirs
	for _, d := range filepath.SplitList(rootChildPath(path)) {
		if strings.HasPrefix(d, home) {
			t.Fatalf("root child PATH contains a user dir: %s", d)
		}
	}
	if rootSafe(filepath.Join(bin, "which")) {
		t.Fatal("a user-owned binary is not root-safe")
	}
	if !rootSafe("/bin/sh") {
		t.Fatal("/bin/sh should be root-safe")
	}
}

func TestUnlistableDirectoryStillRecorded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	root := t.TempDir()
	profile := filepath.Join(root, "Comet")
	if err := os.Mkdir(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profile, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(profile, 0o755)

	snap := Collect(ProbeManifest{DirectoryListings: []string{profile}}, false)
	if _, listed := snap.Directories[profile]; listed {
		t.Fatal("an unreadable directory has no listing")
	}
	if mode, ok := snap.DirectoryModes[profile]; !ok || mode != 0 {
		t.Fatalf("unreadable directory not recorded as present: %v", snap.DirectoryModes)
	}

	// A config behind it is denied, and the directory that denied it is recorded
	cfg := filepath.Join(profile, "config.json")
	snap = Collect(ProbeManifest{FilePaths: []string{cfg}}, false)
	if e := snap.Files[cfg]; !e.Denied || e.Exists {
		t.Fatalf("config behind a mode-000 directory: %+v", e)
	}
	if mode, ok := snap.DirectoryModes[profile]; !ok || mode != 0 {
		t.Fatalf("denying directory not recorded: %v", snap.DirectoryModes)
	}
}

func TestUnlistableSkillDirKeepsSkillMd(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "helper")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("# helper"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(skill, 0o111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(skill, 0o755)

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(root, "skills") + "/**"}}, false)
	if e := snap.Files[filepath.Join(skill, "SKILL.md")]; !e.Exists || e.Content != "# helper" {
		t.Fatalf("SKILL.md of an unlistable skill dir not collected: %+v", e)
	}
	if snap.DirectoryModes[skill] != 0o111 {
		t.Fatalf("mode of the unlistable skill dir not recorded: %v", snap.DirectoryModes)
	}
}

func TestUnlistableSkillDirCollectsKnownNames(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists any directory")
	}
	root := t.TempDir()
	skill := filepath.Join(root, "skills", "evil")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"SKILL.md", "package.json"} {
		if err := os.WriteFile(filepath.Join(skill, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(skill, 0o111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(skill, 0o755)

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(root, "skills") + "/**"}}, false)
	for _, n := range []string{"SKILL.md", "package.json"} {
		if e := snap.Files[filepath.Join(skill, n)]; !e.Exists {
			t.Fatalf("%s in an unlistable skill dir not collected by name: %+v", n, e)
		}
	}
}
