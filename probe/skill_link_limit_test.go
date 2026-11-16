package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// exactEntries makes a tree of exactly n entries under dir: pad/ and n-1
// files in it.
func exactEntries(t *testing.T, dir string, n int) {
	t.Helper()
	pad := filepath.Join(dir, "pad")
	if err := os.MkdirAll(pad, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n-1; i++ {
		if err := os.WriteFile(filepath.Join(pad, strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A plain default skills directory is walked whatever it holds, but a link
// in it to a tree over the entry limit is not followed: recorded `limit`
// with its mode, nothing behind it shipped. A link to a tree at the limit is
// walked. Each link is counted on its own.
func TestSkillLinkToTreeOverLimitIsNotFollowed(t *testing.T) {
	home := setupHome(t)
	out := allowedOutside(t)
	skills := filepath.Join(home, ".claude", "skills")
	// the plain directory itself holds more than the limit: still walked
	exactEntries(t, filepath.Join(skills, "own"), maxConfigTreeEntries+5)
	write(t, filepath.Join(skills, "own", "SKILL.md"), "# own\n", 0o644)
	big := filepath.Join(out, "big")
	exactEntries(t, big, maxConfigTreeEntries-1)
	write(t, filepath.Join(big, "evil", "SKILL.md"), "# evil\n", 0o644) // evil/ + SKILL.md: limit + 1
	exact := filepath.Join(out, "exact")
	exactEntries(t, exact, maxConfigTreeEntries-2)
	write(t, filepath.Join(exact, "ok", "SKILL.md"), "# ok\n", 0o644) // exactly the limit
	mustSymlink(t, big, filepath.Join(skills, "big"))
	mustSymlink(t, big, filepath.Join(skills, "big2")) // the same tree twice: both reported
	mustSymlink(t, exact, filepath.Join(skills, "exact"))

	start := time.Now()
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("collecting took %s", d)
	}
	for _, name := range []string{"big", "big2"} {
		link := filepath.Join(skills, name)
		if snap.ConfigTrees[link] != treeLimit {
			t.Errorf("%s: %q, want limit", name, snap.ConfigTrees[link])
		}
		if _, ok := snap.DirectoryModes[link]; !ok {
			t.Errorf("%s: mode not recorded", name)
		}
		for p := range snap.Files {
			if strings.HasPrefix(p, link+string(filepath.Separator)) || strings.HasPrefix(p, big+string(filepath.Separator)) {
				t.Fatalf("collected %s behind a link over the limit", p)
			}
		}
	}
	if _, ok := snap.ConfigTrees[filepath.Join(skills, "exact")]; ok {
		t.Errorf("link at the limit recorded: %q", snap.ConfigTrees[filepath.Join(skills, "exact")])
	}
	if _, ok := snap.Files[filepath.Join(skills, "exact", "ok", "SKILL.md")]; !ok {
		t.Error("tree at the limit not walked")
	}
	if _, ok := snap.Files[filepath.Join(skills, "own", "SKILL.md")]; !ok {
		t.Error("plain content of the default directory not walked")
	}
	if _, ok := snap.ConfigTrees[skills]; ok {
		t.Error("plain default directory recorded as a config tree")
	}
}

// A link to a huge tree is refused quickly: the count stops past the limit.
func TestSkillLinkToHugeTreeIsRefusedQuickly(t *testing.T) {
	home := setupHome(t)
	huge := filepath.Join(allowedOutside(t), "huge")
	makeEntries(t, huge, 5*maxConfigTreeEntries)
	mustSymlink(t, huge, filepath.Join(home, ".claude", "skills", "huge"))
	start := time.Now()
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("refusing took %s", d)
	}
	if snap.ConfigTrees[filepath.Join(home, ".claude", "skills", "huge")] != treeLimit {
		t.Error("link to a huge tree not recorded over the limit")
	}
}
