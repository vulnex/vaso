package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// shippedUnder: a file under dir (as spelled) is in the snapshot.
func shippedUnder(snap ProbeSnapshot, dir string) bool {
	for p := range snap.Files {
		if strings.HasPrefix(p, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// A default skills directory that is a link to a tree in the home over the
// entry limit is held to it like one linked out of the home: recorded
// `limit`, nothing of it shipped. One within the limit is collected.
func TestInHomeLinkedSkillsRootIsCapped(t *testing.T) {
	home := setupHome(t)
	big := filepath.Join(home, "bigdir")
	exactEntries(t, big, maxConfigTreeEntries-1)
	write(t, filepath.Join(big, "evil", "SKILL.md"), "# evil\n", 0o644) // limit + 1
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "../bigdir", filepath.Join(home, ".claude", "skills"))
	small := filepath.Join(home, "small")
	write(t, filepath.Join(small, "ok", "SKILL.md"), "# ok\n", 0o644)
	mustSymlink(t, small, filepath.Join(home, ".codex", "skills"))
	// a per-agent skills directory (wildcard glob) linked in the home
	if err := os.MkdirAll(filepath.Join(home, ".openclaw", "agents", "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, big, filepath.Join(home, ".openclaw", "agents", "a", "skills"))

	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**", "~/.codex/skills/**", "~/.openclaw/agents/*/skills/**"}}, false)
	claude := filepath.Join(home, ".claude", "skills")
	if snap.ConfigTrees[claude] != treeLimit {
		t.Errorf("linked root: %q, want limit", snap.ConfigTrees[claude])
	}
	agent := filepath.Join(home, ".openclaw", "agents", "a", "skills")
	if snap.ConfigTrees[agent] != treeLimit {
		t.Errorf("linked per-agent root: %q, want limit", snap.ConfigTrees[agent])
	}
	for _, d := range []string{claude, agent, big} {
		if shippedUnder(snap, d) {
			t.Errorf("collected under %s", d)
		}
	}
	codex := filepath.Join(home, ".codex", "skills")
	if snap.ConfigTrees[codex] != treeCollected {
		t.Errorf("linked root within the limit: %q, want collected", snap.ConfigTrees[codex])
	}
	if _, ok := snap.Files[filepath.Join(codex, "ok", "SKILL.md")]; !ok {
		t.Error("linked root within the limit not collected")
	}
}

// Links inside a linked (or config-set) root are not counted against the
// root: each is judged from its own target. Two 9,999-entry links in a
// linked root are both walked, and so is the root's own skill.
func TestLinksInLinkedRootHaveTheirOwnBudget(t *testing.T) {
	home := setupHome(t)
	out := allowedOutside(t)
	prof := filepath.Join(out, "profile", "skills")
	write(t, filepath.Join(prof, "ok", "SKILL.md"), "# ok\n", 0o644)
	for _, n := range []string{"a", "b"} {
		tree := filepath.Join(out, "store", n)
		exactEntries(t, tree, maxConfigTreeEntries-1-2)
		write(t, filepath.Join(tree, "s"+n, "SKILL.md"), "# s\n", 0o644) // 9,999
		mustSymlink(t, tree, filepath.Join(prof, n))
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, prof, filepath.Join(home, ".claude", "skills"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	skills := filepath.Join(home, ".claude", "skills")
	if snap.ConfigTrees[skills] != treeCollected {
		t.Fatalf("root: %q, want collected", snap.ConfigTrees[skills])
	}
	for _, f := range []string{"ok/SKILL.md", "a/sa/SKILL.md", "b/sb/SKILL.md"} {
		if _, ok := snap.Files[filepath.Join(skills, filepath.FromSlash(f))]; !ok {
			t.Errorf("%s not collected", f)
		}
	}
}

// The links of one skills tree hold maxLinkedTreeEntries together: six
// links to distinct 9,999-entry trees — the first five (in walk order) are
// walked, the sixth is recorded `total`, nothing behind it shipped.
func TestSkillLinksShareATotal(t *testing.T) {
	home := setupHome(t)
	out := allowedOutside(t)
	skills := filepath.Join(home, ".claude", "skills")
	for i := 1; i <= 6; i++ {
		tree := filepath.Join(out, "t"+strconv.Itoa(i))
		exactEntries(t, tree, maxConfigTreeEntries-1-2)
		write(t, filepath.Join(tree, "s", "SKILL.md"), "# s\n", 0o644)
		mustSymlink(t, tree, filepath.Join(skills, "l"+strconv.Itoa(i)))
	}
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	for i := 1; i <= 5; i++ {
		link := filepath.Join(skills, "l"+strconv.Itoa(i))
		if _, ok := snap.ConfigTrees[link]; ok {
			t.Errorf("l%d recorded %q", i, snap.ConfigTrees[link])
		}
		if _, ok := snap.Files[filepath.Join(link, "s", "SKILL.md")]; !ok {
			t.Errorf("l%d not walked", i)
		}
	}
	last := filepath.Join(skills, "l6")
	if snap.ConfigTrees[last] != linkTotal {
		t.Errorf("l6: %q, want total", snap.ConfigTrees[last])
	}
	if shippedUnder(snap, last) {
		t.Error("collected behind a link past the total")
	}
}

// Two hundred links to one tree over the limit count it once.
func TestManyLinksToOneTreeCountItOnce(t *testing.T) {
	home := setupHome(t)
	big := filepath.Join(allowedOutside(t), "big")
	makeEntries(t, big, maxConfigTreeEntries+100)
	skills := filepath.Join(home, ".claude", "skills")
	for i := 0; i < 200; i++ {
		mustSymlink(t, big, filepath.Join(skills, "l"+strconv.Itoa(i)))
	}
	start := time.Now()
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
	for i := 0; i < 200; i++ {
		if v := snap.ConfigTrees[filepath.Join(skills, "l"+strconv.Itoa(i))]; v != treeLimit {
			t.Fatalf("l%d: %q", i, v)
		}
	}
}

// Past maxLinkRecords links not followed for size, no further directory
// link is followed and the snapshot says so.
func TestLinkRecordsPastTheirBoundStopFollowing(t *testing.T) {
	old := maxLinkRecords
	maxLinkRecords = 3
	defer func() { maxLinkRecords = old }()
	home := setupHome(t)
	out := allowedOutside(t)
	big := filepath.Join(out, "big")
	makeEntries(t, big, maxConfigTreeEntries+100)
	skills := filepath.Join(home, ".claude", "skills")
	for i := 0; i < 5; i++ {
		mustSymlink(t, big, filepath.Join(skills, "l"+strconv.Itoa(i)))
	}
	small := filepath.Join(out, "small")
	write(t, filepath.Join(small, "s", "SKILL.md"), "# s\n", 0o644)
	mustSymlink(t, small, filepath.Join(skills, "z"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	if !snap.SkillLinksTruncated {
		t.Fatal("not marked truncated")
	}
	n := 0
	for k := range snap.ConfigTrees {
		if strings.HasPrefix(k, skills+"/") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d link records, want 3", n)
	}
	if shippedUnder(snap, filepath.Join(skills, "z")) {
		t.Error("followed a link after the records ran out")
	}
}

// fill makes n empty files in dir.
func fill(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The plan of a tree's links, as skill-tree-count.test.ts plans the same
// layout: each target judged on its own, counts charged to the links' total
// in walk order, one target once.
func TestLinkPlanMatchesTheCLI(t *testing.T) {
	home := setupHome(t)
	root := allowedOutside(t)
	tree := filepath.Join(root, "tree")
	fill(t, filepath.Join(tree, "own"), 20)
	var targets []string
	for i := 1; i <= 6; i++ {
		tg := filepath.Join(root, "t"+strconv.Itoa(i))
		fill(t, filepath.Join(tg, "pad"), maxConfigTreeEntries-1)
		targets = append(targets, tg)
		mustSymlink(t, tg, filepath.Join(tree, "l"+strconv.Itoa(i)))
	}
	big := filepath.Join(root, "big")
	fill(t, filepath.Join(big, "pad"), maxConfigTreeEntries)
	mustSymlink(t, big, filepath.Join(tree, "a-big"))
	mustSymlink(t, targets[0], filepath.Join(tree, "z-again"))
	c := &collector{}
	plan := c.linkPlan(tree, home)
	if plan[big] != linkLimit {
		t.Errorf("big: %q", plan[big])
	}
	want := []string{linkFollow, linkFollow, linkFollow, linkTotal, linkTotal, linkTotal}
	for i, tg := range targets {
		if plan[tg] != want[i] {
			t.Errorf("t%d: %q, want %q", i+1, plan[tg], want[i])
		}
	}
	if len(plan) != 7 {
		t.Errorf("%d verdicts, want 7", len(plan))
	}

	// a followed link's own links come right after it; none into a tree
	// already taken nor above the root
	nest := filepath.Join(root, "nest")
	outer := filepath.Join(root, "outer")
	inner := filepath.Join(root, "inner")
	fill(t, filepath.Join(outer, "s"), 2)
	fill(t, inner, 2)
	mustSymlink(t, inner, filepath.Join(outer, "in"))
	mustSymlink(t, filepath.Join(outer, "s"), filepath.Join(outer, "back"))
	if err := os.MkdirAll(nest, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outer, filepath.Join(nest, "out"))
	mustSymlink(t, root, filepath.Join(nest, "up"))
	np := c.linkPlan(nest, home)
	if len(np) != 2 || np[outer] != linkFollow || np[inner] != linkFollow {
		t.Errorf("nested plan: %v", np)
	}
}
