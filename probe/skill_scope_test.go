package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// allowedOutside is a directory out of the test's home where a skills tree
// may be walked: under /tmp (t.TempDir is under /var on macOS, an OS
// directory no skills tree is walked in).
func allowedOutside(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "vaso-scope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// scopeCase is one row of testdata/skill-scope-cases.json, which
// src/core/skill-root-scope.test.ts reads too: the two sides label paths the
// same way.
type scopeCase struct {
	Path   string   `json:"path"`
	Own    []string `json:"own"`
	All    []string `json:"all"`
	Labels []string `json:"labels"`
}

func TestScopeLabelsMatchTS(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "skill-scope-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []scopeCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 30 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		got := scopeLabels(c.Path, c.Own, c.All)
		if got == nil {
			got = []string{}
		}
		if !reflect.DeepEqual(got, c.Labels) {
			t.Errorf("scopeLabels(%s, own=%v, all=%v) = %v, want %v", c.Path, c.Own, c.All, got, c.Labels)
		}
	}
}

// A manifest skills tree's own links follow the same rule: a skill linked in
// from another volume is read, one linked from an OS directory or the home
// itself is recorded and not read.
func TestManifestSkillTreeLinksFollowTheScope(t *testing.T) {
	home := setupHome(t)
	outside := allowedOutside(t)
	write(t, filepath.Join(outside, "team", "SKILL.md"), "# team\n", 0o644)
	write(t, filepath.Join(outside, "f.js"), "eval(x)\n", 0o644)
	skills := filepath.Join(home, ".claude", "skills")
	write(t, filepath.Join(skills, "own", "SKILL.md"), "# own\n", 0o644)
	mustSymlink(t, filepath.Join(outside, "team"), filepath.Join(skills, "team"))
	mustSymlink(t, filepath.Join(outside, "f.js"), filepath.Join(skills, "own", "f.js"))
	mustSymlink(t, "/usr/share", filepath.Join(skills, "share"))
	mustSymlink(t, "/usr/share/dict/words", filepath.Join(skills, "own", "words.txt"))
	mustSymlink(t, home, filepath.Join(skills, "up"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{"~/.claude/skills/**"}}, false)
	if e := snap.Files[filepath.Join(skills, "team", "SKILL.md")]; e.Content == "" {
		t.Error("skill linked in from out of the home not read")
	}
	if e := snap.Files[filepath.Join(skills, "own", "f.js")]; e.Content == "" {
		t.Error("file linked in from out of the home not read")
	}
	if e := snap.Files[filepath.Join(skills, "own", "words.txt")]; e.Content != "" || (e.Exists && e.Omitted != "sensitive") {
		t.Errorf("file behind a link into /usr: %+v", e)
	}
	for p := range snap.Files {
		for _, n := range []string{"share", "up"} {
			if within(p, filepath.Join(skills, n)) && p != filepath.Join(skills, n) {
				t.Errorf("walked into %s: %s", n, p)
			}
		}
	}
	for _, n := range []string{"team", "share", "up", filepath.Join("own", "words.txt")} {
		if _, ok := snap.Symlinks[filepath.Join(skills, n)]; !ok {
			t.Errorf("link %s not recorded", n)
		}
	}
}

// A directory the manifest lists that a link takes to an OS directory, a
// credential store or another place no skills tree is walked is not listed:
// its link is recorded instead. One linked to another volume is listed.
func TestListingsLinkedToRefusedPlacesAreNotShipped(t *testing.T) {
	home := setupHome(t)
	outside := allowedOutside(t)
	write(t, filepath.Join(home, ".ssh", "id_canary"), "x\n", 0o600)
	write(t, filepath.Join(outside, "team", "SKILL.md"), "# team\n", 0o644)
	mustSymlink(t, "/etc", filepath.Join(home, ".claude", "skills"))
	mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(home, ".codex", "skills"))
	mustSymlink(t, outside, filepath.Join(home, ".gemini", "skills"))
	snap := Collect(ProbeManifest{DirectoryListings: []string{"~/.claude/skills", "~/.codex/skills", "~/.gemini/skills"}}, false)
	for _, d := range []string{".claude", ".codex"} {
		p := filepath.Join(home, d, "skills")
		if _, ok := snap.Directories[p]; ok {
			t.Errorf("%s listed", p)
		}
		if snap.Symlinks[p] == "" {
			t.Errorf("%s: link not recorded", p)
		}
	}
	if l := snap.Directories[filepath.Join(home, ".gemini", "skills")]; len(l) != 1 || l[0] != "team/" {
		t.Errorf("a directory linked to another volume is not listed: %v", l)
	}
}

// A workspace set directly in the home: the probe never lists the home, but
// records the names its derived `workspace-*` siblings match there, so the
// CLI tells a missing `workspace-<id>` from one never looked at.
func TestWildcardNamesInAHome(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, "myws", "skills", "a", "SKILL.md"), "# a\n", 0o644)
	write(t, filepath.Join(home, "workspace-ops", "notes.txt"), "x\n", 0o644)
	write(t, filepath.Join(home, "private.txt"), "x\n", 0o644)
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{agents: {defaults: {workspace: "~/myws"}}}`, 0o644)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{{
		Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "../workspace-*/skills/**"},
	}}}, false)
	key := filepath.ToSlash(filepath.Join(home, "workspace-*"))
	if got := snap.WildcardNames[key]; !reflect.DeepEqual(got, []string{"workspace-ops"}) {
		t.Errorf("wildcardNames[%s] = %v", key, got)
	}
	if _, ok := snap.Directories[home]; ok {
		t.Error("the home was listed")
	}
	// the match itself is listed (names only): its missing skills/ reads as missing
	if l, ok := snap.Directories[filepath.Join(home, "workspace-ops")]; !ok || len(l) != 1 {
		t.Errorf("matched workspace not listed: %v", l)
	}
}
