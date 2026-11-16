package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bmatcuk/doublestar/v4"
)

// The glob index answers as matching every glob does.
func TestGlobIndexMatchesEveryGlob(t *testing.T) {
	globs := []string{
		"/home/u/.codex/sessions/**", "/home/u/.claude.json", "/home/u/.config/*/state.vscdb",
		"/**/token.json", "/home/u/.gemini/tmp/*/chats/**", `/home/u/we\*ird/**`, "/home/u/.copilot/session-state/**",
		"/home/u/library/application support/{cursor,code}/user/globalstorage/state.vscdb",
	}
	paths := []string{
		"/home/u/.codex/sessions", "/home/u/.codex/sessions/a/b.jsonl", "/home/u/.codex/sessionsx/a",
		"/home/u/.claude.json", "/home/u/.claude.json/x", "/home/u/.config/cursor/state.vscdb",
		"/home/u/.config/a/b/state.vscdb", "/x/y/token.json", "/token.json", "/home/u/.gemini/tmp/h/chats/c.json",
		"/home/u/we*ird/f", "/home/u/weXird/f", "/HOME/U/.COPILOT/SESSION-STATE/s.json",
		"/home/u/Library/Application Support/Cursor/User/globalStorage/state.vscdb", "/", "/home",
	}
	idx := newGlobIndex(globs)
	for _, p := range paths {
		want := false
		for _, g := range globs {
			if ok, _ := doublestar.Match(g, strings.ToLower(p)); ok {
				want = true
			}
		}
		if got := idx.matches(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

// Files of a tree reached through links into credential stores are judged
// as the uncached functions judge them: same resolution, same sink verdicts.
func TestCachedResolutionAgreesWithUncached(t *testing.T) {
	home := setupHome(t)
	mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), "{}")
	mustWrite(t, filepath.Join(home, ".ssh", "id_ed25519"), "k")
	mustWrite(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "h")
	mustWrite(t, filepath.Join(home, "repo", "s", "SKILL.md"), "# s")
	mustWrite(t, filepath.Join(home, "repo", "s", "run.sh"), "x")
	skills := filepath.Join(home, ".claude", "skills")
	mustLink(t, filepath.Join(home, "repo"), filepath.Join(skills, "r"))
	mustLink(t, filepath.Join(home, ".ssh"), filepath.Join(skills, "r2"))
	mustLink(t, filepath.Join(home, ".config"), filepath.Join(skills, "cfg"))
	mustLink(t, filepath.Join(home, ".claude", ".credentials.json"), filepath.Join(home, "repo", "s", "c.json"))
	mustLink(t, "../repo", filepath.Join(skills, "rel"))
	c := &collector{}
	n := 0
	for _, base := range []string{skills, filepath.Join(skills, "r"), home} {
		_ = filepath.WalkDir(skills, func(p string, d fs.DirEntry, err error) error {
			if err != nil || p == skills {
				return nil
			}
			check := func(p string) {
				_, isLink, err := lstatThenStat(p)
				if err != nil {
					return
				}
				n++
				if got, want := c.escapesToSinkAt(p, base, isLink), escapesToSink(p, base); got != want {
					t.Errorf("escapesToSink(%s, %s): %v, want %v", p, base, got, want)
				}
				real, ok := c.resolveFile(p, isLink)
				want, err := filepath.EvalSymlinks(p)
				if ok != (err == nil) || (ok && real != filepath.Clean(want)) {
					t.Errorf("resolve %s: %q %v, want %q %v", p, real, ok, want, err)
				}
				if got, want := c.resolvedIntoSinkAt(p, real, base), resolvedIntoSink(p, base); got != want {
					t.Errorf("resolvedIntoSink(%s, %s): %v, want %v", p, base, got, want)
				}
			}
			check(p)
			// and what lies behind each link to a folder
			if d.Type()&os.ModeSymlink != 0 {
				if st, err := os.Stat(p); err == nil && st.IsDir() {
					entries, _ := os.ReadDir(p)
					for _, e := range entries {
						check(filepath.Join(p, e.Name()))
						if e.IsDir() {
							sub, _ := os.ReadDir(filepath.Join(p, e.Name()))
							for _, s := range sub {
								check(filepath.Join(p, e.Name(), s.Name()))
							}
						}
					}
				}
			}
			return nil
		})
	}
	if n < 20 {
		t.Fatalf("only %d paths judged", n)
	}
}
