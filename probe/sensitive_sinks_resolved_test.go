package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A skills tree that reaches an agent's token file through a linked
// directory above the file (the root itself linked to ~/.claude, ~/.codex or
// ~/.config) or through a file link: judged by where the file really is.
func TestCollectNeverShipsTokenFilesReachedThroughLinkedSkillTrees(t *testing.T) {
	cases := []struct {
		name  string
		setup func(home string) []string
	}{
		{"file link to .credentials.json", func(home string) []string {
			mustWrite(t, filepath.Join(home, ".claude", "skills", "s", "SKILL.md"), "---\nname: s\n---\n")
			mustLink(t, filepath.Join(home, ".claude", ".credentials.json"), filepath.Join(home, ".claude", "skills", "s", "c.json"))
			return []string{filepath.Join(home, ".claude", "skills", "s", "c.json")}
		}},
		{"skills linked to ~/.claude", func(home string) []string {
			mustLink(t, filepath.Join(home, ".claude"), filepath.Join(home, ".claude", "skills"))
			return []string{filepath.Join(home, ".claude", "skills", ".credentials.json")}
		}},
		{"skills linked to ../.codex", func(home string) []string {
			mustLink(t, "../.codex", filepath.Join(home, ".claude", "skills"))
			return []string{filepath.Join(home, ".claude", "skills", "auth.json")}
		}},
		{"skills linked to ~/.config", func(home string) []string {
			mustLink(t, filepath.Join(home, ".config"), filepath.Join(home, ".claude", "skills"))
			return []string{filepath.Join(home, ".claude", "skills", "gh", "hosts.yml")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), `{"claudeAiOauth":{"accessToken":"TOKCANARY"}}`)
			mustWrite(t, filepath.Join(home, ".codex", "auth.json"), `{"OPENAI_API_KEY":"KEYCANARY"}`)
			mustWrite(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n  oauth_token: GHCANARY\n")
			want := tc.setup(home)
			snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude", "skills") + "/**"}}, false)
			for p, e := range snap.Files {
				if strings.Contains(e.Content, "CANARY") || strings.Contains(e.Head, "CANARY") {
					t.Fatalf("%s shipped token content", p)
				}
			}
			for _, p := range want {
				if e := snap.Files[p]; !e.Exists || e.Omitted != "sensitive" {
					t.Fatalf("%s: want omitted=sensitive, got %+v", p, e)
				}
			}
		})
	}
	// An ordinary file in a linked tree is still collected
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".config", "tool", "notes.md"), "plain")
	mustLink(t, filepath.Join(home, ".config"), filepath.Join(home, ".claude", "skills"))
	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude", "skills") + "/**"}}, false)
	if e := snap.Files[filepath.Join(home, ".claude", "skills", "tool", "notes.md")]; e.Content != "plain" {
		t.Fatalf("ordinary file in a linked tree not collected: %+v", e)
	}
}

// The manifest's metadata-only stores and its own configs, reached through a
// linked skills dir: metadata only, and disguised like the config.
func TestLinkedSkillTreeFilesJudgedByManifestTargets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	key := "sk-ant-api03-" + strings.Repeat("Qw3rTy9Zx", 8)
	mustWrite(t, filepath.Join(home, ".codex", "sessions", "2026", "11", "16", "rollout-1.jsonl"), `{"msg":"CONVCANARY"}`)
	mustWrite(t, filepath.Join(home, ".codex", "config.toml"), "[env]\nOPENAI_API_KEY = \""+key+"\"\n")
	mustWrite(t, filepath.Join(home, "kit", "SKILL.md"), "---\nname: kit\n---\n")
	mustLink(t, filepath.Join(home, ".codex"), filepath.Join(home, ".claude", "skills", "c"))
	mustLink(t, filepath.Join(home, "kit"), filepath.Join(home, ".claude", "skills", "kit"))
	snap := Collect(ProbeManifest{
		FilePaths:            []string{"~/.codex/config.toml"},
		GlobPatterns:         []string{"~/.claude/skills/**"},
		MetadataGlobPatterns: []string{"~/.codex/sessions/*/*/*/rollout-*.jsonl"},
	}, false)
	session := filepath.Join(home, ".claude", "skills", "c", "sessions", "2026", "11", "16", "rollout-1.jsonl")
	if e := snap.Files[session]; !e.Exists || e.Omitted != "metadata" {
		t.Fatalf("conversation store under a skills spelling: want metadata only, got %+v", e)
	}
	cfg := filepath.Join(home, ".claude", "skills", "c", "config.toml")
	if e := snap.Files[cfg]; !e.Exists || strings.Contains(e.Content, key) || !strings.Contains(e.Content, "OPENAI_API_KEY") {
		t.Fatalf("a manifest config under a skills spelling: want it disguised, got %+v", e)
	}
	if e := snap.Files[filepath.Join(home, ".claude", "skills", "kit", "SKILL.md")]; !strings.Contains(e.Content, "name: kit") {
		t.Fatalf("an ordinary linked skill ships as it is: %+v", e)
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CONVCANARY") {
			t.Fatalf("%s shipped conversation content", p)
		}
	}
}

func TestResolvedIntoSinkKeepsWhatTheSpellingNames(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, "dot", "codex", "auth.json"), "x")
	mustLink(t, filepath.Join(home, "dot", "codex"), filepath.Join(home, ".codex"))
	// ~/.codex → ~/dot/codex: the spelled path names the store, the real one doesn't
	if resolvedIntoSink(filepath.Join(home, ".codex", "auth.json"), filepath.Join(home, ".codex", "auth.json")) {
		t.Fatal("a store spelled as itself is not reached through a link")
	}
	mustWrite(t, filepath.Join(home, ".claude", ".credentials.json"), "x")
	mustLink(t, filepath.Join(home, ".claude"), filepath.Join(home, "k"))
	if !resolvedIntoSink(filepath.Join(home, "k", ".credentials.json"), filepath.Join(home, "k")) {
		t.Fatal("~/k → ~/.claude: .credentials.json is reached through a link")
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustLink(t *testing.T, target, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}
