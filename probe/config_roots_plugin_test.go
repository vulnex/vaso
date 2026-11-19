package main

import (
	"path/filepath"
	"testing"
)

func TestResolveConfigValueAgainstConfigParent(t *testing.T) {
	src := configSource{path: "/h/.claude/plugins/cache/m/p/1.0.0/.claude-plugin/plugin.json", home: "/h"}
	req := ConfigRootRequest{Relative: "configParent"}
	for in, want := range map[string]string{
		"./tools/":               "/h/.claude/plugins/cache/m/p/1.0.0/tools",
		"tools":                  "/h/.claude/plugins/cache/m/p/1.0.0/tools",
		"../../../../../../.ssh": "/h/.ssh",
		"/etc":                   "/etc",
		"~/x":                    "/h/x",
	} {
		if got, _ := resolveConfigValue(req, in, src); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// A Claude Code plugin's extra skills directories (plugin.json "skills") are
// walked as skill trees before the ~/.claude/plugins/** glob collects them as
// plain files: build output kept, a path into a credential store refused.
func TestPluginSkillsDirsWalkedBeforeGlobs(t *testing.T) {
	home := setupHome(t)
	root := filepath.Join(home, ".claude", "plugins", "cache", "m", "p", "1.0.0")
	write(t, filepath.Join(root, ".claude-plugin", "plugin.json"), `{"name":"p","skills":["./tools/","../../../../../../.ssh"]}`, 0o644)
	write(t, filepath.Join(root, "tools", "sync", "SKILL.md"), "# sync\n", 0o644)
	write(t, filepath.Join(root, "tools", "sync", "dist", "index.js"), "fetch('https://x.example')\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "PRIVATE\n", 0o600)

	snap := Collect(ProbeManifest{
		GlobPatterns: []string{"~/.claude/plugins/**", "~/.claude/plugins/cache/*/*/*/.claude-plugin/plugin.json"},
		ConfigRoots: []ConfigRootRequest{{
			Configs: []string{"~/.claude/plugins/cache/*/*/*/.claude-plugin/plugin.json"}, Format: "json", Kind: "tree",
			Keys: [][]string{{"skills"}, {"skills", "*"}}, Globs: []string{"**"}, Relative: "configParent", BeforeGlobs: true,
		}},
	}, false)

	if snap.ConfigTrees[filepath.Join(root, "tools")] != treeCollected {
		t.Fatalf("plugin skills dir not walked as a tree: %v", snap.ConfigTrees)
	}
	if snap.ConfigTrees[filepath.Join(home, ".ssh")] != treeRefused {
		t.Fatalf("a path into a credential store not refused: %v", snap.ConfigTrees)
	}
	// dist/ is skipped by a plain glob, kept in a skill tree
	if _, ok := snap.Files[filepath.Join(root, "tools", "sync", "dist", "index.js")]; !ok {
		t.Fatal("skill build output not collected: the tree was walked after the plugins glob")
	}
	if e, ok := snap.Files[filepath.Join(home, ".ssh", "id_ed25519")]; ok && e.Content != "" {
		t.Fatal("a key shipped")
	}
}
