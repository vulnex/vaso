package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestParseJSON5ReadsCommentsTrailingCommasAndBareKeys(t *testing.T) {
	v, err := parseConfig("json", []byte("\ufeff// top\n{\n  agents: { defaults: { 'workspace': \"~/ws\", }, },\n  /* block */ list: [1, 0x1F, +2, .5, Infinity, 'a\\'b',],\n  \"esc\": \"\\u00e9\\n\",\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := lookupKeys(v, []string{"agents", "defaults", "workspace"}); !reflect.DeepEqual(got, []interface{}{"~/ws"}) {
		t.Fatalf("workspace: %v", got)
	}
	if got := lookupKeys(v, []string{"list", "*"}); len(got) != 6 || got[5] != "a'b" {
		t.Fatalf("list: %v", got)
	}
	if got := lookupKeys(v, []string{"esc"}); got[0] != "é\n" {
		t.Fatalf("escapes: %q", got)
	}
	for _, bad := range []string{`{"a": }`, `{"a": "x"`, `[1 2]`, strings.Repeat("[", 1000) + strings.Repeat("]", 1000)} {
		if _, err := parseConfig("json", []byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad[:min(len(bad), 20)])
		}
	}
}

func TestParseYAMLSubsetReadsBlockMappingsAndSequences(t *testing.T) {
	doc := `# Hermes
mcp_servers:
  files:   # a comment
    command: /opt/mcp/bin/files   # trailing
    args: [
      "--root", "/srv"
    ]
    env:
      KEY: x
  "quoted name":
    command: '/opt/it''s/bin'
  flow: {command: /flow/bin, args: ["--x", y], env: {A: "b"}}
  folded:
    command: >-
      /opt/folded/bin
  literal:
    command: |
      /opt/literal/bin
  multi:
    command: >
      /two
      lines
  broken: {command: /never/read
  block:
    description: |
      command: /not/a/key
    command: "/opt/block/bin"
servers:
- name: a
  command: /seq/a
-   command: /seq/b
security:
  tirith_path: ~/bin/tirith
  enabled: true
---
second: /doc
`
	v, err := parseConfig("yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := lookupKeys(v, []string{"mcp_servers", "*", "command"})
	want := []interface{}{"/opt/block/bin", "/opt/mcp/bin/files", "/flow/bin", "/opt/folded/bin", "/opt/literal/bin\n", nil, "/opt/it's/bin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands: %v", got)
	}
	if got := lookupKeys(v, []string{"servers", "*", "command"}); !reflect.DeepEqual(got, []interface{}{"/seq/a", "/seq/b"}) {
		t.Fatalf("sequence commands: %v", got)
	}
	if got := lookupKeys(v, []string{"security", "enabled"}); got[0] != true {
		t.Fatalf("boolean: %v", got)
	}
	if got := lookupKeys(v, []string{"second"}); len(got) != 0 {
		t.Fatalf("read past the first document: %v", got)
	}
}

func TestParseTOMLForConfigRoots(t *testing.T) {
	v, err := parseConfig("toml", []byte("[agents.main.workspace]\npath = \"/srv/ws\"\n[agents.\"b.c\"]\nworkspace = { path = '~/b' }\n[skills]\nopen_skills_enabled = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := lookupKeys(v, []string{"agents", "*", "workspace", "path"}); !reflect.DeepEqual(got, []interface{}{"~/b", "/srv/ws"}) {
		t.Fatalf("paths: %v", got)
	}
	if _, err := parseConfig("toml", []byte("[a\n")); err == nil {
		t.Fatal("accepted broken TOML")
	}
}

func TestConfigValuesWhenFallbackAndDefault(t *testing.T) {
	cfg := map[string]interface{}{"skills": map[string]interface{}{"open_skills_enabled": true}}
	req := ConfigRootRequest{Keys: [][]string{{"skills", "open_skills_dir"}}, When: []string{"skills", "open_skills_enabled"}, Default: "~/open-skills"}
	if got := configValues(req, cfg); !reflect.DeepEqual(got, []string{"~/open-skills"}) {
		t.Fatalf("default: %v", got)
	}
	cfg["skills"].(map[string]interface{})["open_skills_enabled"] = false
	if got := configValues(req, cfg); got != nil {
		t.Fatalf("collected although disabled: %v", got)
	}
	t.Setenv("VASO_TEST_WS", "/srv/env-ws")
	env := ConfigRootRequest{Keys: [][]string{{"agents", "defaults", "workspace"}}, EnvFallback: "VASO_TEST_WS"}
	if got := configValues(env, map[string]interface{}{}); !reflect.DeepEqual(got, []string{"/srv/env-ws"}) {
		t.Fatalf("env fallback: %v", got)
	}
}

func TestResolveConfigValue(t *testing.T) {
	src := configSource{path: "/h/.zc/config.toml", home: "/h"}
	t.Setenv("VASO_TEST_DIR", "/srv")
	cases := []struct {
		req  ConfigRootRequest
		in   string
		want string
	}{
		{ConfigRootRequest{}, "~/ws", "/h/ws"},
		{ConfigRootRequest{}, " /abs/./x ", "/abs/x"},
		{ConfigRootRequest{}, "rel", ""},
		{ConfigRootRequest{Relative: "home"}, "rel", "/h/rel"},
		{ConfigRootRequest{Relative: "config"}, "b", "/h/.zc/b"},
		{ConfigRootRequest{ExpandEnv: true}, "${VASO_TEST_DIR}/ws", "/srv/ws"},
		{ConfigRootRequest{ExpandEnv: true}, "${VASO_TEST_UNSET_X}/ws", ""},
	}
	for _, c := range cases {
		got, _ := resolveConfigValue(c.req, c.in, src)
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

// setupHome points HOME at a fresh directory (the probe's scanned home).
func setupHome(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home
}

func write(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestCollectConfigDerivedSkillTree(t *testing.T) {
	home := setupHome(t)
	ws := filepath.Join(home, "elsewhere", "ws")
	write(t, filepath.Join(home, ".nanobot", "config.json"), `{"agents": {"defaults": {"workspace": "`+ws+`"}}}`, 0o644)
	secret := "sk-proj-" + strings.Repeat("Ab3dE", 9)
	write(t, filepath.Join(ws, "skills", "evil", "SKILL.md"), "# evil\nOPENAI_API_KEY="+secret+"\n", 0o644)
	write(t, filepath.Join(ws, "skills", "evil", "dist", "index.js"), "fetch('https://x.example')\n", 0o644)
	write(t, filepath.Join(ws, "skills", "evil", "node_modules", "dep", "index.js"), "x\n", 0o644)
	write(t, filepath.Join(ws, "notes.env"), "TOKEN="+secret+"\n", 0o600)

	snap := Collect(ProbeManifest{
		FilePaths: []string{"~/.nanobot/config.json"},
		ConfigRoots: []ConfigRootRequest{{
			Configs: []string{"~/.nanobot/config.json"}, Format: "json", Kind: "tree",
			Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "plugins/**"}, Relative: "home",
		}},
	}, false)

	skill := snap.Files[filepath.Join(ws, "skills", "evil", "SKILL.md")]
	if !skill.Exists || skill.Content == "" {
		t.Fatalf("config-set skill not collected: %+v", skill)
	}
	if strings.Contains(skill.Content, secret[8:len(secret)-4]) {
		t.Fatal("a secret in a config-derived tree shipped as is")
	}
	if _, ok := snap.Files[filepath.Join(ws, "skills", "evil", "dist", "index.js")]; !ok {
		t.Fatal("build output of a skill not collected")
	}
	if _, ok := snap.Files[filepath.Join(ws, "skills", "evil", "node_modules", "dep", "index.js")]; ok {
		t.Fatal("vendor dir walked")
	}
	if _, ok := snap.Files[filepath.Join(ws, "notes.env")]; ok {
		t.Fatal("collected outside the requested globs")
	}
	if snap.ConfigTrees[filepath.Join(ws, "skills")] != treeCollected || snap.ConfigTrees[filepath.Join(ws, "plugins")] != treeCollected {
		t.Fatalf("tree status: %v", snap.ConfigTrees)
	}
}

func TestConfigDerivedTreesRefuseHomeRootAndCredentialStores(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".openclaw", "openclaw.json"), `{skills: {load: {extraDirs: ["~", "/", "~/.ssh", "/etc/x", "`+filepath.Dir(home)+`", "/usr", "~/link"]}}}`, 0o644)
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "PRIVATE\n", 0o600)
	write(t, filepath.Join(home, "doc.txt"), "x\n", 0o644)
	if err := os.Symlink(home, filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	snap := Collect(ProbeManifest{
		ConfigRoots: []ConfigRootRequest{{
			Configs: []string{"~/.openclaw/openclaw.json"}, Format: "json", Kind: "tree",
			Keys: [][]string{{"skills", "load", "extraDirs", "*"}}, Globs: []string{"**"},
		}},
	}, false)
	for _, base := range []string{home, "/", filepath.Join(home, ".ssh"), "/etc/x", filepath.Dir(home), "/usr", filepath.Join(home, "link")} {
		if snap.ConfigTrees[base] != treeRefused {
			t.Errorf("%s: %q, want refused (%v)", base, snap.ConfigTrees[base], snap.ConfigTrees)
		}
	}
	for p := range snap.Files {
		t.Errorf("collected %s", p)
	}
}

func TestConfigDerivedTreeOverTheEntryLimit(t *testing.T) {
	home := setupHome(t)
	ws := filepath.Join(home, "big")
	for i := 0; i < maxConfigTreeEntries/50+2; i++ {
		dir := filepath.Join(ws, "skills", "s"+strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 49; j++ {
			write(t, filepath.Join(dir, "f"+strconv.Itoa(j)), "x", 0o644)
		}
	}
	write(t, filepath.Join(home, "cfg.json"), `{"ws": "~/big"}`, 0o644)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{{
		Configs: []string{"~/cfg.json"}, Format: "json", Kind: "tree", Keys: [][]string{{"ws"}}, Globs: []string{"skills/**"},
	}}}, false)
	if snap.ConfigTrees[filepath.Join(ws, "skills")] != treeLimit {
		t.Fatalf("status %v", snap.ConfigTrees)
	}
	if len(snap.Files) != 0 {
		t.Fatalf("collected %d files from a tree over the limit", len(snap.Files))
	}
}

func TestConfigDerivedSiblingWorkspaces(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{"agents": {"defaults": {"workspace": "~/ws"}}}`, 0o644)
	write(t, filepath.Join(home, "workspace-coder", "skills", "a", "SKILL.md"), "# a\n", 0o644)
	write(t, filepath.Join(home, "secret.txt"), "x\n", 0o600)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{{
		Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "../workspace-*/skills/**"},
	}}}, false)
	if _, ok := snap.Files[filepath.Join(home, "workspace-coder", "skills", "a", "SKILL.md")]; !ok {
		t.Fatalf("sibling workspace skill not collected (%v)", snap.ConfigTrees)
	}
	// recorded under the literal match, never a glob
	if snap.ConfigTrees[filepath.Join(home, "workspace-coder", "skills")] != treeCollected || len(snap.ConfigTrees) != 2 {
		t.Fatalf("status %v", snap.ConfigTrees)
	}
	if _, ok := snap.Directories[home]; ok {
		t.Fatal("listed the home")
	}
	if _, ok := snap.Files[filepath.Join(home, "secret.txt")]; ok {
		t.Fatal("collected the home itself")
	}
}

func TestConfigNamedCommandsAreStatOnly(t *testing.T) {
	home := setupHome(t)
	bin := filepath.Join(filepath.Dir(home), "shared", "bin")
	cmd := filepath.Join(bin, "server")
	write(t, cmd, "#!/bin/sh\nTOKEN=secret-content-never-shipped\n", 0o777)
	if err := os.Chmod(cmd, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".hermes", "config.yaml"), "mcp_servers:\n  a:\n    command: "+cmd+"\n  b:\n    command: /nonexistent/vaso/cmd\n  c:\n    command: npx\nsecurity:\n  tirith_path: ~/tools/tirith\n", 0o644)
	write(t, filepath.Join(home, "tools", "tirith"), "binary", 0o755)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{
		{Configs: []string{"~/.hermes/config.yaml"}, Format: "yaml", Kind: "stat", Keys: [][]string{{"mcp_servers", "*", "command"}}},
		{Configs: []string{"~/.hermes/config.yaml"}, Format: "yaml", Kind: "stat", Keys: [][]string{{"security", "tirith_path"}}},
	}}, false)
	e := snap.Files[cmd]
	if !e.Exists || e.Content != "" || !e.ContentOmitted || e.Mode&0o002 == 0 {
		t.Fatalf("command entry: %+v", e)
	}
	if snap.DirectoryModes[bin]&0o002 == 0 {
		t.Fatalf("command dir mode not recorded: %v", snap.DirectoryModes[bin])
	}
	if e, ok := snap.Files["/nonexistent/vaso/cmd"]; !ok || e.Exists {
		t.Fatalf("absent command not recorded as looked for: %+v", e)
	}
	if _, ok := snap.Files["npx"]; ok {
		t.Fatal("a bare command name was stat'd")
	}
	if e := snap.Files[filepath.Join(home, "tools", "tirith")]; !e.Exists || e.Content != "" {
		t.Fatalf("tirith_path: %+v", e)
	}
}

func TestExplicitSymlinkedFileRecordsLinkAndRealParents(t *testing.T) {
	home := setupHome(t)
	open := filepath.Join(filepath.Dir(home), "open")
	write(t, filepath.Join(open, "cred.json"), "{}", 0o644)
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".app"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".app", "cred.json")
	if err := os.Symlink(filepath.Join(open, "cred.json"), link); err != nil {
		t.Fatal(err)
	}
	// a symlinked config directory below the home
	write(t, filepath.Join(open, "cfgdir", "settings.json"), "{}", 0o644)
	if err := os.Symlink(filepath.Join(open, "cfgdir"), filepath.Join(home, ".cfg")); err != nil {
		t.Fatal(err)
	}

	snap := Collect(ProbeManifest{FilePaths: []string{"~/.app/cred.json", "~/.cfg/settings.json"}}, false)
	if snap.Symlinks[link] != filepath.Join(open, "cred.json") {
		t.Fatalf("explicit file link not recorded: %v", snap.Symlinks)
	}
	if snap.Symlinks[filepath.Join(home, ".cfg")] != filepath.Join(open, "cfgdir") {
		t.Fatalf("symlinked directory below the home not recorded: %v", snap.Symlinks)
	}
	if _, ok := snap.DirectoryModes[open]; !ok {
		t.Fatalf("real parent mode not recorded: %v", snap.DirectoryModes)
	}
	if got := resolveRecordedLinks(filepath.Join(home, ".cfg", "settings.json"), snap.Symlinks); got != filepath.Join(open, "cfgdir", "settings.json") {
		t.Fatalf("resolved %s", got)
	}
	// the home itself and the directories above it are never resolved
	if _, ok := snap.Symlinks[home]; ok {
		t.Fatal("recorded a link above the home")
	}
}

func TestConfigDerivedTreeKeepsMetadataOnlyStoresMetadata(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".openclaw", "openclaw.json"), `{skills: {load: {extraDirs: ["~/.agent"]}}}`, 0o644)
	write(t, filepath.Join(home, ".agent", "sessions", "s1.jsonl"), "private conversation\n", 0o600)
	write(t, filepath.Join(home, ".agent", "tool", "SKILL.md"), "# tool\n", 0o644)
	snap := Collect(ProbeManifest{
		MetadataGlobPatterns: []string{"~/.agent/sessions/*"},
		ConfigRoots: []ConfigRootRequest{{
			Configs: []string{"~/.openclaw/openclaw.json"}, Format: "json", Kind: "tree",
			Keys: [][]string{{"skills", "load", "extraDirs", "*"}}, Globs: []string{"**"},
		}},
	}, false)
	if e := snap.Files[filepath.Join(home, ".agent", "sessions", "s1.jsonl")]; !e.ContentOmitted || e.Content != "" {
		t.Fatalf("a metadata-only store inside a config tree shipped content: %+v", e)
	}
	if e := snap.Files[filepath.Join(home, ".agent", "tool", "SKILL.md")]; e.Content == "" {
		t.Fatalf("skill not collected: %+v", e)
	}
}
