package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func extraDirsManifest(dirs ...string) ProbeManifest {
	return ProbeManifest{ConfigRoots: []ConfigRootRequest{{
		Configs: []string{"~/.openclaw/openclaw.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"skills", "load", "extraDirs", "*"}}, Globs: []string{"**"},
	}}}
}

func writeExtraDirs(t *testing.T, home string, dirs ...string) {
	t.Helper()
	quoted := make([]string, len(dirs))
	for i, d := range dirs {
		quoted[i] = strconv.Quote(d)
	}
	write(t, filepath.Join(home, ".openclaw", "openclaw.json"), `{skills: {load: {extraDirs: [`+strings.Join(quoted, ", ")+`]}}}`, 0o644)
}

func TestTreeAllowedOnlyStrictlyInsideTheHomeAndOutsideStores(t *testing.T) {
	home := setupHome(t)
	other := filepath.Join(filepath.Dir(home), "other")
	write(t, filepath.Join(other, "skills", "a", "SKILL.md"), "# a\n", 0o644)
	mustSymlink(t, other, filepath.Join(home, "to-other"))
	mustSymlink(t, "/etc", filepath.Join(home, "to-etc"))
	if err := os.MkdirAll(filepath.Join(home, "work", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{filepath.Join(home, "work", "skills"), true},
		{filepath.Join(home, "missing", "skills"), true},
		{home, false},
		{filepath.Dir(home), false},
		{"/", false},
		{"/etc", false},
		{"/private/etc", false},
		{"/usr/share", false},
		{other, false},
		{filepath.Join(home, "to-other"), false},
		{filepath.Join(home, "to-etc"), false},
		{filepath.Join(home, "work", "..", ".."), false},
		{filepath.Join(home, ".ssh"), false},
		{filepath.Join(home, ".config", "gh"), false},
		{filepath.Join(home, ".config", "gcloud", "x"), false},
		{filepath.Join(home, ".azure"), false},
		{filepath.Join(home, ".password-store"), false},
		{filepath.Join(home, "Library", "Keychains"), false},
		{filepath.Join(home, ".mozilla", "firefox"), false},
		{filepath.Join(home, "Library", "Application Support", "Google", "Chrome"), false},
	} {
		if got := treeAllowed(c.p, home); got != c.want {
			t.Errorf("treeAllowed(%s) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestConfigTreesOutsideTheHomeShipNothing(t *testing.T) {
	home := setupHome(t)
	other := filepath.Join(filepath.Dir(home), "otheruser")
	write(t, filepath.Join(other, "notes", "secret.md"), "OTHER-USER-CANARY\n", 0o644)
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "oauth_token: GH-CANARY\n", 0o600)
	mustSymlink(t, "/private/etc", filepath.Join(home, "etc-link"))
	writeExtraDirs(t, home, "/private/etc", "/etc", other, "~/.config/gh", "~/.config", "~/etc-link")
	snap := Collect(extraDirsManifest(), false)
	for _, base := range []string{"/private/etc", "/etc", other, filepath.Join(home, ".config", "gh"), filepath.Join(home, "etc-link")} {
		if snap.ConfigTrees[base] != treeRefused {
			t.Errorf("%s: %q, want refused", base, snap.ConfigTrees[base])
		}
	}
	for p, e := range snap.Files {
		if strings.HasPrefix(p, "/private/etc") || strings.HasPrefix(p, "/etc") || strings.HasPrefix(p, other) || strings.Contains(p, filepath.Join(".config", "gh")) {
			if e.Content != "" {
				t.Errorf("content shipped for %s", p)
			}
		}
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("canary shipped in %s", p)
		}
	}
}

func TestLinksInsideAConfigTreeStayInsideTheHome(t *testing.T) {
	home := setupHome(t)
	outside := filepath.Join(filepath.Dir(home), "outside")
	write(t, filepath.Join(outside, "lib", "evil.js"), "OUTSIDE-CANARY\n", 0o644)
	write(t, filepath.Join(outside, "one.js"), "OUTSIDE-FILE-CANARY\n", 0o644)
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "GH-CANARY\n", 0o600)
	tree := filepath.Join(home, "tree")
	write(t, filepath.Join(tree, "s", "SKILL.md"), "# s\n", 0o644)
	mustSymlink(t, "/private/etc", filepath.Join(tree, "s", "etc"))
	mustSymlink(t, "/etc", filepath.Join(tree, "s", "etc2"))
	mustSymlink(t, filepath.Join(outside, "lib"), filepath.Join(tree, "s", "lib"))
	mustSymlink(t, filepath.Join(outside, "one.js"), filepath.Join(tree, "s", "one.js"))
	mustSymlink(t, filepath.Join(home, ".config", "gh"), filepath.Join(tree, "s", "gh"))
	mustSymlink(t, home, filepath.Join(tree, "s", "home"))
	writeExtraDirs(t, home, "~/tree")
	snap := Collect(extraDirsManifest(), false)
	if snap.ConfigTrees[tree] != treeCollected {
		t.Fatalf("status %v", snap.ConfigTrees)
	}
	if e := snap.Files[filepath.Join(tree, "s", "SKILL.md")]; e.Content == "" {
		t.Fatal("skill not collected")
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") || strings.Contains(e.Content, "root:") {
			t.Errorf("content behind a link shipped: %s", p)
		}
	}
	if _, ok := snap.Files[filepath.Join(tree, "s", "one.js")]; ok {
		t.Error("file link out of the home recorded")
	}
	// …but every link is recorded by name and target, as a local walk sees
	// it: SKL-013 reports a link into a credential store or out of the home
	for _, n := range []string{"etc", "etc2", "lib", "one.js", "gh", "home"} {
		if _, ok := snap.Symlinks[filepath.Join(tree, "s", n)]; !ok {
			t.Errorf("link %s not recorded: %v", n, snap.Symlinks)
		}
	}
}

// A link met inside a linked directory of a config tree is recorded too,
// even when it leads somewhere the walk never goes.
func TestLinksInALinkedDirOfAConfigTreeAreRecorded(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), "KEY-CANARY\n", 0o600)
	lib := filepath.Join(home, "lib")
	write(t, filepath.Join(lib, "x.js"), "module.exports = 1\n", 0o644)
	mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(lib, "keys"))
	tree := filepath.Join(home, "tree")
	write(t, filepath.Join(tree, "s", "SKILL.md"), "# s\n", 0o644)
	mustSymlink(t, lib, filepath.Join(tree, "s", "lib"))
	writeExtraDirs(t, home, "~/tree")
	snap := Collect(extraDirsManifest(), false)
	if _, ok := snap.Files[filepath.Join(tree, "s", "lib", "x.js")]; !ok {
		t.Fatal("linked directory not walked")
	}
	if _, ok := snap.Symlinks[filepath.Join(tree, "s", "lib", "keys")]; !ok {
		t.Fatalf("link into ~/.ssh not recorded: %v", snap.Symlinks)
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("content behind a link shipped: %s", p)
		}
	}
}

func TestConfigTreeCountFollowsLinksLikeTheWalk(t *testing.T) {
	home := setupHome(t)
	small := filepath.Join(home, "small")
	for i := 0; i < 11; i++ {
		write(t, filepath.Join(small, "s", "f"+strconv.Itoa(i)+".js"), "x", 0o644)
	}
	huge := filepath.Join(home, "outside-huge")
	for i := 0; i < maxConfigTreeEntries/100+1; i++ {
		dir := filepath.Join(huge, "d"+strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 100; j++ {
			if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(j)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mustSymlink(t, huge, filepath.Join(small, "s", "huge"))
	writeExtraDirs(t, home, "~/small")
	snap := Collect(extraDirsManifest(), false)
	if snap.ConfigTrees[small] != treeLimit {
		t.Fatalf("a link past the entry limit: %v", snap.ConfigTrees)
	}
	if len(snap.Files) > 1 { // the config itself is not in the manifest
		t.Fatalf("collected %d files", len(snap.Files))
	}
}

func TestCredentialNamedFilesInConfigTreesAreMetadataOnly(t *testing.T) {
	home := setupHome(t)
	tree := filepath.Join(home, "tree")
	bare := strings.Repeat("9f3a", 16)
	write(t, filepath.Join(tree, "s", "token"), bare+"\n", 0o600)
	write(t, filepath.Join(tree, "s", "server.key"), bare+"\n", 0o600)
	write(t, filepath.Join(tree, "s", "credentials.json"), `{"x": "`+bare+`"}`, 0o600)
	write(t, filepath.Join(tree, "s", "tokens"), "#!/bin/sh\necho hi\n", 0o755)
	write(t, filepath.Join(tree, "s", "tokenizer.js"), "module.exports = 1\n", 0o644)
	writeExtraDirs(t, home, "~/tree")
	snap := Collect(extraDirsManifest(), false)
	for _, n := range []string{"token", "server.key", "credentials.json"} {
		if e := snap.Files[filepath.Join(tree, "s", n)]; !e.Exists || e.Content != "" || e.Omitted != "metadata" {
			t.Errorf("%s: %+v", n, e)
		}
	}
	for _, n := range []string{"tokens", "tokenizer.js"} {
		if e := snap.Files[filepath.Join(tree, "s", n)]; e.Content == "" {
			t.Errorf("%s not collected: %+v", n, e)
		}
	}
}

func TestWildcardConfigTreeListsWhatItRangesOver(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{}`, 0o644)
	write(t, filepath.Join(home, ".picoclaw", "workspace-a", "skills", "x", "SKILL.md"), "# x\n", 0o644)
	if err := os.MkdirAll(filepath.Join(home, ".picoclaw", "workspace-b"), 0o755); err != nil {
		t.Fatal(err)
	}
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{{
		Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"agents", "defaults", "workspace"}}, Default: "", Globs: []string{"skills/**", "../workspace-*/skills/**"},
		EnvFallback: "VASO_TEST_PICO_WS",
	}}}, false)
	_ = snap
	t.Setenv("VASO_TEST_PICO_WS", filepath.Join(home, ".picoclaw", "workspace"))
	snap = Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{{
		Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "../workspace-*/skills/**"},
		EnvFallback: "VASO_TEST_PICO_WS",
	}}}, false)
	if snap.ConfigTrees[filepath.Join(home, ".picoclaw", "workspace-a", "skills")] != treeCollected {
		t.Fatalf("status %v", snap.ConfigTrees)
	}
	for k := range snap.ConfigTrees {
		if strings.ContainsAny(k, "*?[{") {
			t.Fatalf("glob key %s", k)
		}
	}
	if l, ok := snap.Directories[filepath.Join(home, ".picoclaw")]; !ok || len(l) == 0 {
		t.Fatalf("wildcard parent not listed: %v", snap.Directories)
	}
	if _, ok := snap.Directories[filepath.Join(home, ".picoclaw", "workspace-b")]; !ok {
		t.Fatalf("wildcard match not listed: %v", snap.Directories)
	}
}

// A credential collected by a glob through a chain of links: the whole chain
// is recorded, so the CLI judges the real parents (p-C, p-H).
func TestGlobbedCredentialRecordsTheWholeLinkChain(t *testing.T) {
	home := setupHome(t)
	open := filepath.Join(home, "open")
	write(t, filepath.Join(open, "auth.json"), "{}", 0o644)
	priv := filepath.Join(home, "priv")
	if err := os.MkdirAll(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	// p-C: file link → file link (private dir) → open file
	mustSymlink(t, filepath.Join(open, "auth.json"), filepath.Join(priv, "auth.json"))
	mustSymlink(t, filepath.Join(priv, "auth.json"), filepath.Join(home, ".codex", "auth.json"))
	// p-H: file link → path through a directory link (in the private dir)
	mustSymlink(t, open, filepath.Join(priv, "lnk"))
	mustSymlink(t, filepath.Join(priv, "lnk", "auth.json"), filepath.Join(home, ".zc", "auth.json"))
	if err := os.Chmod(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	snap := Collect(ProbeManifest{MetadataGlobPatterns: []string{"~/.codex/auth.json", "~/.zc/*.json"}}, false)
	for _, p := range []string{filepath.Join(home, ".codex", "auth.json"), filepath.Join(home, ".zc", "auth.json")} {
		if got := resolveRecordedLinks(p, snap.Symlinks); got != filepath.Join(open, "auth.json") {
			t.Errorf("%s resolves to %s through the recorded links (%v)", p, got, snap.Symlinks)
		}
	}
	if _, ok := snap.DirectoryModes[open]; !ok {
		t.Fatalf("real parent mode not recorded")
	}
}

// A per-agent workspace that is a link (`workspace-<id>` → elsewhere): the
// no-follow glob can't enter it, so it is walked as a config-derived tree
// when it stays inside the home, and recorded refused otherwise — both for
// the manifest's own glob and a config-derived wildcard base.
func TestLinkedWildcardWorkspacesAreWalkedOrRefused(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, "realws", "skills", "e", "SKILL.md"), "# e\n", 0o644)
	outside := filepath.Join(filepath.Dir(home), "elsewhere")
	write(t, filepath.Join(outside, "skills", "o", "SKILL.md"), "OUTSIDE-CANARY\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "skills", "k", "SKILL.md"), "SSH-CANARY\n", 0o600)
	for _, dir := range []string{".picoclaw", "pc"} {
		mustSymlink(t, filepath.Join(home, "realws"), filepath.Join(home, dir, "workspace-lnk"))
		mustSymlink(t, outside, filepath.Join(home, dir, "workspace-out"))
		mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(home, dir, "workspace-ssh"))
	}
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{agents: {defaults: {workspace: "~/pc/workspace"}}}`, 0o644)
	snap := Collect(ProbeManifest{
		GlobPatterns: []string{"~/.picoclaw/workspace-*/skills/**"},
		ConfigRoots: []ConfigRootRequest{{
			Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
			Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "../workspace-*/skills/**"},
		}},
	}, false)
	for _, dir := range []string{".picoclaw", "pc"} {
		lnk := filepath.Join(home, dir, "workspace-lnk", "skills")
		if snap.ConfigTrees[lnk] != treeCollected {
			t.Errorf("%s: %q, want collected", lnk, snap.ConfigTrees[lnk])
		}
		if e := snap.Files[filepath.Join(lnk, "e", "SKILL.md")]; e.Content == "" {
			t.Errorf("%s: skill behind the link not collected", dir)
		}
		for _, n := range []string{"workspace-out", "workspace-ssh"} {
			if p := filepath.Join(home, dir, n, "skills"); snap.ConfigTrees[p] != treeRefused {
				t.Errorf("%s: %q, want refused", p, snap.ConfigTrees[p])
			}
		}
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("content behind a refused link shipped: %s", p)
		}
	}
}

// A config-set skill root whose name holds glob metacharacters is walked as
// the literal directory it is.
func TestConfigTreeWithGlobCharactersInItsName(t *testing.T) {
	home := setupHome(t)
	names := []string{"ws{1}", "ws[2]", "ws*3", "ws?4"}
	for _, d := range names {
		write(t, filepath.Join(home, d, "s", "SKILL.md"), "# s\n", 0o644)
	}
	write(t, filepath.Join(home, "ws1", "s", "SKILL.md"), "# decoy\n", 0o644)
	writeExtraDirs(t, home, "~/ws{1}", "~/ws[2]", "~/ws*3", "~/ws?4")
	snap := Collect(extraDirsManifest(), false)
	for _, d := range names {
		base := filepath.Join(home, d)
		if snap.ConfigTrees[base] != treeCollected {
			t.Errorf("%s: %q, want collected", d, snap.ConfigTrees[base])
		}
		if e := snap.Files[filepath.Join(base, "s", "SKILL.md")]; e.Content == "" {
			t.Errorf("%s: skill not collected", d)
		}
	}
	if _, ok := snap.Files[filepath.Join(home, "ws1", "s", "SKILL.md")]; ok {
		t.Error("a metacharacter matched another directory")
	}
}
