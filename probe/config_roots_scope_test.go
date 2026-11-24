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

func TestTreeAllowedRefusesHomesOSDirectoriesAndStores(t *testing.T) {
	home := setupHome(t)
	other := allowedOutside(t)
	write(t, filepath.Join(other, "skills", "a", "SKILL.md"), "# a\n", 0o644)
	mustSymlink(t, other, filepath.Join(home, "to-other"))
	mustSymlink(t, "/etc", filepath.Join(home, "to-etc"))
	mustSymlink(t, "/usr/share", filepath.Join(home, "to-usr"))
	write(t, filepath.Join(home, ".ssh", "config"), "Host x\n", 0o600)
	mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(other, "to-ssh"))
	if err := os.MkdirAll(filepath.Join(home, "work", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    string
		want bool
	}{
		{filepath.Join(home, "work", "skills"), true},
		{filepath.Join(home, "missing", "skills"), true},
		{other, true},
		{filepath.Join(home, "to-other"), true},
		{filepath.Join(other, "missing"), true},
		{"/opt/team-skills", true},
		{"/srv/skills", true},
		{"/nix/store/abc-hm/skills", true},
		{"/Volumes/Team/skills", true},
		{"/mnt/data/skills", true},
		{"/media/usb/skills", true},
		{home, false},
		{filepath.Dir(home), false},
		{"/", false},
		{"/etc", false},
		{"/private/etc", false},
		{"/usr/share", false},
		{"/var/lib/skills", false},
		{"/private/var/skills", false},
		{"/System/Library", false},
		{"/Library/skills", false},
		{"/lib64/skills", false},
		{"/home", false},
		{"/home/someone-else/skills", false},
		{"/Users/someone-else/skills", false},
		{"/root/skills", false},
		{filepath.Join(home, "to-etc"), false},
		{filepath.Join(home, "to-usr"), false},
		{filepath.Join(other, "to-ssh"), false},
		{filepath.Join(other, ".ssh"), false},
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

// Refused config trees (an OS directory, the area of other users' homes, a
// credential store) record their existence and nothing else.
func TestConfigTreesInRefusedPlacesShipNothing(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "oauth_token: GH-CANARY\n", 0o600)
	mustSymlink(t, "/private/etc", filepath.Join(home, "etc-link"))
	homes := "/home"
	if _, err := os.Stat("/Users"); err == nil {
		homes = "/Users"
	}
	writeExtraDirs(t, home, "/private/etc", "/etc", "/usr/share", homes, "~/.config/gh", "~/.config", "~/etc-link")
	snap := Collect(extraDirsManifest(), false)
	refused := []string{"/private/etc", "/etc", "/usr/share", homes, filepath.Join(home, ".config", "gh"), filepath.Join(home, "etc-link")}
	for _, base := range refused {
		if snap.ConfigTrees[base] != treeRefused {
			t.Errorf("%s: %q, want refused", base, snap.ConfigTrees[base])
		}
		if _, ok := snap.Directories[base]; ok {
			t.Errorf("%s listed", base)
		}
	}
	// its existence is recorded (a mode), never a listing
	for _, base := range []string{"/etc", "/usr/share", filepath.Join(home, ".config", "gh"), filepath.Join(home, "etc-link")} {
		if _, ok := snap.DirectoryModes[base]; !ok {
			t.Errorf("%s: existence not recorded", base)
		}
	}
	for p, e := range snap.Files {
		for _, base := range refused[:4] {
			if strings.HasPrefix(p, base+"/") && e.Content != "" {
				t.Errorf("content shipped for %s", p)
			}
		}
		if strings.Contains(e.Content, "CANARY") {
			t.Errorf("canary shipped in %s", p)
		}
	}
}

// A config tree's links are followed where a skills tree may be walked (out
// of the home too) — never into an OS directory, the home itself or a
// credential store.
func TestLinksInsideAConfigTreeFollowTheScope(t *testing.T) {
	home := setupHome(t)
	outside := allowedOutside(t)
	write(t, filepath.Join(outside, "lib", "evil.js"), "eval(atob(x))\n", 0o644)
	write(t, filepath.Join(outside, "one.js"), "require('child_process')\n", 0o644)
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "GH-CANARY\n", 0o600)
	tree := filepath.Join(home, "tree")
	write(t, filepath.Join(tree, "s", "SKILL.md"), "# s\n", 0o644)
	mustSymlink(t, "/private/etc", filepath.Join(tree, "s", "etc"))
	mustSymlink(t, "/etc", filepath.Join(tree, "s", "etc2"))
	mustSymlink(t, "/usr/share", filepath.Join(tree, "s", "share"))
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
	if e := snap.Files[filepath.Join(tree, "s", "lib", "evil.js")]; e.Content == "" {
		t.Error("a link to a directory out of the home is not followed")
	}
	if e := snap.Files[filepath.Join(tree, "s", "one.js")]; e.Content == "" {
		t.Error("a file link out of the home is not read")
	}
	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") || strings.Contains(e.Content, "root:") {
			t.Errorf("content behind a link shipped: %s", p)
		}
		for _, n := range []string{"etc", "etc2", "share", "gh", "home"} {
			if strings.HasPrefix(p, filepath.Join(tree, "s", n)+"/") {
				t.Errorf("walked into %s: %s", n, p)
			}
		}
	}
	// ...and every link is recorded by name and target, as a local walk sees
	// it: SKL-013 reports a link into a credential store or out of the home
	for _, n := range []string{"etc", "etc2", "share", "lib", "one.js", "gh", "home"} {
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

func TestConfigTreeJudgesItsLinksOnTheirOwn(t *testing.T) {
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
	// The link is judged on its own, not counted against the tree it is in:
	// the tree is collected, the link past the entry limit is not followed
	if snap.ConfigTrees[small] != treeCollected {
		t.Fatalf("the tree holding a link past the entry limit: %v", snap.ConfigTrees)
	}
	link := filepath.Join(small, "s", "huge")
	if snap.ConfigTrees[link] != treeLimit {
		t.Fatalf("a link past the entry limit: %q", snap.ConfigTrees[link])
	}
	if _, ok := snap.Files[filepath.Join(small, "s", "f0.js")]; !ok {
		t.Error("the tree's own files not collected")
	}
	if shippedUnder(snap, link) || shippedUnder(snap, huge) {
		t.Fatal("collected behind a link past the entry limit")
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
	// an executable bit alone doesn't make a key or a token file a program
	write(t, filepath.Join(tree, "s", "id_ed25519"), "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ"+bare+"\n", 0o755)
	write(t, filepath.Join(tree, "s", "secrets.json"), `{"x": "`+bare+`"}`, 0o755)
	// files that are sensitive sinks themselves (like .netrc) are not walked
	// at all, here or locally (skill-root-scope.ts)
	sinks := []string{".vault-token", ".psql_history", ".bash_history", ".mysql_history", ".netrc",
		".histfile", ".lesshst", ".irb_history", ".Rhistory"}
	for _, n := range sinks {
		write(t, filepath.Join(tree, "s", n), "hvs.Q7rT2mZ9kLp4Vw8NcB1dYh6J PASSWORD 'pw-"+bare+"'\n", 0o600)
	}
	stores := []string{"login.keyring",
		"Cookies", "Login Data", "Web Data", "key4.db", "logins.json",
		filepath.Join("keyrings", "user.keystore2"), filepath.Join("keyrings", "default")}
	for _, n := range stores {
		write(t, filepath.Join(tree, "s", n), "hvs.Q7rT2mZ9kLp4Vw8NcB1dYh6J PASSWORD 'pw-"+bare+"'\n", 0o600)
	}
	writeExtraDirs(t, home, "~/tree")
	snap := Collect(extraDirsManifest(), false)
	for _, n := range append([]string{"token", "server.key", "credentials.json", "id_ed25519", "secrets.json"}, stores...) {
		if e := snap.Files[filepath.Join(tree, "s", n)]; !e.Exists || e.Content != "" || e.Omitted != "metadata" {
			t.Errorf("%s: %+v", n, e)
		}
	}
	for _, n := range sinks {
		if e, ok := snap.Files[filepath.Join(tree, "s", n)]; ok && (e.Content != "" || e.Exists && e.Omitted == "") {
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
// where a skills tree may be walked (in the home or out of it), and recorded
// refused otherwise — both for the manifest's own glob and a config-derived
// wildcard base.
func TestLinkedWildcardWorkspacesAreWalkedOrRefused(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, "realws", "skills", "e", "SKILL.md"), "# e\n", 0o644)
	outside := allowedOutside(t)
	write(t, filepath.Join(outside, "skills", "o", "SKILL.md"), "# o\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "skills", "k", "SKILL.md"), "SSH-CANARY\n", 0o600)
	mustSymlink(t, "/usr/share", filepath.Join(home, "usrws", "skills"))
	for _, dir := range []string{".picoclaw", "pc"} {
		mustSymlink(t, filepath.Join(home, "realws"), filepath.Join(home, dir, "workspace-lnk"))
		mustSymlink(t, outside, filepath.Join(home, dir, "workspace-out"))
		mustSymlink(t, filepath.Join(home, ".ssh"), filepath.Join(home, dir, "workspace-ssh"))
		mustSymlink(t, filepath.Join(home, "usrws"), filepath.Join(home, dir, "workspace-usr"))
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
		for _, c := range [][2]string{{"workspace-lnk", "e"}, {"workspace-out", "o"}} {
			lnk := filepath.Join(home, dir, c[0], "skills")
			if snap.ConfigTrees[lnk] != treeCollected {
				t.Errorf("%s: %q, want collected", lnk, snap.ConfigTrees[lnk])
			}
			if e := snap.Files[filepath.Join(lnk, c[1], "SKILL.md")]; e.Content == "" {
				t.Errorf("%s: skill behind the link %s not collected", dir, c[0])
			}
		}
		for _, n := range []string{"workspace-ssh", "workspace-usr"} {
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

// A workspace set through a link to the home (or a home that is a link, with
// the workspace spelled the real way): the home spelled the other way is
// never listed, but where it resolves is recorded, so the CLI tells derived
// workspace-<id> siblings spelled that way are in the home.
func TestHomeSpelledTheOtherWayRecordsItsResolution(t *testing.T) {
	home := setupHome(t)
	link := filepath.Join(filepath.Dir(home), "homelink")
	mustSymlink(t, home, link)
	write(t, filepath.Join(home, "myws", "skills", "x", "SKILL.md"), "# x\n", 0o644)
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{"agents": {"defaults": {"workspace": "`+filepath.Join(link, "myws")+`"}}}`, 0o644)
	req := ConfigRootRequest{
		Configs: []string{"~/.picoclaw/config.json"}, Format: "json", Kind: "tree",
		Keys: [][]string{{"agents", "defaults", "workspace"}}, Globs: []string{"skills/**", "../workspace-*/skills/**"},
	}
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{req}}, false)
	if got := snap.ResolvedDirs[link]; got != home {
		t.Fatalf("resolvedDirs %v, want %s → %s", snap.ResolvedDirs, link, home)
	}
	if _, listed := snap.Directories[link]; listed {
		t.Fatal("home listed under its other spelling")
	}
	if _, listed := snap.Directories[home]; listed {
		t.Fatal("home listed")
	}

	// the home itself a link
	t.Setenv("HOME", link)
	write(t, filepath.Join(home, ".picoclaw", "config.json"), `{"agents": {"defaults": {"workspace": "`+filepath.Join(home, "myws")+`"}}}`, 0o644)
	snap = Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{req}}, false)
	if got := snap.ResolvedDirs[link]; got != home {
		t.Fatalf("resolvedDirs %v, want the home %s → %s", snap.ResolvedDirs, link, home)
	}
	if _, ok := snap.ResolvedDirs[home]; ok {
		t.Fatal("a directory recorded resolving to itself")
	}
}
