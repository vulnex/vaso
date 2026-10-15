package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInExcludedDirOnlyBelowPatternBase(t *testing.T) {
	cases := []struct {
		pattern, match string
		want           bool
	}{
		{"/home/u/.claude/skills/**", "/home/u/.claude/skills/x/node_modules/a/index.js", true},
		{"/home/u/.claude/skills/**", "/home/u/.claude/skills/x/.git/config", true},
		{"/home/u/.claude/skills/**", "/home/u/.claude/skills/x/src/index.js", false},
		// A user or path segment named "build" above the glob base doesn't count
		{"/home/build/.claude/skills/**", "/home/build/.claude/skills/x/SKILL.md", false},
		// A pattern that names node_modules on purpose (npm package version globs)
		{"/home/u/.nvm/versions/node/*/lib/node_modules/@google/gemini-cli/package.json",
			"/home/u/.nvm/versions/node/v22/lib/node_modules/@google/gemini-cli/package.json", false},
	}
	for _, c := range cases {
		if got := inExcludedDir(c.pattern, c.match); got != c.want {
			t.Errorf("inExcludedDir(%q, %q) = %v, want %v", c.pattern, c.match, got, c.want)
		}
	}
}

func TestCollectFileMetadataOnlyAndBudget(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	code := write("a.js", "console.log(1)")
	img := write("logo.png", "PNGDATA")
	big := write("b.js", "0123456789")

	c := &collector{budget: 20}
	if e := c.collectFile(code, false); e.Content != "console.log(1)" || e.ContentOmitted {
		t.Fatalf("code file content not collected: %+v", e)
	}
	if e := c.collectFile(img, false); e.Content != "" || !e.ContentOmitted || e.Mode != 0o600 {
		t.Fatalf("binary asset should be metadata-only: %+v", e)
	}
	if e := c.collectFile(code, true); !e.ContentOmitted || e.Content != "" {
		t.Fatalf("metadata-only request returned content: %+v", e)
	}
	// 14 bytes spent of 20; a 10-byte file no longer fits
	if e := c.collectFile(big, false); !e.ContentOmitted || !c.truncated {
		t.Fatalf("budget not enforced: %+v truncated=%v", e, c.truncated)
	}
}

func TestCollectPathAllowsLargeExplicitConfigs(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("x"), 6<<20) // over the 5 MiB glob limit
	cfg := filepath.Join(dir, "config.json")
	bin := filepath.Join(dir, "agent")
	for _, p := range []string{cfg, bin} {
		if err := os.WriteFile(p, big, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	snap := ProbeSnapshot{Files: map[string]FileEntry{}, Directories: map[string][]string{}, DirectoryModes: map[string]int{}}
	c := &collector{budget: 64 << 20}
	c.collectPath(&snap, cfg, false, true) // explicit filePath
	c.collectPath(&snap, bin, false, true) // explicit, but not a config
	if e := snap.Files[cfg]; e.ContentOmitted || len(e.Content) != len(big) {
		t.Fatalf("explicit config over 5 MiB not collected: omitted=%v len=%d", e.ContentOmitted, len(e.Content))
	}
	if !snap.Files[bin].ContentOmitted {
		t.Fatalf("explicit non-config over 5 MiB should stay omitted")
	}
	glob := ProbeSnapshot{Files: map[string]FileEntry{}, Directories: map[string][]string{}, DirectoryModes: map[string]int{}}
	c.collectPath(&glob, cfg, false, false) // glob match
	if !glob.Files[cfg].ContentOmitted {
		t.Fatalf("glob match over 5 MiB should stay omitted")
	}
}

func TestCollectPathRecordsDirectoriesAndAncestors(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "Library", "App Support", "com.example")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "Library"), 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(root, "Library"), 0o755)
	file := filepath.Join(dataDir, "prefs.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := ProbeSnapshot{Files: map[string]FileEntry{}, Directories: map[string][]string{}, DirectoryModes: map[string]int{}}
	c := &collector{budget: 1 << 20}
	c.collectPath(&snap, dataDir, false, true) // a directory requested as a "file path"
	c.collectPath(&snap, file, false, false)
	recordAncestorModes(&snap)

	if _, isFile := snap.Files[dataDir]; isFile {
		t.Fatalf("directory recorded as a file entry")
	}
	if snap.DirectoryModes[dataDir] != 0o755 || len(snap.Directories[dataDir]) != 1 {
		t.Fatalf("directory mode/listing missing: mode=%o listing=%v", snap.DirectoryModes[dataDir], snap.Directories[dataDir])
	}
	if snap.DirectoryModes[filepath.Join(root, "Library")] != 0o700 {
		t.Fatalf("ancestor mode not recorded: %v", snap.DirectoryModes)
	}
}

func TestCollectEnvRedactsCredentials(t *testing.T) {
	t.Setenv("VASOTEST_API_KEY", "sk-live-secret")
	t.Setenv("VASOTEST_BOT_TOKEN", "123:abc")
	t.Setenv("VASOTEST_KEY_PASSPHRASE", "hunter2")
	t.Setenv("VASOTEST_HOME", "/srv/agent")
	t.Setenv("VASOTEST_BASE_URL", "http://127.0.0.1:11434")
	t.Setenv("VASOTEST_SSH_KEY_PATH", "/srv/keys/agent.key")
	t.Setenv("VASOTEST_KEYBOARD", "us")

	env := collectEnv([]string{"VASOTEST_"})
	for _, k := range []string{"VASOTEST_API_KEY", "VASOTEST_BOT_TOKEN", "VASOTEST_KEY_PASSPHRASE"} {
		if env[k] != redactedEnvValue {
			t.Errorf("%s = %q, want redacted", k, env[k])
		}
	}
	if env["VASOTEST_HOME"] != "/srv/agent" || env["VASOTEST_BASE_URL"] != "http://127.0.0.1:11434" ||
		env["VASOTEST_SSH_KEY_PATH"] != "/srv/keys/agent.key" || env["VASOTEST_KEYBOARD"] != "us" {
		t.Errorf("non-secret values changed: %v", env)
	}
}

func TestRunCommandIsolateHome(t *testing.T) {
	commandAllowlist["sh"] = true
	defer delete(commandAllowlist, "sh")
	realHome, _ := os.UserHomeDir()
	out := runCommand(CommandRequest{ID: "t", Cmd: "sh", Args: []string{"-c", "echo $HOME; pwd; touch $HOME/marker"}, IsolateHome: true}, "")
	lines := strings.Fields(out.Stdout)
	if len(lines) < 2 || lines[0] == realHome || filepath.Base(lines[0]) != filepath.Base(lines[1]) {
		t.Fatalf("HOME not isolated: %q", out.Stdout)
	}
	if _, err := os.Stat(lines[0]); !os.IsNotExist(err) {
		t.Fatalf("isolated home %s not removed", lines[0])
	}
	plain := runCommand(CommandRequest{ID: "t", Cmd: "sh", Args: []string{"-c", "echo $HOME"}}, "")
	if strings.TrimSpace(plain.Stdout) != realHome {
		t.Fatalf("HOME changed without IsolateHome: %q", plain.Stdout)
	}
}

// A link into a checkout outside the skills tree is followed (the agent loads
// it); links back into the tree are not (TestGlobFollowsSkillLinksOutsideTheTree).
func TestCollectFollowsOutsideSkillLinksAndRecordsLinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real", "src")
	skill := filepath.Join(root, "skills", "browse")
	for _, d := range []string{real, skill} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(real, "lib.ts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "own.ts"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(skill, "src")
	linkFile := filepath.Join(skill, "SKILL.md")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "lib.ts"), linkFile); err != nil {
		t.Fatal(err)
	}

	snap := Collect(ProbeManifest{
		GlobPatterns:      []string{filepath.Join(root, "skills") + "/**"},
		DirectoryListings: []string{skill},
	}, false)

	if _, ok := snap.Files[filepath.Join(linkDir, "lib.ts")]; !ok {
		t.Fatal("did not follow a skill symlinked in from outside the tree")
	}
	if _, ok := snap.Files[filepath.Join(skill, "own.ts")]; !ok {
		t.Fatal("regular file not collected")
	}
	if snap.Symlinks[linkDir] != real || snap.Symlinks[linkFile] != filepath.Join(real, "lib.ts") {
		t.Fatalf("symlinks not recorded: %v", snap.Symlinks)
	}
}

func TestParsePrivateGroups(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ncarol:x:1000:1000:Carol:/home/carol:/bin/bash\nalice:x:1001:100:,,,:/home/alice:/bin/bash\nbob:x:1002:100::/home/bob:/bin/sh\nshared:x:1003:1003::/home/shared:/bin/sh\n"
	group := "root:x:0:\ncarol:x:1000:\nusers:x:100:\nshared:x:1003:alice\ndocker:x:983:carol\n"
	got := parsePrivateGroups(passwd, group)
	want := map[string]int{"0": 0, "1000": 1000}
	if len(got) != len(want) || got["0"] != 0 || got["1000"] != 1000 {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCollectRecordsOwners(t *testing.T) {
	root := t.TempDir()
	f := filepath.Join(root, "cfg.json")
	if err := os.WriteFile(f, []byte("{}"), 0o664); err != nil {
		t.Fatal(err)
	}
	snap := Collect(ProbeManifest{FilePaths: []string{f}}, false)
	owner, ok := snap.Owners[f]
	if !ok || owner[0] != os.Getuid() || owner[1] != os.Getgid() {
		t.Fatalf("owner not recorded: %v (uid %d gid %d)", snap.Owners[f], os.Getuid(), os.Getgid())
	}
	if _, ok := snap.Owners[root]; !ok {
		t.Fatalf("ancestor directory owner not recorded")
	}
}

func TestInstallOnRunWrapperNotExecuted(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "lib", "node_modules", "@abacus-ai", "cli", "scripts", "npm-wrapper")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "ran")
	shim := filepath.Join(pkg, "shim.cjs")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shim, filepath.Join(binDir, "abacusai")); err != nil {
		t.Fatal(err)
	}

	out := runCommand(CommandRequest{ID: "abacusai-version", Cmd: "abacusai", Args: []string{"--version"}, Timeout: 3000, IsolateHome: true}, binDir)
	if out.ExitCode != -1 || !strings.Contains(out.Stderr, "install-on-run") {
		t.Fatalf("expected the shim to be refused, got %+v", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the npm shim was executed")
	}

	// A native binary of the same name still runs.
	native := filepath.Join(root, "native")
	if err := os.MkdirAll(native, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "abacusai"), []byte("#!/bin/sh\necho 'Abacus.AI CLI version 2.10.2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out = runCommand(CommandRequest{ID: "abacusai-version", Cmd: "abacusai", Args: []string{"--version"}, Timeout: 3000, IsolateHome: true}, native)
	if out.ExitCode != 0 || !strings.Contains(out.Stdout, "2.10.2") {
		t.Fatalf("expected the native binary to run, got %+v", out)
	}

	if InstallsOnRun("claude", shim) {
		t.Fatal("only listed commands are guarded")
	}
}

func TestExpandForEach(t *testing.T) {
	req := CommandRequest{
		ID: "openshell-sandbox-policy", Cmd: "openshell",
		Args:    []string{"policy", "get", "{name}", "--workspace", "{workspace}", "--full", "-o", "json"},
		ForEach: &CommandForEach{From: "list", Array: "sandboxes", Fields: []string{"name", "workspace"}},
	}
	want := []string{"policy", "get", "box-1", "--workspace", "default", "--full", "-o", "json"}

	// 0.1.x shape: {"sandboxes": [...]}; malformed and option-like values are skipped
	obj := `{"sandboxes":[{"name":"box-1","workspace":"default"},{"name":"--evil","workspace":"default"},{"name":"a/b","workspace":"x"},{"name":"nows"}]}`
	got := expandForEach(req, map[string]CommandOutput{"list": {Stdout: obj}})
	if len(got) != 1 || strings.Join(got[0], " ") != strings.Join(want, " ") {
		t.Fatalf("object form: got %v", got)
	}

	// A missing or empty field takes its default (sandboxes in the default workspace)
	req.ForEach.Defaults = map[string]string{"workspace": "default"}
	got = expandForEach(req, map[string]CommandOutput{"list": {Stdout: `{"sandboxes":[{"name":"box-1"},{"name":"box-1","workspace":""},{"name":"box-1","workspace":null},{"workspace":"default"},{"name":"box-2","workspace":"--x"}]}`}})
	if len(got) != 3 {
		t.Fatalf("defaults: expected 3 runs, got %v", got)
	}
	for _, args := range got {
		if strings.Join(args, " ") != strings.Join(want, " ") {
			t.Fatalf("defaults: got %v", args)
		}
	}
	req.ForEach.Defaults = nil

	// 0.0.x shape: a bare array
	got = expandForEach(req, map[string]CommandOutput{"list": {Stdout: `[{"name":"box-1","workspace":"default"}]`}})
	if len(got) != 1 || strings.Join(got[0], " ") != strings.Join(want, " ") {
		t.Fatalf("array form: got %v", got)
	}

	// Failed, missing or non-JSON source → no runs
	for name, outputs := range map[string]map[string]CommandOutput{
		"failed":   {"list": {Stdout: obj, ExitCode: 1}},
		"missing":  {},
		"not json": {"list": {Stdout: "No sandboxes found."}},
	} {
		if got := expandForEach(req, outputs); len(got) != 0 {
			t.Fatalf("%s: expected no runs, got %v", name, got)
		}
	}

	// Capped
	var many []string
	for i := 0; i < maxForEachItems+5; i++ {
		many = append(many, fmt.Sprintf(`{"name":"b%d","workspace":"w"}`, i))
	}
	got = expandForEach(req, map[string]CommandOutput{"list": {Stdout: "[" + strings.Join(many, ",") + "]"}})
	if len(got) != maxForEachItems {
		t.Fatalf("expected cap %d, got %d", maxForEachItems, len(got))
	}
}

func TestBuildAugmentedPathAddsPackageManagerDirs(t *testing.T) {
	homes := []UserHome{{Path: "/Users/u"}}
	got := strings.Split(buildAugmentedPath(homes, "/usr/bin:/bin:/usr/local/bin"), ":")
	if got[0] != "/Users/u/.local/bin" {
		t.Fatalf("user bin dirs must come first: %v", got)
	}
	tail := strings.Join(got[len(got)-5:], ":")
	if tail != "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/snap/bin" {
		t.Fatalf("session PATH must keep its order, package dirs appended once: %v", got)
	}
}

func TestCollectShipsBinaryFilesAsBase64(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "user_settings.pb")
	raw := []byte{0x0a, 0x05, 't', 'u', 'r', 'b', 'o', 0xff, 0xfe, 0x00, 0x80}
	if err := os.WriteFile(bin, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(root, "config.json")
	if err := os.WriteFile(text, []byte(`{"a":"é"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Collect(ProbeManifest{FilePaths: []string{bin, text}}, false)

	b := snap.Files[bin]
	if b.Encoding != "base64" {
		t.Fatalf("binary file not base64-encoded: %+v", b)
	}
	got, err := base64.StdEncoding.DecodeString(b.Content)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("bytes did not round-trip: %v %v", got, err)
	}
	if tx := snap.Files[text]; tx.Encoding != "" || tx.Content != `{"a":"é"}` {
		t.Fatalf("UTF-8 text must stay plain: %+v", tx)
	}
}

func TestExpandPathsResolvesEnvRootedPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("VASOTEST_REL", "relative/dir")
	t.Setenv("VASOTEST_ABS", "/srv/pico/")
	t.Setenv("VASOTEST_TILDE", "~/alt")
	t.Setenv("VASOTEST_EMPTY", "")
	homes := []UserHome{{Username: "u", Path: home}}
	got := expandPaths([]string{
		"${VASOTEST_ABS}/config.json",
		"${VASOTEST_TILDE}/skills/**",
		"${VASOTEST_REL}/x",
		"${VASOTEST_EMPTY}/x",
		"${VASOTEST_UNSET}/x",
		"${VASOTEST_ABS}",
		"${VASOTEST_ABS}/../.zeroclaw/config.toml",
		"~/.picoclaw/config.json",
	}, homes)
	want := []string{
		"/srv/pico/config.json",
		filepath.Join(home, "alt") + "/skills/**",
		"/srv/pico",
		"/srv/.zeroclaw/config.toml",
		filepath.Join(home, ".picoclaw/config.json"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSkillTreesKeepBuildOutputAndBinaries(t *testing.T) {
	if !inExcludedDir("/h/.claude/skills/**", "/h/.claude/skills/s/node_modules/x.js") {
		t.Fatal("node_modules must stay excluded in skill trees")
	}
	if inExcludedDir("/h/.claude/skills/**", "/h/.claude/skills/s/dist/index.js") {
		t.Fatal("dist/ inside a skill must be collected")
	}
	if !inExcludedDir("/h/.openclaw/**", "/h/.openclaw/x/dist/index.js") {
		t.Fatal("dist/ outside skill trees stays excluded")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "helper.node")
	if err := os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F', 0, 1}, 0o755); err != nil {
		t.Fatal(err)
	}
	c := &collector{budget: 1 << 20}
	if e := c.collectFile(bin, false); !e.ContentOmitted {
		t.Fatalf("outside a skill tree a .node file is metadata-only, got %+v", e)
	}
	c.inSkillTree = true
	if e := c.collectFile(bin, false); e.ContentOmitted || e.Content == "" {
		t.Fatalf("inside a skill tree a .node file ships its content, got %+v", e)
	}
}
