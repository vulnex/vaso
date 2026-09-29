package main

import (
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
