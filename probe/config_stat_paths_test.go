//go:build unix

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A config-named command that doesn't exist: the missing directories above
// it are recorded as absent and the existing ones (mode, owner) up to the
// root, so the CLI tells who can plant it as a local scan does.
func TestMissingConfigCommandRecordsItsAncestors(t *testing.T) {
	home := setupHome(t)
	open := filepath.Join(filepath.Dir(home), "open")
	if err := os.MkdirAll(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	cmd := filepath.Join(open, "nodir", "x", "cmd")
	write(t, filepath.Join(home, ".hermes", "config.yaml"), "mcp_servers:\n  a:\n    command: "+cmd+"\n", 0o644)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{
		{Configs: []string{"~/.hermes/config.yaml"}, Format: "yaml", Kind: "stat", Keys: [][]string{{"mcp_servers", "*", "command"}}},
	}}, false)
	for _, p := range []string{cmd, filepath.Dir(cmd), filepath.Dir(filepath.Dir(cmd))} {
		if e, ok := snap.Files[p]; !ok || e.Exists {
			t.Fatalf("%s not recorded as absent: %+v (%v)", p, e, ok)
		}
	}
	for dir := open; ; dir = filepath.Dir(dir) {
		if _, ok := snap.DirectoryModes[dir]; !ok {
			t.Fatalf("existing ancestor %s not recorded", dir)
		}
		if _, ok := snap.Owners[dir]; !ok {
			t.Fatalf("owner of %s not recorded", dir)
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	if snap.DirectoryModes[open]&0o002 == 0 {
		t.Fatalf("mode of %s: %o", open, snap.DirectoryModes[open])
	}
}

// A dangling link: its chain, its own owner, and the directories where it
// leads.
func TestDanglingConfigLinkRecordsWhereItLeads(t *testing.T) {
	home := setupHome(t)
	open := filepath.Join(filepath.Dir(home), "open")
	safe := filepath.Join(filepath.Dir(home), "safe")
	for _, d := range []string{open, safe} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(safe, "dang")
	target := filepath.Join(open, "notthere")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".hermes", "config.yaml"), "mcp_servers:\n  a:\n    command: "+link+"\n", 0o644)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{
		{Configs: []string{"~/.hermes/config.yaml"}, Format: "yaml", Kind: "stat", Keys: [][]string{{"mcp_servers", "*", "command"}}},
	}}, false)
	if snap.Symlinks[link] != target {
		t.Fatalf("link not recorded: %v", snap.Symlinks)
	}
	if _, ok := snap.LinkOwners[link]; !ok {
		t.Fatalf("link owner not recorded: %v", snap.LinkOwners)
	}
	if _, ok := snap.DirectoryModes[open]; !ok {
		t.Fatal("the directory the link leads to not recorded")
	}
}

// A `..` after a link is taken from where the link leads, as the kernel does
// (and the CLI, launchPathSpelling): that spelling is stat'd and the link
// before the `..` recorded, so the CLI walks the same way on the snapshot.
func TestDotDotAfterLinkStatsWhereItLeads(t *testing.T) {
	home := setupHome(t)
	open := filepath.Join(filepath.Dir(home), "open")
	safe := filepath.Join(filepath.Dir(home), "safe")
	for _, d := range []string{filepath.Join(open, "bin"), safe} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(open, "bin", "cmd"), "#!/bin/sh\n", 0o755)
	link := filepath.Join(safe, "lnk2")
	if err := os.Symlink(filepath.Join(open, "bin"), link); err != nil {
		t.Fatal(err)
	}
	cmd := link + "/../bin/cmd"
	script := link + "/./../missing3.py"
	write(t, filepath.Join(home, ".hermes", "config.yaml"), "mcp_servers:\n  a:\n    command: "+cmd+"\n    args: ["+script+"]\n", 0o644)
	snap := Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{
		{Configs: []string{"~/.hermes/config.yaml"}, Format: "yaml", Kind: "stat", Keys: [][]string{{"mcp_servers", "*", "command"}, {"mcp_servers", "*", "args", "*"}}},
	}}, false)
	if e, ok := snap.Files[filepath.Join(open, "bin", "cmd")]; !ok || !e.Exists {
		t.Fatalf("where the command leads not stat'd: %+v (%v)", e, ok)
	}
	if e, ok := snap.Files[filepath.Join(open, "missing3.py")]; !ok || e.Exists {
		t.Fatalf("where the script leads not recorded as absent: %+v (%v)", e, ok)
	}
	if snap.Symlinks[link] != filepath.Join(open, "bin") {
		t.Fatalf("the link before `..` not recorded: %v", snap.Symlinks)
	}
	if _, ok := snap.LinkOwners[link]; !ok {
		t.Fatal("the link's owner not recorded")
	}
	c := &collector{}
	if got, ok := c.dotDotSpelling(&ProbeSnapshot{}, "/a/./b//c"); ok {
		t.Fatalf("no `..`: %q", got)
	}
	if got, _ := c.dotDotSpelling(&ProbeSnapshot{}, "/nonexistent-vaso/x/../../y/z"); got != "/y/z" {
		t.Fatalf("got %q", got)
	}
}

// The paths a value names besides itself, as the CLI judges them.
func TestConfigPathsWithin(t *testing.T) {
	cases := map[string][]string{
		"${HOME}/tools/bin":   {"/h/tools/bin"},
		"${env:HOME}/x":       {"/h/x"},
		"--require=/x/pre.js": {"/x/pre.js"},
		"file:///x/s.js":      {"/x/s.js"},
		"node /x/s.js":        {"/x/s.js"},
		"/x/run.sh --flag /y": {"/x/run.sh", "/y"},
		"/plain/path":         nil,
		"${OTHER}/x":          nil,
		"KEY=value":           nil,
		// where it leads, too: the CLI judges the cleaned path
		"/p/safe/../ww/missing2": {"/p/ww/missing2"},
		"node /p/a/../s.js":      {"/p/a/../s.js", "/p/s.js"},
		"--require=/x//pre.js":   {"/x//pre.js", "/x/pre.js"},
	}
	for raw, want := range cases {
		if got := configPathsWithin(raw, "/h"); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", raw, got, want)
		}
	}
}

// `~name/…` as the CLI expands a Hermes command: the home where the OS puts it.
func TestUserTildePath(t *testing.T) {
	cases := []struct {
		v, goos, want string
		ok            bool
	}{
		{"~alice/tools/mcp-bin", "darwin", "/Users/alice/tools/mcp-bin", true},
		{"~alice/tools/mcp-bin", "linux", "/home/alice/tools/mcp-bin", true},
		{"~root/bin/x", "linux", "/root/bin/x", true},
		{"~root", "darwin", "/var/root", true},
		{"~/x", "linux", "", false},
		{"~", "linux", "", false},
		{"/abs", "linux", "", false},
		{"~al ice/x", "linux", "", false},
	}
	for _, c := range cases {
		if got, ok := userTildePath(c.v, c.goos); got != c.want || ok != c.ok {
			t.Errorf("%q on %s: got %q %v, want %q %v", c.v, c.goos, got, ok, c.want, c.ok)
		}
	}
}
