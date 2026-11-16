package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// foldingDir reports whether dir's filesystem opens `written` as `stored`
// (APFS applies full Unicode case folding: `weiss` opens `weiß`).
func foldingDir(t *testing.T, dir, stored, written string) bool {
	t.Helper()
	p := filepath.Join(dir, stored+"-fold-probe")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	_, err := os.Stat(filepath.Join(dir, written+"-fold-probe"))
	return err == nil
}

// A home written in letters only full case folding maps to it (weiss for
// weiß, fix for ﬁx), or under a parent the probe may search but not list, is
// the home: identity decides, not the name. Refused like the home, nothing
// of it shipped.
func TestHomeByIdentityWhateverItsSpelling(t *testing.T) {
	for _, tc := range []struct {
		name, stored, written string
		unlistable            bool
	}{
		{"eszett", "weiß", "weiss", false},
		{"eszett-upper", "weiß", "WEISS", false},
		{"ligature", "ﬁx", "fix", false},
		{"unlistable-parent", "Home", "HOME", true},
		{"unlistable-parent-eszett", "weiß", "weiss", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := allowedOutside(t)
			if !foldingDir(t, base, tc.stored, tc.written) {
				t.Skip("filesystem does not fold these names")
			}
			parent := filepath.Join(base, "p")
			home := filepath.Join(parent, tc.stored)
			written := filepath.Join(parent, tc.written)
			write(t, filepath.Join(home, "Documents", "diary.txt"), "DIARY-CANARY\n", 0o644)
			write(t, filepath.Join(home, "proj", "evil", "SKILL.md"), "# evil\n", 0o644)
			writeExtraDirs(t, home, written)
			t.Setenv("HOME", home)
			if tc.unlistable {
				if err := os.Chmod(parent, 0o311); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(parent, 0o755) })
				if os.Getuid() == 0 {
					t.Skip("root lists any directory")
				}
			}
			snap := Collect(extraDirsManifest(), false)
			if snap.ConfigTrees[written] != treeRefused {
				t.Errorf("%q: %q, want refused", written, snap.ConfigTrees[written])
			}
			for p, e := range snap.Files {
				if strings.Contains(e.Content, "CANARY") {
					t.Errorf("home content shipped: %s", p)
				}
			}
			if got := snap.ResolvedDirs[filepath.ToSlash(written)]; got != filepath.ToSlash(home) {
				t.Errorf("resolvedDirs[%q] = %q, want %q", written, got, home)
			}
		})
	}
}

// An agent config whose real path is in a credential store, reached through
// a spelling only folding maps to the store (`~/.ßh` opens `~/.ssh`), is
// judged by where it is: not shipped.
func TestConfigLinkedIntoStoreThroughFoldedSpelling(t *testing.T) {
	home := setupHome(t)
	if !foldingDir(t, home, ".ssh", ".ßh") {
		t.Skip("filesystem does not fold these names")
	}
	write(t, filepath.Join(home, ".ssh", "config"), "Host x\n  User CANARYSSHUSER\n", 0o600)
	mustSymlink(t, filepath.Join(home, ".ßh", "config"), filepath.Join(home, ".claude", "settings.json"))
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n  user: CANARYGHUSER\n", 0o600)
	mustSymlink(t, filepath.Join(home, ".conﬁg", "gh", "hosts.yml"), filepath.Join(home, ".copilot", "config.json"))
	snap := Collect(ProbeManifest{FilePaths: []string{"~/.claude/settings.json", "~/.copilot/config.json"}}, false)
	for _, p := range []string{filepath.Join(home, ".claude", "settings.json"), filepath.Join(home, ".copilot", "config.json")} {
		e := snap.Files[p]
		if !e.Exists || e.Omitted != "sensitive" || strings.Contains(e.Content, "CANARY") {
			t.Errorf("%s: %+v, want present and omitted sensitive", p, e)
		}
	}
}

// A regular file in a skills tree that is a credential-store file under
// another name — a hard link — is withheld like a link into that store and
// says which file it is; the store file under its own name, and a hard link
// between two ordinary files, are not.
func TestHardLinkToCredentialStoreNotShipped(t *testing.T) {
	home := setupHome(t)
	key := filepath.Join(home, ".ssh", "id_rsa")
	write(t, key, "-----BEGIN OPENSSH PRIVATE KEY-----\nSSHKEYCANARY\n", 0o600)
	cred := filepath.Join(home, ".claude", ".credentials.json")
	write(t, cred, `{"claudeAiOauth":{"accessToken":"CCREDCANARY"}}`, 0o600)
	hosts := filepath.Join(home, ".config", "gh", "hosts.yml")
	write(t, hosts, "github.com:\n  oauth_token: GHHOSTSCANARY\n", 0o600)
	skill := filepath.Join(home, ".claude", "skills", "s")
	write(t, filepath.Join(skill, "SKILL.md"), "# s\n", 0o644)
	plain := filepath.Join(home, "notes.txt")
	write(t, plain, "ordinary\n", 0o644)
	links := map[string]string{
		filepath.Join(skill, "id.txt"):    key,
		filepath.Join(skill, "c.json"):    cred,
		filepath.Join(skill, "hosts.yml"): hosts,
		filepath.Join(skill, "notes.md"):  plain,
	}
	for l, target := range links {
		if err := os.Link(target, l); err != nil {
			t.Skipf("hard links unsupported: %v", err)
		}
	}
	snap := Collect(ProbeManifest{
		FilePaths:    []string{"~/.config/gh/hosts.yml"},
		GlobPatterns: []string{"~/.claude/skills/**"},
	}, false)
	for l, target := range links {
		e := snap.Files[l]
		if !e.Exists {
			t.Errorf("%s not recorded", l)
			continue
		}
		if target == plain {
			if e.ContentOmitted || e.HardLinkOf != "" || e.Content != "ordinary\n" {
				t.Errorf("%s: an ordinary hard link withheld: %+v", l, e)
			}
			continue
		}
		if e.Omitted != "sensitive" || e.HardLinkOf != target || strings.Contains(e.Content, "CANARY") {
			t.Errorf("%s: %+v, want omitted sensitive, hardLinkOf %s", l, e, target)
		}
	}
	// hosts.yml under its own name is a Copilot config: collected (disguised)
	if e := snap.Files[hosts]; e.ContentOmitted || e.HardLinkOf != "" {
		t.Errorf("the store file under its own name: %+v", e)
	}
}

// The search roots are SINK_SEARCH_ROOTS in src/core/hard-link-sinks.ts,
// entry for entry.
func TestSinkSearchRootsMatchTS(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "src", "core", "hard-link-sinks.ts"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)export const SINK_SEARCH_ROOTS[^=]*= \[(.*?)\n\];`).FindStringSubmatch(string(src))
	if block == nil {
		t.Fatal("SINK_SEARCH_ROOTS not found")
	}
	var ts []string
	for _, m := range regexp.MustCompile(`\{ path: '([^']*)', depth: (\d+) \}`).FindAllStringSubmatch(block[1], -1) {
		ts = append(ts, m[1]+":"+m[2])
	}
	var probe []string
	for _, r := range sinkSearchRoots {
		probe = append(probe, r.path+":"+strconv.Itoa(r.depth))
	}
	if strings.Join(ts, ",") != strings.Join(probe, ",") {
		t.Fatalf("sink search roots differ:\nTS:    %v\nprobe: %v", ts, probe)
	}
	if !regexp.MustCompile(`MAX_SINK_IDENTITY_ENTRIES = ` + strconv.Itoa(maxSinkIdentityEntries) + `;`).Match(src) {
		t.Fatal("MAX_SINK_IDENTITY_ENTRIES differs from maxSinkIdentityEntries")
	}
}
