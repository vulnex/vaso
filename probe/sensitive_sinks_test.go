package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The probe's sink list is SENSITIVE_SINKS from the TS catalogue, verbatim.
func TestSensitiveSinksMatchTS(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "src", "analyzers", "sensitive-paths.ts"))
	if err != nil {
		t.Fatal(err)
	}
	var ts []string
	for _, m := range regexp.MustCompile(`(?m)^\s*\{ re: /(.*)/([a-z]*), label:`).FindAllStringSubmatch(string(src), -1) {
		if m[2] != "iu" {
			t.Fatalf("TS sink /%s/%s: the probe compiles every sink case-insensitively with Unicode folding (iu)", m[1], m[2])
		}
		ts = append(ts, m[1])
	}
	if strings.Join(ts, "\n") != strings.Join(sensitiveSinkPatterns, "\n") {
		t.Fatalf("probe sinks differ from SENSITIVE_SINKS:\nTS:    %q\nprobe: %q", ts, sensitiveSinkPatterns)
	}
}

func TestCollectNeverShipsContentBehindSensitiveSkillLinks(t *testing.T) {
	home := t.TempDir()
	mk := func(p, content string, mode os.FileMode) string {
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return full
	}
	link := func(target, p string) string {
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
		return full
	}
	mk(".ssh/id_ed25519", "SSHCANARY", 0o600)
	creds := mk(".aws/credentials", "AWSCANARY", 0o600)
	mk("src/ext/index.js", "eval(x)", 0o644)
	mk(".claude/skills/fmt/SKILL.md", "---\nname: fmt\n---\n", 0o644)
	sshDir := link("../../.ssh", ".claude/skills/sshlink")
	credLink := link(creds, ".claude/skills/fmt/creds.txt")
	// A link named like the sink itself is still below the glob base
	disguised := link(filepath.Join(home, ".ssh"), ".claude/skills/.ssh")
	ext := link(filepath.Join(home, "src", "ext"), ".claude/skills/ext")

	snap := Collect(ProbeManifest{GlobPatterns: []string{filepath.Join(home, ".claude", "skills") + "/**"}}, false)

	for p, e := range snap.Files {
		if strings.Contains(e.Content, "CANARY") || (e.Head != "" && strings.Contains(p, "creds")) {
			t.Fatalf("%s shipped content from behind a sensitive link", p)
		}
	}
	if e := snap.Files[credLink]; !e.Exists || e.Omitted != "sensitive" || !e.ContentOmitted {
		t.Fatalf("file link into ~/.aws: want metadata with omitted=sensitive, got %+v", e)
	}
	for _, d := range []string{sshDir, disguised} {
		if _, ok := snap.Files[filepath.Join(d, "id_ed25519")]; ok {
			t.Fatalf("walked into %s", d)
		}
		if snap.Symlinks[d] == "" {
			t.Fatalf("link %s not recorded (SKL-013 reads its target)", d)
		}
	}
	// An ordinary skill linked in from a checkout elsewhere is still followed
	if e := snap.Files[filepath.Join(ext, "index.js")]; e.Content != "eval(x)" {
		t.Fatalf("ordinary linked skill not collected: %+v", e)
	}
}

func TestEscapesToSinkOnlyForSinksTheBaseDoesNotName(t *testing.T) {
	root := t.TempDir()
	sink := filepath.Join(root, ".aws")
	if err := os.MkdirAll(filepath.Join(sink, "units"), 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(sink, "units", "real.conf")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	inSink := filepath.Join(sink, "alias.conf")
	if err := os.Symlink(real, inSink); err != nil {
		t.Fatal(err)
	}
	// Within the location VASO asked for (a unit linking elsewhere in /etc)
	if escapesToSink(inSink, sink) {
		t.Fatal("a link within the named sink is not an escape")
	}
	// From a skills tree into it
	skills := filepath.Join(root, "skills")
	if err := os.MkdirAll(skills, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(skills, "x.conf")
	if err := os.Symlink(real, out); err != nil {
		t.Fatal(err)
	}
	if !escapesToSink(out, skills) {
		t.Fatal("a skill link into ~/.aws must be an escape")
	}
	// No link at all, or nothing there
	if escapesToSink(real, real) || escapesToSink(filepath.Join(skills, "missing"), skills) {
		t.Fatal("plain or missing paths are not escapes")
	}
	// A real directory named like a sink inside the tree is not reached
	// through a link (a local walk reads it too)
	named := filepath.Join(skills, "kit", ".ssh", "notes.md")
	if err := os.MkdirAll(filepath.Dir(named), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(named, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if escapesToSink(named, skills) {
		t.Fatal("a real .ssh directory in a skill is not a link escape")
	}
	// An explicit config that is itself a link into a sink
	cfg := filepath.Join(root, "settings.json")
	if err := os.Symlink(real, cfg); err != nil {
		t.Fatal(err)
	}
	if !escapesToSink(cfg, cfg) {
		t.Fatal("an explicit path linking into ~/.aws is an escape")
	}
}
