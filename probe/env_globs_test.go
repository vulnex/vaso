package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dt24 g9-F4: OPENCLAW_STATE_DIR=/ walked the whole filesystem, =$HOME
// shipped every *.json5 in the home.
func TestEnvGlobsRefuseRootAndHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	state := filepath.Join(home, ".openclaw-state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		env, raw string
		refused  bool
	}{
		{"/", "${OPENCLAW_STATE_DIR}/**/*.json5", true},
		{home, "${OPENCLAW_STATE_DIR}/**/*.json5", true},
		{filepath.Dir(home), "${OPENCLAW_STATE_DIR}/**/*.json5", true},
		// another user's home, the home area itself
		{"/home/someone-else/.openclaw", "${OPENCLAW_STATE_DIR}/skills/**", true},
		{"/home", "${PICOCLAW_HOME}/workspace*/skills/**", true},
		// dt24 g1-R1: an OS directory's subtree the agent's own variable
		// names (systemd StateDirectory=openclaw, a node package dir) is
		// walked, as locally
		{"/var/lib/openclaw", "${OPENCLAW_STATE_DIR}/skills/**", false},
		{"/var/lib/openclaw", "${OPENCLAW_STATE_DIR}/**/*.json5", false},
		{"/usr/lib/node_modules/picoclaw", "${PICOCLAW_HOME}/workspace*/skills/**", false},
		// /etc is a sensitive location (SENSITIVE_SINKS), not just an OS dir
		{"/etc/openclaw", "${OPENCLAW_STATE_DIR}/**/*.json5", true},
		{filepath.Join(home, ".ssh"), "${OPENCLAW_STATE_DIR}/**/*.json5", true},
		{state, "${OPENCLAW_STATE_DIR}/**/*.json5", false},
		{"/opt/openclaw", "${OPENCLAW_STATE_DIR}/**/*.json5", false},
		// below the root or home by a name: the agent's own tree
		{home, "${OPENCLAW_STATE_DIR}/skills/**", false},
		{"/", "${OPENCLAW_STATE_DIR}/agents/*/agent.yaml", false},
		// one level, named files: kept below the home, not at the root
		{home, "${CODEX_HOME}/*.config.toml", false},
		{"/", "${CODEX_HOME}/*.config.toml", true},
		// a literal path is no walk
		{"/", "${OPENCLAW_STATE_DIR}/openclaw.json", false},
	}
	for _, c := range cases {
		name := envPathPrefix.FindStringSubmatch(c.raw)[1]
		t.Setenv(name, c.env)
		got := expandPaths([]string{c.raw}, nil)
		if len(got) != 1 {
			t.Fatalf("%s=%s %s: expanded to %q", name, c.env, c.raw, got)
		}
		if r := envGlobRefused(c.raw, got[0], []string{home}); r != c.refused {
			t.Errorf("%s=%s %s (%s): refused %v, want %v", name, c.env, c.raw, got[0], r, c.refused)
		}
	}
	// the table src/adapters/default-skill-roots.test.ts reads too
	raw, err := os.ReadFile("testdata/env-glob-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var shared []struct {
		Value, Glob string
		Refused     bool
	}
	if err := json.Unmarshal(raw, &shared); err != nil {
		t.Fatal(err)
	}
	for _, c := range shared {
		value := filepath.Clean(strings.ReplaceAll(c.Value, "$HOME", home))
		name := envPathPrefix.FindStringSubmatch(c.Glob)[1]
		t.Setenv(name, value)
		got := expandPaths([]string{c.Glob}, nil)
		if len(got) != 1 {
			t.Fatalf("%s=%s %s: expanded to %q", name, value, c.Glob, got)
		}
		if r := envGlobRefused(c.Glob, got[0], []string{home}); r != c.Refused {
			t.Errorf("shared case %s=%s %s: refused %v, want %v", name, c.Value, c.Glob, r, c.Refused)
		}
	}
	// a ~/ glob is the manifest's own, never refused here
	if envGlobRefused("~/.openclaw/**/*.json5", filepath.Join(home, ".openclaw/**/*.json5"), []string{home}) {
		t.Error("manifest glob refused")
	}
}
