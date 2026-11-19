package main

import (
	"os"
	"path/filepath"
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
		{"/etc", "${OPENCLAW_STATE_DIR}/**/*.json5", true},
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
		if r := envGlobRefused(c.raw, got[0]); r != c.refused {
			t.Errorf("%s=%s %s (%s): refused %v, want %v", name, c.env, c.raw, got[0], r, c.refused)
		}
	}
	// a ~/ glob is the manifest's own, never refused here
	if envGlobRefused("~/.openclaw/**/*.json5", filepath.Join(home, ".openclaw/**/*.json5")) {
		t.Error("manifest glob refused")
	}
}
