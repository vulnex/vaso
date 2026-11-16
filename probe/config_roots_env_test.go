package main

import (
	"path/filepath"
	"testing"
)

// A tree only an environment variable sets (no config file): walked, refused
// or capped like a config-set one, for the probe user's own home.
func TestEnvOnlyConfigTree(t *testing.T) {
	home := setupHome(t)
	out := allowedOutside(t)
	write(t, filepath.Join(out, "s", "SKILL.md"), "# s\n", 0o644)
	req := ConfigRootRequest{Format: "json", Kind: "tree", EnvFallback: "VASO_TEST_BUILTIN", Globs: []string{"**"}}
	collect := func(v string) ProbeSnapshot {
		t.Setenv("VASO_TEST_BUILTIN", v)
		return Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{req}}, false)
	}

	snap := collect(out + "/./")
	if snap.ConfigTrees[out] != treeCollected {
		t.Fatalf("outside tree: %v", snap.ConfigTrees)
	}
	if _, ok := snap.Files[filepath.Join(out, "s", "SKILL.md")]; !ok {
		t.Fatal("SKILL.md not collected")
	}
	for _, c := range []struct{ value, key string }{
		{"/etc/", "/etc"},
		{"~", home},
		{"~/.ssh", filepath.Join(home, ".ssh")},
	} {
		snap = collect(c.value)
		if snap.ConfigTrees[c.key] != treeRefused {
			t.Errorf("%s: %v, want refused", c.value, snap.ConfigTrees)
		}
	}
	// relative: the agent's working directory, unknown — nothing walked
	snap = collect("skills")
	if len(snap.ConfigTrees) != 0 {
		t.Errorf("relative value walked: %v", snap.ConfigTrees)
	}
	// unset: nothing
	t.Setenv("VASO_TEST_BUILTIN", "")
	if snap = Collect(ProbeManifest{ConfigRoots: []ConfigRootRequest{req}}, false); len(snap.ConfigTrees) != 0 {
		t.Errorf("unset variable walked: %v", snap.ConfigTrees)
	}
}
