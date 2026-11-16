package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// A store folder that is a link to a file is recorded as a link with the
// mode and owner a stat through it answers — never the file's content.
func TestStoreLinkedToFileRecordsModeOnly(t *testing.T) {
	home := setupHome(t)
	key := filepath.Join(home, ".ssh", "id_rsa")
	write(t, key, "CANARY-KEY-CONTENT\n", 0o644)
	write(t, filepath.Join(home, ".ssh", "CANARY-SSH-NAME"), "x", 0o644)
	ss := filepath.Join(home, ".copilot", "session-state")
	mustSymlink(t, key, ss)
	write(t, filepath.Join(home, ".copilot", "mcp-secrets", "index.json"), "{}", 0o600)

	snap := Collect(copilotStoreManifest, false)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "CANARY") {
		t.Errorf("content or a name from behind the link was shipped")
	}
	if snap.Symlinks[ss] != key {
		t.Errorf("link not recorded: %v", snap.Symlinks)
	}
	e, ok := snap.Files[ss]
	if !ok || !e.Exists || e.Mode != 0o644 || e.Content != "" || !e.ContentOmitted {
		t.Errorf("session-state: %+v, want the target's mode, no content", e)
	}
	if _, ok := snap.Directories[ss]; ok {
		t.Errorf("listed")
	}
	// the other stores are collected as before
	if e, ok := snap.Files[filepath.Join(home, ".copilot", "mcp-secrets", "index.json")]; !ok || !e.Exists {
		t.Errorf("mcp-secrets/index.json not collected")
	}
}

// ~/.copilot itself linked out of the home (or into a credential store): its
// chain is recorded, nothing in its stores — the config files are collected
// as before. A link within the home is followed.
func TestAgentFolderLinkedAwayShipsNoStoreNames(t *testing.T) {
	for _, tc := range []struct {
		name    string
		foreign bool
		target  func(home, outside string) string
	}{
		{"out of the home", true, func(_, outside string) string { return filepath.Join(outside, "cop") }},
		{"into ~/.aws", true, func(home, _ string) string { return filepath.Join(home, ".aws", "cop") }},
		{"to the home", true, func(home, _ string) string { return home }},
		{"within the home", false, func(home, _ string) string { return filepath.Join(home, "dotfiles", "cop") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := setupHome(t)
			outside, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			real := tc.target(home, outside)
			write(t, filepath.Join(real, "session-state", "abc", "CANARY-SESSION.jsonl"), "{}", 0o644)
			write(t, filepath.Join(real, "mcp-secrets", "CANARY-SECRET.json"), "{}", 0o644)
			write(t, filepath.Join(real, "config.json"), "{}", 0o600)
			cop := filepath.Join(home, ".copilot")
			mustSymlink(t, real, cop)
			m := copilotStoreManifest
			m.FilePaths = []string{"~/.copilot/config.json"}

			snap := Collect(m, false)
			raw, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(raw), "CANARY"); got == tc.foreign {
				t.Errorf("store names shipped = %v, want %v", got, !tc.foreign)
			}
			if snap.Symlinks[cop] != real {
				t.Errorf("~/.copilot's link not recorded: %v", snap.Symlinks)
			}
			if e, ok := snap.Files[filepath.Join(cop, "config.json")]; !ok || !e.Exists {
				t.Errorf("config.json not collected")
			}
		})
	}
}

// COPILOT_HOME set outside the home is the agent's own folder: its stores
// are collected (names and modes) as under ~/.copilot.
func TestRelocatedAgentFolderOutsideHomeIsOwn(t *testing.T) {
	setupHome(t)
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(outside, "cp")
	write(t, filepath.Join(cp, "session-state", "abc", "events.jsonl"), "{}", 0o644)
	m := ProbeManifest{
		MetadataGlobPatterns: []string{cp + "/session-state/*", cp + "/session-state/*/*"},
		PrivateStores:        []string{cp + "/session-state"},
	}
	snap := Collect(m, false)
	if e, ok := snap.Files[filepath.Join(cp, "session-state", "abc", "events.jsonl")]; !ok || !e.Exists || e.Mode != 0o644 {
		t.Errorf("events.jsonl: %+v, want collected", e)
	}
}
