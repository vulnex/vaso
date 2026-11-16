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

// COPILOT_HOME named .copilot below a folder of the home that links out of
// it (~/x → elsewhere, COPILOT_HOME=~/x/.copilot): the folder resolves out of
// the home, so nothing in its stores ships — its parent is no home.
func TestRelocatedAgentFolderBelowLinkedParentShipsNoStoreNames(t *testing.T) {
	for _, sub := range []string{".copilot", filepath.Join("a", ".copilot")} {
		t.Run(sub, func(t *testing.T) {
			home := setupHome(t)
			outside, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			real := filepath.Join(outside, "x", sub)
			write(t, filepath.Join(real, "session-state", "abc", "CANARY-SESSION.jsonl"), "{}", 0o644)
			write(t, filepath.Join(real, "mcp-secrets", "CANARY-SECRET.json"), "{}", 0o644)
			mustSymlink(t, filepath.Join(outside, "x"), filepath.Join(home, "x"))
			cop := filepath.Join(home, "x", sub)
			t.Setenv("COPILOT_HOME", "~/"+filepath.ToSlash(filepath.Join("x", sub)))
			m := ProbeManifest{
				MetadataGlobPatterns: []string{
					"${COPILOT_HOME}/session-state/*", "${COPILOT_HOME}/session-state/*/*",
					"${COPILOT_HOME}/mcp-secrets/*", "${COPILOT_HOME}/mcp-secrets/*/*",
				},
				DirectoryListings: []string{"${COPILOT_HOME}/session-state", "${COPILOT_HOME}/mcp-secrets"},
				PrivateStores:     []string{"${COPILOT_HOME}/session-state", "${COPILOT_HOME}/mcp-secrets"},
			}
			snap := Collect(m, false)
			raw, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "CANARY") {
				t.Errorf("store names from behind ~/x shipped")
			}
			if _, ok := snap.Directories[filepath.Join(cop, "session-state")]; ok {
				t.Errorf("session-state listed")
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

// HOME with ".." segments or a trailing slash is cleaned before anything is
// joined onto it: the snapshot's homedir and paths are the ones a local
// scan uses, and the CLI accepts the snapshot.
func TestCollectCleansHome(t *testing.T) {
	home := setupHome(t)
	write(t, filepath.Join(home, ".codex", "config.toml"), "model = \"x\"\n", 0o600)
	for _, spelled := range []string{filepath.Join(home, ".codex") + "/..", home + "/", home + "/./"} {
		t.Setenv("HOME", spelled)
		snap := Collect(ProbeManifest{FilePaths: []string{"~/.codex/config.toml"}}, false)
		if snap.Homedir != home {
			t.Errorf("HOME=%s: homedir %q, want %q", spelled, snap.Homedir, home)
		}
		if e, ok := snap.Files[filepath.Join(home, ".codex", "config.toml")]; !ok || !e.Exists {
			t.Errorf("HOME=%s: config.toml not collected under the clean home", spelled)
		}
	}
}

// An agent folder an environment variable puts inside another tool's
// credential store (COPILOT_HOME=~/.aws/cop): its files' content never ships.
func TestNoContentFromInsideCredentialStores(t *testing.T) {
	home := setupHome(t)
	cfg := filepath.Join(home, ".aws", "cop", "config.json")
	write(t, cfg, "{\"CANARY\": 1}\n", 0o600)
	t.Setenv("COPILOT_HOME", "~/.aws/cop")
	snap := Collect(ProbeManifest{FilePaths: []string{"${COPILOT_HOME}/config.json", "~/.copilot/config.json"}}, false)
	e, ok := snap.Files[cfg]
	if !ok || !e.Exists || e.Content != "" || e.Omitted != "sensitive" {
		t.Errorf("config.json in ~/.aws: %+v, want present, content omitted (sensitive)", e)
	}
	if !inCredentialStore("/home/u/.ssh/codex/config.toml") || inCredentialStore("/home/u/.copilot/config.json") || inCredentialStore("/etc/hermes/config.yaml") {
		t.Errorf("inCredentialStore")
	}
}
