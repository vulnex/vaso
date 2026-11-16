package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storeLinkCase is one row of testdata/store-link-cases.json, which
// src/core/store-links.test.ts reads too: both sides judge targets alike.
type storeLinkCase struct {
	Target     string   `json:"target"`
	HomeRoots  []string `json:"homeRoots"`
	StoreRoots []string `json:"storeRoots"`
	StoreDir   string   `json:"storeDir"`
	Want       *string  `json:"want"`
}

func TestForeignStoreTargetMatchesTS(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "store-link-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []storeLinkCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 20 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		want := ""
		if c.Want != nil {
			want = *c.Want
		}
		if got := foreignStoreTarget(c.Target, c.HomeRoots, c.StoreRoots, c.StoreDir); got != want {
			t.Errorf("foreignStoreTarget(%s, home=%v, store=%v, %s) = %q, want %q", c.Target, c.HomeRoots, c.StoreRoots, c.StoreDir, got, want)
		}
	}
}

func TestStoreHomeOf(t *testing.T) {
	if got := storeHomeOf("/home/u/.copilot", "/home/me"); got != "/home/u" {
		t.Errorf("got %s", got)
	}
	if got := storeHomeOf("/opt/cop", "/home/me"); got != "/home/me" {
		t.Errorf("got %s", got)
	}
}

var copilotStoreManifest = ProbeManifest{
	MetadataGlobPatterns: []string{
		"~/.copilot/session-state/*", "~/.copilot/session-state/*/*",
		"~/.copilot/mcp-secrets/*", "~/.copilot/mcp-secrets/*/*",
		"~/.copilot/mcp-oauth-config/*", "~/.copilot/mcp-oauth-config/*/*",
		"~/.copilot/command-history-state/*", "~/.copilot/command-history-state/*/*",
		// POL-005's credential names under a store (manifest-builder)
		"~/.copilot/session-state/*/{credentials,.npmrc}",
	},
	DirectoryListings: []string{
		"~/.copilot", "~/.copilot/session-state", "~/.copilot/mcp-secrets",
		"~/.copilot/mcp-oauth-config", "~/.copilot/command-history-state",
	},
	PrivateStores: []string{
		"~/.copilot/session-state", "~/.copilot/mcp-secrets",
		"~/.copilot/mcp-oauth-config", "~/.copilot/command-history-state",
	},
}

// A store folder linked to a place that isn't the agent's — or a folder
// linked inside a store — is recorded as a link (target, the mode a stat
// through it answers) with nothing behind it: no names, no modes, no
// listing. A folder linked inside the home is followed as before.
func TestForeignStoreLinksShipNothingBehindThem(t *testing.T) {
	home := setupHome(t)
	outside := t.TempDir()
	write(t, filepath.Join(home, ".aws", "credentials"), "[default]\n", 0o600)
	write(t, filepath.Join(home, ".aws", "CANARY-AWS-NAME"), "x", 0o644)
	write(t, filepath.Join(outside, "CANARY-OUT-NAME"), "x", 0o644)
	write(t, filepath.Join(outside, "sub", "CANARY-OUT-SUB"), "x", 0o644)
	write(t, filepath.Join(home, "CANARY-HOME-NAME"), "x", 0o644)
	write(t, filepath.Join(home, "sess", "events.jsonl"), "{}", 0o644)
	write(t, filepath.Join(home, ".copilot", "session-state", "real", "events.jsonl"), "{}", 0o600)
	cop := filepath.Join(home, ".copilot")
	mustSymlink(t, filepath.Join(home, ".aws"), filepath.Join(cop, "mcp-secrets"))
	mustSymlink(t, filepath.Join(home, "hop"), filepath.Join(cop, "mcp-oauth-config"))
	mustSymlink(t, outside, filepath.Join(home, "hop"))
	mustSymlink(t, home, filepath.Join(cop, "command-history-state"))
	ss := filepath.Join(cop, "session-state")
	mustSymlink(t, outside, filepath.Join(ss, "out"))
	mustSymlink(t, filepath.Join(home, ".aws"), filepath.Join(ss, "aws"))
	mustSymlink(t, home, filepath.Join(ss, "home"))
	mustSymlink(t, cop, filepath.Join(ss, "cop"))
	mustSymlink(t, "..", filepath.Join(ss, "up")) // relative: ~/.copilot holds the store
	mustSymlink(t, filepath.Join(home, "sess"), filepath.Join(ss, "ok"))

	snap := Collect(copilotStoreManifest, false)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "credentials") {
		t.Errorf("a name from behind a foreign store link was shipped")
	}
	for _, link := range []string{
		filepath.Join(cop, "mcp-secrets"), filepath.Join(cop, "mcp-oauth-config"), filepath.Join(cop, "command-history-state"),
		filepath.Join(ss, "out"), filepath.Join(ss, "aws"), filepath.Join(ss, "home"), filepath.Join(ss, "cop"), filepath.Join(ss, "up"),
	} {
		if _, ok := snap.Symlinks[link]; !ok {
			t.Errorf("%s: link not recorded", link)
		}
		if _, ok := snap.DirectoryModes[link]; !ok {
			t.Errorf("%s: no mode — the CLI can't tell it is a folder", link)
		}
		if _, ok := snap.Directories[link]; ok {
			t.Errorf("%s: listed", link)
		}
		for p := range snap.Files {
			if strictlyWithin(p, link) {
				t.Errorf("%s collected behind %s", p, link)
			}
		}
		for p := range snap.DirectoryModes {
			if strictlyWithin(p, link) {
				t.Errorf("mode of %s recorded behind %s", p, link)
			}
		}
	}
	// the chain through ~/hop, so the CLI resolves it as locally
	if snap.Symlinks[filepath.Join(home, "hop")] != outside {
		t.Errorf("the second hop is not recorded: %v", snap.Symlinks)
	}
	// a folder of the home is followed as before; the store's own files too
	for _, p := range []string{filepath.Join(ss, "ok", "events.jsonl"), filepath.Join(ss, "real", "events.jsonl")} {
		if e, ok := snap.Files[p]; !ok || !e.Exists || e.Content != "" {
			t.Errorf("%s: %+v, want metadata", p, e)
		}
	}
}

// Without privateStores (an older CLI's manifest) collection is unchanged.
func TestNoPrivateStoresNoForeignLinks(t *testing.T) {
	home := setupHome(t)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "f.json"), "{}", 0o644)
	mustSymlink(t, outside, filepath.Join(home, ".copilot", "mcp-secrets"))
	m := copilotStoreManifest
	m.PrivateStores = nil
	snap := Collect(m, false)
	if _, ok := snap.Files[filepath.Join(home, ".copilot", "mcp-secrets", "f.json")]; !ok {
		t.Errorf("collection changed without privateStores")
	}
}
