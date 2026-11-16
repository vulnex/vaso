package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Private stores (the manifest's privateStores: Copilot's session-state/,
// command-history-state/, mcp-oauth-config/, mcp-secrets/) are collected as
// metadata — names and modes. A store folder that is itself a link, or a
// folder linked inside one, can lead somewhere that isn't the agent's: a
// credential store, out of the home, the home itself, a folder holding the
// store. GHC-001 reports such a link once and never walks it, so nothing
// behind it is collected either: only the link (its chain of targets and the
// mode a stat through it answers). The same holds for a store folder that is
// a link to a file, and for every store of an agent folder that is itself
// linked to such a place (~/.copilot → out of the home, foreignAgentDir).

// foreignStoreTarget ports foreignStoreTarget in src/core/store-links.ts:
// why a linked folder resolving to target is not the agent's own —
// "sensitive", "outside", "home" or "store" — or "" for an ordinary folder of
// the home. Both sides test testdata/store-link-cases.json.
func foreignStoreTarget(target string, homeRoots, storeRoots []string, storeDir string) string {
	if len(sinkSet(target)) > 0 {
		return "sensitive"
	}
	inside := false
	for _, root := range append(append([]string{}, homeRoots...), storeRoots...) {
		if storeWithin(target, root) {
			inside = true
			break
		}
	}
	if !inside {
		return "outside"
	}
	for _, root := range homeRoots {
		if storeWithin(root, target) {
			return "home"
		}
	}
	for _, root := range storeRoots {
		if storeWithin(root, target) {
			return "store"
		}
	}
	if storeWithin(storeDir, target) {
		return "store"
	}
	return ""
}

// foreignAgentDir ports foreignAgentDir in src/core/store-links.ts: why the
// agent's folder itself, written at written and resolving to real, is a
// foreign place for its private stores — "sensitive", "outside" (a folder set
// inside the home that resolves out of it) or "home" (the home or a folder
// above it) — or "" when its stores are the agent's own: no link, a link
// within the home, or a folder set outside the home on purpose.
func foreignAgentDir(written, real string, homeRoots []string) string {
	if len(sinkSet(real)) > 0 {
		return "sensitive"
	}
	if real == written {
		return ""
	}
	writtenIn, realIn := false, false
	for _, root := range homeRoots {
		writtenIn = writtenIn || storeWithin(written, root)
		realIn = realIn || storeWithin(real, root)
	}
	if writtenIn && !realIn {
		return "outside"
	}
	for _, root := range homeRoots {
		if storeWithin(root, real) {
			return "home"
		}
	}
	return ""
}

// storeWithin ports withinDir (src/core/store-links.ts): p is dir or inside
// it — a name below dir starting with ".." is not inside, as path.relative
// tells it.
func storeWithin(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

// storeHomeOf ports storeHomeOf (src/core/store-links.ts): the parent of
// ~/.copilot, else (a folder COPILOT_HOME moved elsewhere) the probe user's home.
func storeHomeOf(agentDir, homedir string) string {
	if filepath.Base(agentDir) == ".copilot" {
		return filepath.Dir(agentDir)
	}
	return homedir
}

// spellings: p as written and resolved (resolveExisting), once each.
func spellings(p string) []string {
	out := []string{p}
	if real := resolveExisting(p); real != p {
		out = append(out, real)
	}
	return out
}

// markForeignStoreLinks finds, for each private store, the links GHC-001
// doesn't walk — the store folder itself, else each folder linked directly
// inside it — records each (its chain and the mode a stat through it
// answers, never a listing) and remembers it: nothing behind one is collected
// (behindForeignLink).
func (c *collector) markForeignStoreLinks(snapshot *ProbeSnapshot, stores []string) {
	own, _ := os.UserHomeDir()
	for _, store := range stores {
		if !filepath.IsAbs(store) {
			continue
		}
		store = filepath.Clean(store)
		agentDir := filepath.Dir(store)
		homeRoots := spellings(storeHomeOf(agentDir, own))
		// The agent folder itself (or a folder above it) linked to a place
		// that isn't the agent's: its chain only, nothing in the store
		if foreignAgentDir(agentDir, resolveExisting(agentDir), homeRoots) != "" {
			c.recordLinkChain(snapshot, agentDir)
			c.foreignLinks = append(c.foreignLinks, store)
			continue
		}
		storeRoots := spellings(agentDir)
		// The store folder a link to a file (or anything but a folder): no
		// store of the agent's — the link's chain and the mode and owner a
		// stat through it answers, never content
		if isSymlink(store) {
			if st, err := os.Stat(store); err == nil && !st.IsDir() {
				c.foreignLinks = append(c.foreignLinks, store)
				recordSymlink(snapshot.Symlinks, store)
				c.recordLinkChain(snapshot, store)
				recordOwner(snapshot, store, st)
				snapshot.Files[store] = c.collectFileLimit(store, store, true, 0)
				continue
			}
		}
		foreign := func(link string) bool {
			if !isSymlink(link) {
				return false
			}
			if st, err := os.Stat(link); err != nil || !st.IsDir() {
				return false // dangling, or a file linked inside a store: judged as a file
			}
			if foreignStoreTarget(resolveExisting(link), homeRoots, storeRoots, store) == "" {
				return false
			}
			c.foreignLinks = append(c.foreignLinks, link)
			recordSymlink(snapshot.Symlinks, link)
			c.recordLinkChain(snapshot, link)
			recordDirMode(snapshot, link)
			return true
		}
		if foreign(store) {
			continue
		}
		entries, err := os.ReadDir(store)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Type()&os.ModeSymlink != 0 {
				foreign(filepath.Join(store, e.Name()))
			}
		}
	}
}

// behindForeignLink: p lies below a link markForeignStoreLinks found, as
// written — nothing there is collected, listed or recorded.
func (c *collector) behindForeignLink(p string) bool {
	p = filepath.Clean(p)
	for _, link := range c.foreignLinks {
		if strictlyWithin(p, link) {
			return true
		}
	}
	return false
}

// isForeignLink: p is one of those links (recorded already; never listed).
func (c *collector) isForeignLink(p string) bool {
	p = filepath.Clean(p)
	for _, link := range c.foreignLinks {
		if p == link {
			return true
		}
	}
	return false
}
