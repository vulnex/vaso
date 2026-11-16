package main

import (
	"os"
	"path/filepath"
	"sort"
)

// A hard link has no target to resolve: a skills-tree file hard-linked to
// ~/.ssh/id_rsa is, to every path check, a plain file in the skills tree.
// Only its identity (device and inode) tells. A regular file with more than
// one link whose identity is a file in a credential store of a scanned home
// is judged as a link into that store: never shipped (omitted "sensitive",
// HardLinkOf naming the store file), as a local scan never reads it
// (src/core/hard-link-sinks.ts).

// sinkSearchRoot is a place under a home where credential-store files live,
// searched to depth (1 = its own entries). A file found there counts only
// when its path is a sensitive sink (sinkSet). Mirrors SINK_SEARCH_ROOTS in
// src/core/hard-link-sinks.ts entry for entry (TestSinkSearchRootsMatchTS).
type sinkSearchRoot struct {
	path  string
	dir   bool
	depth int
}

var sinkSearchRoots = []sinkSearchRoot{
	{".", true, 1},
	{".ssh", true, 3},
	{".aws", true, 3},
	{".gnupg", true, 3},
	{".kube", true, 3},
	{".docker", true, 2},
	{".config/gh", true, 2},
	{".config/gcloud", true, 4},
	{".azure", true, 3},
	{".password-store", true, 6},
	{"Library/Keychains", true, 3},
	{".codex", true, 1},
	{".claude", true, 1},
	{".gemini", true, 1},
	{".qwen", true, 1},
	{".local/share/opencode", true, 1},
	{".local/share/devin", true, 1},
	{".config/nanoclaw", true, 1},
	{".hermes", true, 3},
	{".openclaw", true, 5},
	{".clawdbot", true, 5},
	{".nanobot", true, 4},
	{".abacusai", true, 1},
	{".grokbot", true, 1},
	{".cursor/sand", true, 1},
	{".ironclaw/reborn", true, 3},
	{".zeroclaw", true, 1},
	{".config/openshell", true, 5},
	{".local/state/openshell", true, 5},
	{"Library/Cookies", true, 1},
}

// maxSinkIdentityEntries bounds the entries read to build one home's index.
const maxSinkIdentityEntries = 20000

// fileID is a file's identity on its host.
type fileID struct{ dev, ino uint64 }

// sinkIdentities maps the identity of every multiply-linked file in a
// credential store of the scanned homes to its path there. Built on first
// use: most files have one link and never need it.
type sinkIdentities struct {
	built bool
	byID  map[fileID]string
}

// hardLinkedSink is the credential-store file the regular file at path
// (info: its stat) shares its identity with, when that store is one neither
// path's own spelling nor base names (resolvedIntoSink's rule); "" otherwise.
func (c *collector) hardLinkedSink(path, base string, info os.FileInfo) string {
	id, nlink, ok := fileIdentity(info)
	if !ok || nlink < 2 || !info.Mode().IsRegular() {
		return ""
	}
	if !c.sinkIDs.built {
		homes := c.homes
		if own, err := os.UserHomeDir(); err == nil {
			homes = append(homes[:len(homes):len(homes)], own)
		}
		c.sinkIDs = sinkIdentities{built: true, byID: buildSinkIdentities(homes)}
	}
	sink, ok := c.sinkIDs.byID[id]
	if !ok {
		return ""
	}
	named := sinkSet(base)
	for i := range sinkSet(path) {
		named[i] = true
	}
	for i := range sinkSet(sink) {
		if !named[i] {
			return sink
		}
	}
	return ""
}

// buildSinkIdentities indexes the multiply-linked regular files in each
// home's credential stores (sinkSearchRoots, bounded): identity → path.
func buildSinkIdentities(homes []string) map[fileID]string {
	out := make(map[fileID]string)
	seen := make(map[string]bool)
	for _, h := range homes {
		if h == "" || !filepath.IsAbs(h) {
			continue
		}
		h = filepath.Clean(h)
		if seen[h] {
			continue
		}
		seen[h] = true
		budget := maxSinkIdentityEntries
		for _, r := range sinkSearchRoots {
			indexSinkTree(filepath.Join(h, filepath.FromSlash(r.path)), r.depth, &budget, out)
		}
	}
	return out
}

// indexSinkTree adds dir's multiply-linked sink files, depth levels down
// (links not followed: a store's own files are what a hard link can share).
func indexSinkTree(dir string, depth int, budget *int, out map[fileID]string) {
	if depth < 1 || *budget <= 0 {
		return
	}
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	names, _ := f.Readdirnames(-1)
	f.Close()
	sort.Strings(names)
	for _, n := range names {
		if *budget <= 0 {
			return
		}
		*budget--
		p := filepath.Join(dir, n)
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			indexSinkTree(p, depth-1, budget, out)
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if id, nlink, ok := fileIdentity(info); ok && nlink > 1 && len(sinkSet(p)) > 0 {
			if _, dup := out[id]; !dup {
				out[id] = p
			}
		}
	}
}
