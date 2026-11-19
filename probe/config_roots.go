package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// ConfigRootRequest asks for paths an agent's config sets (a workspace, an
// extra skills directory, an MCP server's command): the probe reads the
// config, takes the string values at Keys, and either walks each as a skill
// tree ("tree": Globs under it, content disguised like any config) or
// records it as metadata ("stat": existence, mode, owner — never content).
type ConfigRootRequest struct {
	// Config files, in manifest path syntax (~, ${VAR}, globs). None, with
	// EnvFallback set: the variable's value alone, for the probe user.
	Configs []string `json:"configs"`
	// "json" (JSON/JSONC/JSON5), "toml" or "yaml".
	Format string `json:"format"`
	// Key paths into the parsed config; "*" is every key of a mapping or
	// item of an array.
	Keys [][]string `json:"keys"`
	// "tree" or "stat".
	Kind string `json:"kind"`
	// tree: globs relative to each value ("skills/**", "**",
	// "../workspace-*/skills/**"); each must end in "/**" or be "**".
	Globs []string `json:"globs,omitempty"`
	// A relative value is resolved against "home", "config" (the config
	// file's directory) or "configParent" (the directory above it: a plugin
	// root, for <root>/.claude-plugin/plugin.json); empty: relative values
	// are skipped.
	Relative string `json:"relative,omitempty"`
	// Expand ${NAME} from the environment in values (unset: value skipped).
	ExpandEnv bool `json:"expandEnv,omitempty"`
	// When no key holds a string: this variable's value, expanded the same way.
	EnvFallback string `json:"envFallback,omitempty"`
	// Only when this key path is boolean true in the same config.
	When []string `json:"when,omitempty"`
	// Used when When holds and no key holds a string (expanded the same way).
	Default string `json:"default,omitempty"`
	// Walked before the manifest's globs, which would otherwise collect the
	// tree as plain files first (a Claude Code plugin's extra skills
	// directories, under the ~/.claude/plugins/** glob).
	BeforeGlobs bool `json:"beforeGlobs,omitempty"`
}

// configRootsPhase: the requests walked before the manifest's globs (early),
// or the others.
func configRootsPhase(requests []ConfigRootRequest, early bool) []ConfigRootRequest {
	var out []ConfigRootRequest
	for _, r := range requests {
		if r.BeforeGlobs == early {
			out = append(out, r)
		}
	}
	return out
}

// Status of a config-derived tree, by its walk base (ConfigTrees).
const (
	treeCollected = "collected"
	treeRefused   = "refused" // a base no probe walks (/, a home or above, a credential store)
	treeLimit     = "limit"   // more than maxConfigTreeEntries entries: not collected
)

// maxConfigTreeEntries bounds one config-derived tree: a config pointing a
// workspace at a large directory must not turn the snapshot into a copy of it.
const maxConfigTreeEntries = 10000

// maxConfigStats bounds how many config-named paths are stat'd per run.
const maxConfigStats = 2000

// maxConfigReadBytes bounds a config read for its path values.
const maxConfigReadBytes = maxConfigContentBytes

// configSource is one config file and the home its ~ expands to.
type configSource struct {
	path string
	home string
}

// configSources expands a request's config patterns per scanned home (or the
// probe user's home for ${VAR}-rooted and absolute patterns).
func configSources(patterns []string, homes []UserHome) []configSource {
	ownHome, _ := os.UserHomeDir()
	var out []configSource
	add := func(p, home string) {
		if !strings.ContainsAny(p, "*?[{") {
			out = append(out, configSource{p, home})
			return
		}
		matches, err := doublestar.FilepathGlob(p, doublestar.WithNoFollow())
		if err != nil {
			return
		}
		for _, m := range matches {
			out = append(out, configSource{m, home})
		}
	}
	for _, raw := range patterns {
		if strings.HasPrefix(raw, "~/") || raw == "~" {
			for _, h := range homes {
				add(filepath.Join(h.Path, strings.TrimPrefix(raw, "~")), h.Path)
			}
			continue
		}
		for _, p := range expandPaths([]string{raw}, nil) {
			add(p, ownHome)
		}
	}
	return out
}

// readConfigForPaths reads a regular config file, bounded, without blocking.
func readConfigForPaths(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigReadBytes {
		return nil, false
	}
	f, err := openForRead(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigReadBytes+1))
	if err != nil || int64(len(data)) > maxConfigReadBytes {
		return nil, false
	}
	return data, true
}

// lookupKeys returns the values at a key path ("*" = every key or item).
func lookupKeys(v interface{}, path []string) []interface{} {
	if len(path) == 0 {
		return []interface{}{v}
	}
	var out []interface{}
	switch t := v.(type) {
	case map[string]interface{}:
		if path[0] == "*" {
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				out = append(out, lookupKeys(t[k], path[1:])...)
			}
		} else if child, ok := t[path[0]]; ok {
			out = append(out, lookupKeys(child, path[1:])...)
		}
	case []interface{}:
		if path[0] == "*" {
			for _, item := range t {
				out = append(out, lookupKeys(item, path[1:])...)
			}
		}
	}
	return out
}

// configValues are the raw string values a request names in one config,
// with the env fallback / default applied as the CLI's adapters do.
func configValues(req ConfigRootRequest, parsed interface{}) []string {
	if len(req.When) > 0 {
		hits := lookupKeys(parsed, req.When)
		if len(hits) != 1 || hits[0] != true {
			return nil
		}
	}
	var out []string
	for _, k := range req.Keys {
		for _, v := range lookupKeys(parsed, k) {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		if req.EnvFallback != "" {
			if v, ok := os.LookupEnv(req.EnvFallback); ok && v != "" {
				out = append(out, v)
			}
		} else if req.Default != "" {
			out = append(out, req.Default)
		}
	}
	return out
}

// resolveConfigValue turns a config value into an absolute path: ${NAME}
// from the environment when asked, ~ as the config's home, relative values
// against the home or the config's directory (or not at all).
func resolveConfigValue(req ConfigRootRequest, raw string, src configSource) (string, bool) {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsRune(v, 0) {
		return "", false
	}
	if req.ExpandEnv {
		unresolved := false
		v = envRef.ReplaceAllStringFunc(v, func(m string) string {
			val, ok := os.LookupEnv(m[2 : len(m)-1])
			if !ok {
				unresolved = true
			}
			return val
		})
		if unresolved {
			return "", false
		}
	}
	switch {
	case v == "~":
		v = src.home
	case strings.HasPrefix(v, "~/"):
		v = filepath.Join(src.home, v[2:])
	case filepath.IsAbs(v):
	case req.Relative == "home":
		v = filepath.Join(src.home, v)
	case req.Relative == "config":
		v = filepath.Join(filepath.Dir(src.path), v)
	case req.Relative == "configParent":
		v = filepath.Join(filepath.Dir(filepath.Dir(src.path)), v)
	default:
		return "", false
	}
	return filepath.Clean(v), true
}

// collectConfigRoots runs every configRoots request.
func (c *collector) collectConfigRoots(snapshot *ProbeSnapshot, requests []ConfigRootRequest, homes []UserHome) {
	parsedCache := make(map[string]interface{})
	stats := 0
	for _, req := range requests {
		if req.Kind != "tree" && req.Kind != "stat" {
			continue
		}
		sources := configSources(req.Configs, homes)
		envOnly := len(req.Configs) == 0 && req.EnvFallback != ""
		if envOnly {
			// A path only an environment variable sets (PICOCLAW_BUILTIN_SKILLS):
			// the probe user's own, as the CLI reads it for that user only
			ownHome, _ := os.UserHomeDir()
			sources = []configSource{{"", ownHome}}
		}
		for _, src := range sources {
			key := req.Format + "\x00" + src.path
			parsed, cached := parsedCache[key]
			if envOnly {
				parsed, cached = map[string]interface{}{}, true
			}
			if !cached {
				if data, ok := readConfigForPaths(src.path); ok {
					parsed, _ = parseConfig(req.Format, data)
				}
				parsedCache[key] = parsed
			}
			if parsed == nil {
				continue
			}
			for _, raw := range configValues(req, parsed) {
				if req.Kind == "stat" {
					if stats < maxConfigStats {
						stats += c.statConfigPath(snapshot, raw, src)
					}
					continue
				}
				root, ok := resolveConfigValue(req, raw, src)
				if !ok {
					continue
				}
				// A directory named `ws[2]` is walked as itself
				pattern, ok := escapeGlobMeta(root)
				if !ok {
					continue
				}
				for _, g := range req.Globs {
					c.collectConfigTree(snapshot, pattern, g, src.home)
				}
			}
		}
	}
}

// statConfigPath records a config-named path (an MCP server's command) as
// metadata, keyed exactly as the config spells it — the CLI looks it up by
// that string. Returns how many paths it stat'd.
func (c *collector) statConfigPath(snapshot *ProbeSnapshot, raw string, src configSource) int {
	var paths []string
	if strings.HasPrefix(raw, "/") {
		paths = append(paths, raw)
	}
	if t := strings.TrimSpace(raw); t != raw && strings.HasPrefix(t, "/") {
		paths = append(paths, t)
	} else if strings.HasPrefix(t, "~/") {
		paths = append(paths, filepath.Join(src.home, t[2:]))
	}
	paths = append(paths, configPathsWithin(raw, src.home)...)
	for _, p := range paths {
		if real, ok := c.dotDotSpelling(snapshot, p); ok {
			paths = append(paths, real)
		}
	}
	n := 0
	for _, p := range paths {
		if strings.ContainsRune(p, 0) {
			continue
		}
		if _, done := snapshot.Files[p]; done {
			continue
		}
		if _, done := snapshot.DirectoryModes[p]; done {
			continue
		}
		c.collectPath(snapshot, p, p, true, false)
		c.recordMissingTarget(snapshot, p)
		n++
	}
	return n
}

// maxConfigTrees bounds how many config-derived trees one snapshot records
// (the CLI rejects a snapshot with more, see snapshot-load.ts).
const maxConfigTrees = 2000

// collectConfigTree walks glob g under root as a skill tree, unless its base
// is somewhere no tree is walked from or holds too much. Every base is
// recorded under its literal path: a wildcard base (`…/workspace-*/skills`)
// is judged and recorded per match, and the directories its wildcard ranges
// over are listed, so the CLI can tell a match that doesn't exist from one
// the probe never looked at — without reading glob syntax out of a snapshot.
func (c *collector) collectConfigTree(snapshot *ProbeSnapshot, root, g, home string) {
	g = filepath.ToSlash(g)
	if g != "**" && !strings.HasSuffix(g, "/**") {
		return
	}
	pattern := filepath.Clean(filepath.Join(root, filepath.FromSlash(g)))
	base := strings.TrimSuffix(strings.TrimSuffix(filepath.ToSlash(pattern), "**"), "/")
	if base == "" {
		base = "/"
	}
	if snapshot.ConfigTrees == nil {
		snapshot.ConfigTrees = make(map[string]string)
	}
	if !hasGlobMeta(base) {
		c.collectConfigBase(snapshot, filepath.FromSlash(unescapeGlob(base)), home)
		return
	}
	// The directory the first wildcard segment ranges over, and the ones it
	// matches, are listed (names only) when a tree could be walked there; a
	// home is never listed — only the names its wildcard matches are recorded
	// (WildcardNames), so a derived match that doesn't exist reads as missing
	static, rest := doublestar.SplitPattern(base)
	staticDir := filepath.FromSlash(static)
	escapedStatic, ok := escapeGlobMeta(staticDir)
	// The home itself, either spelling (a workspace set in the home, or
	// through a link to it): its resolution is recorded, so the CLI can tell
	// matches spelled the other way are in the home, and so are the names
	// its wildcard matches there
	first := strings.SplitN(rest, "/", 2)[0]
	listMatches := false
	if home != "" && !treeAllowed(staticDir, home) && resolveExisting(filepath.Clean(staticDir)) == resolveExisting(filepath.Clean(home)) {
		recordResolvedDir(snapshot, staticDir)
		recordWildcardNames(snapshot, staticDir, first)
		listMatches = true
	}
	if ok && treeAllowed(staticDir, home) {
		if listing := collectDirectory(staticDir, snapshot.Symlinks); listing != nil {
			snapshot.Directories[staticDir] = listing
		}
		listMatches = true
	}
	if ok && listMatches {
		if dirs, err := doublestar.FilepathGlob(filepath.Join(escapedStatic, first), doublestar.WithNoFollow()); err == nil {
			for _, d := range dirs {
				if !treeAllowed(d, home) {
					continue
				}
				if listing := collectDirectory(d, snapshot.Symlinks); listing != nil {
					snapshot.Directories[d] = listing
				}
			}
		}
	}
	// A match reached through a directory link (a per-agent workspace that is
	// a link) is the agent's tree too: collectConfigBase judges where it leads
	for _, m := range expandFollowingDirLinks(filepath.FromSlash(base)) {
		c.collectConfigBase(snapshot, m, home)
	}
}

// maxWildcardNames bounds one WildcardNames entry; a directory with more
// matches is not recorded (its matches stay not verified).
const maxWildcardNames = 1000

// recordWildcardNames records the names in dir (a home, never listed) that
// the wildcard segment seg matches — only those names, and not a dangling
// link's (nothing is there).
func recordWildcardNames(snapshot *ProbeSnapshot, dir, seg string) {
	if seg == "" || !strings.ContainsAny(seg, "*?[{") || strings.Contains(seg, "**") {
		return
	}
	key := filepath.ToSlash(filepath.Join(dir, seg))
	if _, done := snapshot.WildcardNames[key]; done || len(snapshot.WildcardNames) >= maxConfigTrees {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := []string{}
	for _, e := range entries {
		if ok, _ := doublestar.Match(seg, e.Name()); ok {
			// a dangling link is no directory there, as a local stat finds
			if e.Type()&os.ModeSymlink != 0 {
				if _, err := os.Stat(filepath.Join(dir, e.Name())); err != nil {
					continue
				}
			}
			if len(names) >= maxWildcardNames {
				return
			}
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if snapshot.WildcardNames == nil {
		snapshot.WildcardNames = make(map[string][]string)
	}
	snapshot.WildcardNames[key] = names
}

// maxResolvedDirs bounds ResolvedDirs (homes, and home spellings met as a
// config tree's wildcard directory).
const maxResolvedDirs = maxConfigTrees

// recordResolvedDir records where p resolves, when that differs from p.
func recordResolvedDir(snapshot *ProbeSnapshot, p string) {
	if p == "" || !filepath.IsAbs(p) {
		return
	}
	p = filepath.Clean(p)
	real := resolveExisting(p)
	if real == p || !filepath.IsAbs(real) {
		return
	}
	if snapshot.ResolvedDirs == nil {
		snapshot.ResolvedDirs = make(map[string]string)
	}
	key := filepath.ToSlash(p)
	if _, done := snapshot.ResolvedDirs[key]; done || len(snapshot.ResolvedDirs) >= maxResolvedDirs {
		return
	}
	snapshot.ResolvedDirs[key] = filepath.ToSlash(real)
}

// maxLinkedExpansion bounds how many paths expandFollowingDirLinks returns.
const maxLinkedExpansion = maxConfigTrees

// expandFollowingDirLinks expands a wildcard path (no `**`) segment by
// segment, following directory links at every segment as an agent opening
// `<dir>/workspace-<id>/skills` does — doublestar's no-follow glob never
// enters a linked `workspace-<id>`. Matches keep the names they were reached
// by; nothing is read but directory listings.
func expandFollowingDirLinks(pattern string) []string {
	static, rest := doublestar.SplitPattern(filepath.ToSlash(pattern))
	if rest == "" {
		if _, err := os.Lstat(pattern); err == nil {
			return []string{pattern}
		}
		return nil
	}
	segs := strings.Split(rest, "/")
	for _, seg := range segs {
		if seg == "**" {
			matches, _ := doublestar.FilepathGlob(pattern, doublestar.WithNoFollow())
			return matches
		}
	}
	cur := []string{filepath.FromSlash(static)}
	// the names matching a segment in a directory, by where the directory
	// leads: twenty thousand links to one folder list and match it once
	matched := make(map[string][]string)
	for i, seg := range segs {
		last := i == len(segs)-1
		var next []string
		for _, dir := range cur {
			if !strings.ContainsAny(seg, `*?[{\`) {
				if p := filepath.Join(dir, seg); keepExpanded(p, last) {
					next = append(next, p)
				}
				continue
			}
			key := dir
			if real, err := filepath.EvalSymlinks(dir); err == nil {
				key = real
			}
			key += "\x00" + seg
			names, done := matched[key]
			if !done {
				entries, err := os.ReadDir(dir) // follows dir when it is a link
				if err != nil {
					continue
				}
				for _, e := range entries {
					if ok, _ := doublestar.Match(seg, e.Name()); ok {
						names = append(names, e.Name())
					}
				}
				matched[key] = names
			}
			for _, name := range names {
				if p := filepath.Join(dir, name); keepExpanded(p, last) {
					next = append(next, p)
				}
			}
		}
		if len(next) > maxLinkedExpansion {
			next = next[:maxLinkedExpansion]
		}
		cur = next
	}
	sort.Strings(cur)
	return cur
}

// keepExpanded: p exists, and is a directory (or a link to one) unless it is
// the last segment.
func keepExpanded(p string, last bool) bool {
	if last {
		_, err := os.Lstat(p)
		return err == nil
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// throughLink: a component of p below static (p itself included) is a symlink.
func throughLink(static, p string) bool {
	rel, err := filepath.Rel(static, p)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	cur := static
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		if info, err := os.Lstat(cur); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

// collectLinkedSkillBases walks, for a manifest skills glob with wildcard
// directories (`~/.picoclaw/workspace-*/skills/**`), the bases its no-follow
// glob couldn't enter because a matched directory is a link: as a
// config-derived tree (treeAllowed — see skill_scope.go), recorded in
// ConfigTrees under the linked path, so the CLI reports one it refused or
// capped as not scanned instead of empty.
func (c *collector) collectLinkedSkillBases(snapshot *ProbeSnapshot, pattern string) {
	slash := filepath.ToSlash(pattern)
	if !strings.HasSuffix(slash, "/**") {
		return
	}
	base := strings.TrimSuffix(slash, "/**")
	static, rest := doublestar.SplitPattern(base)
	if rest == "" {
		return
	}
	if snapshot.ConfigTrees == nil {
		snapshot.ConfigTrees = make(map[string]string)
	}
	staticDir := filepath.FromSlash(static)
	for _, m := range expandFollowingDirLinks(filepath.FromSlash(base)) {
		if throughLink(staticDir, m) {
			c.collectConfigBase(snapshot, m, c.homeOf(m))
		}
	}
}

// followLinkedMetadata records, for a metadata glob with wildcard
// directories (`~/.copilot/session-state/*/*`), the matches its no-follow
// glob couldn't reach because a matched directory is a link
// (session-state/<id> → ~/sess): metadata only, under the linked path, and
// only where the link stays inside the home and outside credential stores
// (inHomeOutsideStores) — as a local scan judges the files it finds behind it.
func (c *collector) followLinkedMetadata(snapshot *ProbeSnapshot, pattern string) {
	slash := filepath.ToSlash(pattern)
	static, rest := doublestar.SplitPattern(slash)
	if rest == "" || strings.Contains(rest, "**") || !strings.Contains(rest, "/") {
		return
	}
	staticDir := filepath.FromSlash(static)
	for _, m := range expandFollowingDirLinks(pattern) {
		if !throughLink(staticDir, m) || inExcludedDir(pattern, m) || c.behindForeignLink(m) {
			continue
		}
		if _, done := snapshot.Files[m]; done {
			continue
		}
		home := c.homeOf(m)
		if home == "" {
			continue
		}
		if !inHomeOutsideStores(m, home) {
			// A file link in a followed folder that leads into a credential
			// store or out of the home: recorded like a link directly in the
			// store — its links (names, targets) and its mode, never content —
			// so the CLI judges it as a local scan does
			if isSymlink(m) && inHomeOutsideStores(filepath.Dir(m), home) {
				recordSymlink(snapshot.Symlinks, m)
				c.recordLinkChain(snapshot, m)
				c.collectPath(snapshot, m, globBase(pattern), true, false)
			}
			continue
		}
		recordSymlink(snapshot.Symlinks, m)
		c.collectPath(snapshot, m, globBase(pattern), true, false)
	}
}

// isSymlink: p itself is a symbolic link.
func isSymlink(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// homeOf is the scanned home (or the probe user's) p lies strictly inside,
// as written, else once both are resolved (a linked home spelled the other
// way); "" when none — a tree there is refused.
func (c *collector) homeOf(p string) string {
	homes := c.homes
	if own, err := os.UserHomeDir(); err == nil {
		homes = append(homes[:len(homes):len(homes)], own)
	}
	best := ""
	for _, h := range homes {
		h = filepath.Clean(h)
		if strictlyWithin(filepath.Clean(p), h) && len(h) > len(best) {
			best = h
		}
	}
	if best != "" {
		return best
	}
	real := resolveExisting(filepath.Clean(p))
	for _, h := range homes {
		h = filepath.Clean(h)
		if strictlyWithin(real, resolveExisting(h)) && len(h) > len(best) {
			best = h
		}
	}
	return best
}

// linkedOutSkillBase: the static base of a manifest skills glob
// (~/.claude/skills, ~/.picoclaw/workspace/skills) lies in a home as written
// but a link — the directory itself or one above it, ~/.claude → another
// volume — takes it out of the home or into a place no skills tree is walked
// (treeAllowed). It is walked as a config-derived tree when treeAllowed
// (content disguised, credential-named files metadata only, entry cap) and
// recorded refused otherwise, with the links that lead there — as local scans
// walk or refuse it (src/core/skill-root-scope.ts).
func (c *collector) linkedOutSkillBase(snapshot *ProbeSnapshot, pattern string) bool {
	base := globBase(pattern)
	if !filepath.IsAbs(base) || c.scannedHomeOrAbove(base) {
		return false
	}
	home := c.homeOf(base)
	if home == "" || !strictlyWithin(filepath.Clean(base), home) || len(sinkSet(base)) > 0 {
		return false
	}
	if strictlyWithin(resolveExisting(filepath.Clean(base)), resolveExisting(home)) && treeAllowed(base, home) {
		// Stays in the home: an ordinary manifest tree — unless the skills
		// directory is itself a link (~/.claude/skills → ~/bigdir), a linked
		// root held to the entry limit wherever it leads, as local scans hold
		// it (linkedManifestBase); collectLinkedSkillBases would record it
		// after the glob had collected it whole
		root, literal := literalTreeRoot(pattern)
		if !literal || filepath.Clean(root) != filepath.Clean(base) || !isSymlink(root) {
			return false
		}
	}
	if snapshot.ConfigTrees == nil {
		snapshot.ConfigTrees = make(map[string]string)
	}
	c.collectConfigBase(snapshot, base, home)
	return true
}

// collectConfigBase walks base as a config-derived skill tree and records
// what it did under base's path.
func (c *collector) collectConfigBase(snapshot *ProbeSnapshot, base, home string) {
	key := filepath.ToSlash(filepath.Clean(base))
	if _, done := snapshot.ConfigTrees[key]; done || c.treeRecords >= maxConfigTrees {
		return
	}
	c.treeRecords++
	// A tree not walked still says whether it exists (its mode, never a
	// listing): the CLI reports it present or absent as a local scan sees it
	notWalked := func(status string) {
		snapshot.ConfigTrees[key] = status
		if _, done := snapshot.DirectoryModes[base]; !done {
			recordDirMode(snapshot, base)
		}
		// the links that take it where it leads (names and targets): the CLI
		// tells a link to the home itself from one out of it, as locally
		c.recordLinkChain(snapshot, base)
	}
	if home == "" || !treeAllowed(base, home) || c.scannedHomeOrAbove(base) {
		notWalked(treeRefused)
		return
	}
	if c.limitScan(base).n > maxConfigTreeEntries {
		notWalked(treeLimit)
		return
	}
	pattern, ok := escapeGlobMeta(base)
	if !ok {
		return
	}
	inSkillTree, configTree, treeHome := c.inSkillTree, c.configTree, c.treeHome
	c.inSkillTree, c.configTree, c.treeHome = true, true, home
	c.collectGlob(snapshot, filepath.Join(pattern, "**"))
	c.inSkillTree, c.configTree, c.treeHome = inSkillTree, configTree, treeHome
	snapshot.ConfigTrees[key] = treeCollected
}

// scannedHomeOrAbove: p is a scanned home, the probe user's home, or a
// directory above one (homes nested in another user's home).
func (c *collector) scannedHomeOrAbove(p string) bool {
	homes := c.homes
	if own, err := os.UserHomeDir(); err == nil {
		homes = append(homes[:len(homes):len(homes)], own)
	}
	for _, h := range homes {
		if within(filepath.Clean(h), filepath.Clean(p)) {
			return true
		}
	}
	return false
}

// inHomeOutsideStores: once resolved, p lies strictly inside home (resolved
// too, so either spelling of a linked home is the home) and outside every
// credential store, as written and resolved — where a linked metadata folder
// (followLinkedMetadata) is followed. Skills trees use treeAllowed.
func inHomeOutsideStores(p, home string) bool {
	p, home = filepath.Clean(p), filepath.Clean(home)
	if !filepath.IsAbs(p) || !filepath.IsAbs(home) || home == string(filepath.Separator) {
		return false
	}
	if len(sinkSet(p)) > 0 {
		return false
	}
	realHome := resolveExisting(home)
	real := resolveExisting(p)
	return realHome != string(filepath.Separator) && strictlyWithin(real, realHome) && len(sinkSet(real)) == 0
}

// strictlyWithin: p lies below dir (not dir itself).
func strictlyWithin(p, dir string) bool {
	return p != dir && within(p, dir)
}

// resolveExisting resolves p's links like a realpath, for as much of p as
// exists: the deepest existing directory resolved (and spelled as the
// filesystem stores it, canonicalCase), the rest appended as is.
func resolveExisting(p string) string {
	var tail []string
	for cur := p; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			// spelled as stored: a home written in other letters is the home
			if stored := storedSpelling(real); stored != real {
				if cur != real {
					noteRespelled(cur, stored)
				}
				real = stored
			}
			for i := len(tail) - 1; i >= 0; i-- {
				real = filepath.Join(real, tail[i])
			}
			return real
		}
		if filepath.Dir(cur) == cur {
			return p
		}
		tail = append(tail, filepath.Base(cur))
	}
}

// maxLinkedTreeEntries bounds what the directory links of one skills tree
// may hold together (each followed link's own tree, counted on its own; a
// link over the entry limit is never walked and not charged): five trees at
// the entry limit. Twenty links to 9,999-entry trees made a 49 MB snapshot in 161 s;
// 50,000 entries keep that near 12 MB, well inside the probe's content
// budget and what the CLI loads, while real linked skill sets (a checkout
// of a skills repo, a home-manager profile) hold a few thousand at most.
// src/core/skill-tree-count.ts MAX_LINKED_SKILL_ENTRIES.
const maxLinkedTreeEntries = 5 * maxConfigTreeEntries

// maxJudgedLinkEntries bounds what judging the directory links of one
// skills tree may count in all: each distinct target counted once, to the
// entry limit, followed or not — fifty targets at the limit. Past it, a link
// to a target not yet counted is not counted and gets linkTotal, so links to
// many distinct large directories can't make the probe count without end.
// src/core/skill-tree-count.ts MAX_JUDGED_LINK_ENTRIES.
const maxJudgedLinkEntries = 10 * maxLinkedTreeEntries

// treeScan is what a count of one tree found: its entries (stopping past
// the limit it was counted to) and, in walk order, its directory links.
type treeScan struct {
	n     int
	links []string
}

// scanTree counts the entries a skills-tree walk of dir visits, from where
// dir leads — vendor and VCS directories skipped, build output counted, a
// link counted as one entry and never descended into (each link is judged
// from its own target: linkPlan) — stopping past limit (limit < 0: none).
// It lists the tree's links (their paths under dir's real path) in the
// order WalkDir meets them. skill-tree-count.ts scanSkillTree.
func scanTree(dir string, limit int) treeScan {
	var s treeScan
	rootReal, err := realPath(dir)
	if err != nil {
		rootReal = dir
	}
	// WalkDir lists nothing under a root that is itself a link
	_ = filepath.WalkDir(rootReal, func(p string, e fs.DirEntry, err error) error {
		if err != nil || p == rootReal {
			return nil
		}
		if e.IsDir() && excludedGlobDirs[e.Name()] && !skillTreeBuildDirs[e.Name()] {
			return filepath.SkipDir
		}
		if s.n++; limit >= 0 && s.n > limit {
			return errStopWalk
		}
		if e.Type()&os.ModeSymlink != 0 {
			s.links = append(s.links, p)
		}
		return nil
	})
	return s
}

// countTreeEntries is scanTree's count.
func countTreeEntries(dir string, limit int) int {
	return scanTree(dir, limit).n
}

var errStopWalk = errors.New("stop walk")

// Verdicts of linkPlan on a directory link's target.
const (
	linkFollow = "follow"
	linkLimit  = treeLimit // its tree holds more than maxConfigTreeEntries
	linkTotal  = "total"   // the links' total (maxLinkedTreeEntries) is spent
)

// limitScan is c's scan of dir to the entry limit, remembered by where dir
// leads: two hundred links to one tree count it once.
func (c *collector) limitScan(dir string) treeScan {
	real, err := realPath(dir)
	if err != nil {
		real = dir
	}
	if s, ok := c.treeScans[real]; ok {
		return s
	}
	s := scanTree(real, maxConfigTreeEntries)
	if c.treeScans == nil {
		c.treeScans = make(map[string]treeScan)
	}
	c.treeScans[real] = s
	return s
}

// linkPlan decides, for the skills tree at root (of the user whose home is
// home), which directory links a walk of it follows, by where they lead —
// the same whichever way a walk meets them. Links are taken in WalkDir order
// from the root, each followed one's own links right after it, at most
// maxLinkDepth deep; one into a tree already taken, back into the root or
// above it, or where treeAllowed refuses, gets no verdict. Each target is
// counted on its own (limitScan): over maxConfigTreeEntries → linkLimit
// (never walked, not charged); else its count is charged to the root's
// links' total, past maxLinkedTreeEntries in all → linkTotal (not charged
// either), else linkFollow. Once the targets counted hold
// maxJudgedLinkEntries, a new target is not counted and gets linkTotal.
// Remembered per home and root.
// skill-tree-count.ts planSkillLinks.
func (c *collector) linkPlan(root, home string) map[string]string {
	rootReal, err := realPath(root)
	if err != nil {
		rootReal = root
	}
	key := home + "\x00" + rootReal
	if p, ok := c.linkPlans[key]; ok {
		return p
	}
	plan := make(map[string]string)
	if c.linkPlans == nil {
		c.linkPlans = make(map[string]map[string]string)
	}
	c.linkPlans[key] = plan
	taken := []string{rootReal}
	used, judged := 0, 0
	var visit func(links []string, depth int)
	visit = func(links []string, depth int) {
		if depth >= maxLinkDepth {
			return
		}
		for _, p := range links {
			real, err := realPath(p)
			if err != nil {
				continue
			}
			if _, done := plan[real]; done || within(rootReal, real) {
				continue
			}
			covered := false
			for _, t := range taken {
				if within(real, t) {
					covered = true
					break
				}
			}
			if covered || !treeAllowed(p, home) {
				continue
			}
			if st, err := os.Stat(real); err != nil || !st.IsDir() {
				continue
			}
			if judged >= maxJudgedLinkEntries {
				plan[real] = linkTotal
				continue
			}
			s := c.limitScan(real)
			judged += s.n
			switch {
			case s.n > maxConfigTreeEntries:
				plan[real] = linkLimit
			case used+s.n > maxLinkedTreeEntries:
				plan[real] = linkTotal
			default:
				used += s.n
				plan[real] = linkFollow
				taken = append(taken, real)
				visit(s.links, depth+1)
			}
		}
	}
	visit(scanTree(rootReal, -1).links, 0)
	return plan
}

// credentialName: a file name that marks the file as a credential — its
// content may be a bare token no key names, which the disguiser can't tell
// from a hash: token and key files, a Vault token (.vault-token), shell and
// client histories (.bash_history, .psql_history: passwords typed inline),
// login keyrings, netrc/pgpass/git-credentials, browser cookie and login
// stores (Cookies, Login Data, Web Data, key4.db, logins.json). A
// config-derived tree ships such files as metadata only.
var credentialName = regexp.MustCompile(`(?i)^(?:\.?(?:tokens?|secrets?|credentials?|passwords?|api[_-]?keys?|access[_-]?tokens?|auth[_-]?tokens?)(?:\.(?:json|toml|ya?ml|txt|ini|cfg|conf|env|dat))?|.*\.(?:key|pem|p12|pfx|jks|keystore|keyring|kdbx|token|secret|gpg|asc)|id_(?:rsa|dsa|ecdsa|ed25519)|client_secret[\w.-]*\.json|\.htpasswd|\.vault-token|\.[\w-]*history|\.histfile|\.lesshst|[._]netrc|\.pgpass|\.my\.cnf|\.git-credentials|\.Xauthority|Cookies(?:-journal)?|Login Data(?: For Account)?(?:-journal)?|Web Data(?:-journal)?|key[34]\.db|logins\.json|cookies\.sqlite(?:-wal|-journal)?|signons\.sqlite)$`)

// credentialDir: a directory whose files are credentials whatever they are
// called (GNOME keyrings).
var credentialDir = regexp.MustCompile(`(?i)^keyrings$`)

func credentialFileName(p string) bool {
	if credentialName.MatchString(filepath.Base(p)) {
		return true
	}
	for dir := filepath.Dir(p); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if credentialDir.MatchString(filepath.Base(dir)) {
			return true
		}
	}
	return false
}

// programHeader: the file starts like a program — a `#!` script or an
// executable format (ELF, Mach-O, PE) — so an executable bit means what it
// says and a credential-like name doesn't make it a credential.
func programHeader(p string) bool {
	f, err := openForRead(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case len(head) >= 2 && head[0] == '#' && head[1] == '!':
		return true
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return true
	case len(head) == 4:
		for _, m := range [][]byte{{0x7f, 'E', 'L', 'F'}, {0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe}} {
			if string(head) == string(m) {
				return true
			}
		}
	}
	return false
}

// escapeGlobMeta escapes doublestar's metacharacters in a literal path, so a
// directory named `ws[2]` or `ws{1}` is globbed as itself. ok is false where
// `\` is the path separator (no escaping) and p holds a metacharacter.
func escapeGlobMeta(p string) (string, bool) {
	if !strings.ContainsAny(p, `*?[]{}\`) {
		return p, true
	}
	if filepath.Separator == '\\' {
		return p, false
	}
	var b strings.Builder
	for _, r := range p {
		if strings.ContainsRune(`*?[]{}\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String(), true
}

// literalTreeRoot is the directory a `<root>/**` glob walks when root has no
// unescaped metacharacter (escapes removed); ok is false otherwise.
func literalTreeRoot(pattern string) (string, bool) {
	slash := filepath.ToSlash(pattern)
	if !strings.HasSuffix(slash, "/**") {
		return "", false
	}
	root := strings.TrimSuffix(slash, "/**")
	if hasGlobMeta(root) {
		return "", false
	}
	return filepath.FromSlash(unescapeGlob(root)), true
}

// hasGlobMeta: s holds an unescaped glob metacharacter.
func hasGlobMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '*', '?', '[', '{':
			return true
		}
	}
	return false
}

// unescapeGlob removes escapeGlobMeta's backslashes.
func unescapeGlob(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// envRef is a ${NAME} reference in a config value.
var envRef = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)
