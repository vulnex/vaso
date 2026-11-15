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
	// Config files, in manifest path syntax (~, ${VAR}, globs).
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
	// A relative value is resolved against "home" or "config" (the config
	// file's directory); empty: relative values are skipped.
	Relative string `json:"relative,omitempty"`
	// Expand ${NAME} from the environment in values (unset: value skipped).
	ExpandEnv bool `json:"expandEnv,omitempty"`
	// When no key holds a string: this variable's value, expanded the same way.
	EnvFallback string `json:"envFallback,omitempty"`
	// Only when this key path is boolean true in the same config.
	When []string `json:"when,omitempty"`
	// Used when When holds and no key holds a string (expanded the same way).
	Default string `json:"default,omitempty"`
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
		for _, src := range configSources(req.Configs, homes) {
			key := req.Format + "\x00" + src.path
			parsed, cached := parsedCache[key]
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
	// home is never listed — a match missing below it stays not verified
	static, rest := doublestar.SplitPattern(base)
	staticDir := filepath.FromSlash(static)
	escapedStatic, ok := escapeGlobMeta(staticDir)
	if ok && treeAllowed(staticDir, home) {
		first := strings.SplitN(rest, "/", 2)[0]
		if listing := collectDirectory(staticDir, snapshot.Symlinks); listing != nil {
			snapshot.Directories[staticDir] = listing
		}
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
			entries, err := os.ReadDir(dir) // follows dir when it is a link
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ok, _ := doublestar.Match(seg, e.Name()); !ok {
					continue
				}
				if p := filepath.Join(dir, e.Name()); keepExpanded(p, last) {
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
// config-derived tree (treeAllowed — inside the scanned home, outside every
// credential store), recorded in ConfigTrees under the linked path, so the
// CLI reports one it refused or capped as not scanned instead of empty.
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

// homeOf is the scanned home (or the probe user's) p lies strictly inside,
// as written; "" when none — a tree there is refused.
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
	return best
}

// collectConfigBase walks base as a config-derived skill tree and records
// what it did under base's path.
func (c *collector) collectConfigBase(snapshot *ProbeSnapshot, base, home string) {
	key := filepath.ToSlash(filepath.Clean(base))
	if _, done := snapshot.ConfigTrees[key]; done || len(snapshot.ConfigTrees) >= maxConfigTrees {
		return
	}
	if home == "" || !treeAllowed(base, home) || c.scannedHomeOrAbove(base) {
		snapshot.ConfigTrees[key] = treeRefused
		return
	}
	if countTreeEntries(base, home, maxConfigTreeEntries) > maxConfigTreeEntries {
		snapshot.ConfigTrees[key] = treeLimit
		return
	}
	pattern, ok := escapeGlobMeta(base)
	if !ok {
		return
	}
	saved := [3]interface{}{c.inSkillTree, c.configTree, c.treeHome}
	c.inSkillTree, c.configTree, c.treeHome = true, true, home
	c.collectGlob(snapshot, filepath.Join(pattern, "**"))
	c.inSkillTree, c.configTree, c.treeHome = saved[0].(bool), saved[1].(bool), saved[2].(string)
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

// treeAllowed is the one place a config-derived tree may be walked from, and
// what a link met while walking one may lead to: strictly inside home — the
// home of the user whose config named it — and outside every credential
// store (SENSITIVE_SINKS), both as written and once resolved. Anything else
// (/, /etc or /private/etc, other users' homes, the home itself, ~/.ssh,
// ~/.config/gh…) is refused; the CLI applies the same rule to local scans
// (src/core/skill-root-scope.ts).
func treeAllowed(p, home string) bool {
	p, home = filepath.Clean(p), filepath.Clean(home)
	if !filepath.IsAbs(p) || !filepath.IsAbs(home) || home == string(filepath.Separator) {
		return false
	}
	if !strictlyWithin(p, home) || len(sinkSet(p)) > 0 {
		return false
	}
	realHome := resolveExisting(home)
	real := resolveExisting(p)
	return strictlyWithin(real, realHome) && len(sinkSet(real)) == 0
}

// strictlyWithin: p lies below dir (not dir itself).
func strictlyWithin(p, dir string) bool {
	return p != dir && within(p, dir)
}

// resolveExisting resolves p's links like a realpath, for as much of p as
// exists: the deepest existing directory resolved, the rest appended as is.
func resolveExisting(p string) string {
	var tail []string
	for cur := p; ; cur = filepath.Dir(cur) {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
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

// countTreeEntries counts what a config-tree walk of dir visits — vendor and
// VCS directories skipped, directory links followed wherever the walk follows
// them (treeAllowed targets, each real directory once, maxLinkDepth deep) —
// stopping past limit. It may count more than the walk collects, never less.
func countTreeEntries(dir, home string, limit int) int {
	n := 0
	visited := map[string]bool{}
	rootReal, err := filepath.EvalSymlinks(dir)
	if err != nil {
		rootReal = dir
	}
	visited[rootReal] = true
	var walk func(d string, depth int) bool
	walk = func(d string, depth int) bool {
		stop := false
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || p == d {
				return nil
			}
			if e.IsDir() && excludedGlobDirs[e.Name()] && !skillTreeBuildDirs[e.Name()] {
				return filepath.SkipDir
			}
			if n++; n > limit {
				stop = true
				return errStopWalk
			}
			if e.Type()&os.ModeSymlink == 0 || depth >= maxLinkDepth || !treeAllowed(p, home) {
				return nil
			}
			real, err := filepath.EvalSymlinks(p)
			// a link back into the tree or above it isn't followed (followFrom)
			if err != nil || visited[real] || within(real, rootReal) || within(rootReal, real) {
				return nil
			}
			if st, err := os.Stat(p); err != nil || !st.IsDir() {
				return nil
			}
			visited[real] = true
			if walk(real, depth+1) { // WalkDir doesn't descend into a link given as its root
				stop = true
				return errStopWalk
			}
			return nil
		})
		return stop
	}
	walk(dir, 0)
	return n
}

var errStopWalk = errors.New("stop walk")

// credentialName: a file name that marks the file as a credential — its
// content may be a bare token no key names, which the disguiser can't tell
// from a hash. A config-derived tree ships such files as metadata only.
var credentialName = regexp.MustCompile(`(?i)^(?:\.?(?:tokens?|secrets?|credentials?|passwords?|api[_-]?keys?|access[_-]?tokens?|auth[_-]?tokens?)(?:\.(?:json|toml|ya?ml|txt|ini|cfg|conf|env|dat))?|.*\.(?:key|pem|p12|pfx|jks|keystore|kdbx|token|secret|gpg|asc)|id_(?:rsa|dsa|ecdsa|ed25519)|client_secret[\w.-]*\.json|\.htpasswd)$`)

func credentialFileName(p string) bool {
	return credentialName.MatchString(filepath.Base(p))
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
