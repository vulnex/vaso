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
				if !ok || strings.ContainsAny(root, "*?[{\\") {
					continue // a literal glob character can't be walked as one
				}
				for _, g := range req.Globs {
					c.collectConfigTree(snapshot, root, g)
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

// collectConfigTree walks glob g under root as a skill tree, unless its base
// is somewhere no tree is walked from or holds too much.
func (c *collector) collectConfigTree(snapshot *ProbeSnapshot, root, g string) {
	g = filepath.ToSlash(g)
	if g != "**" && !strings.HasSuffix(g, "/**") {
		return
	}
	pattern := filepath.Clean(filepath.Join(root, filepath.FromSlash(g)))
	basePattern := filepath.ToSlash(strings.TrimSuffix(strings.TrimSuffix(filepath.ToSlash(pattern), "**"), "/"))
	if basePattern == "" {
		basePattern = "/"
	}
	if snapshot.ConfigTrees == nil {
		snapshot.ConfigTrees = make(map[string]string)
	}
	if _, done := snapshot.ConfigTrees[basePattern]; done {
		return
	}
	bases := []string{filepath.FromSlash(basePattern)}
	if strings.ContainsAny(basePattern, "*?[{") {
		// judged per match: ~/workspace-*/skills is fine although ~ is not
		matches, err := doublestar.FilepathGlob(filepath.FromSlash(basePattern), doublestar.WithNoFollow())
		if err != nil {
			snapshot.ConfigTrees[basePattern] = treeRefused
			return
		}
		bases = matches
	}
	if c.unsafeTreeBase(filepath.FromSlash(basePattern)) {
		snapshot.ConfigTrees[basePattern] = treeRefused
		return
	}
	entries := 0
	for _, b := range bases {
		if c.unsafeTreeBase(b) {
			snapshot.ConfigTrees[basePattern] = treeRefused
			return
		}
		if entries += countTreeEntries(b, maxConfigTreeEntries-entries+1); entries > maxConfigTreeEntries {
			snapshot.ConfigTrees[basePattern] = treeLimit
			return
		}
	}
	c.inSkillTree, c.configTree = true, true
	c.collectGlob(snapshot, pattern)
	c.inSkillTree, c.configTree = false, false
	snapshot.ConfigTrees[basePattern] = treeCollected
}

// unsafeTreeBase: a directory no config-derived tree is walked from — the
// root or a top-level directory, a scanned home or a directory above one, or
// a credential store or shell startup file (lexically or once resolved).
func (c *collector) unsafeTreeBase(b string) bool {
	check := func(p string) bool {
		p = filepath.Clean(p)
		if !filepath.IsAbs(p) || p == string(filepath.Separator) || filepath.Dir(p) == string(filepath.Separator) {
			return true
		}
		homes := c.homes
		if own, err := os.UserHomeDir(); err == nil {
			homes = append(homes[:len(homes):len(homes)], own)
		}
		for _, h := range homes {
			if within(filepath.Clean(h), p) {
				return true // p is h or above it
			}
		}
		return len(sinkSet(p)) > 0
	}
	if check(b) {
		return true
	}
	if real, err := filepath.EvalSymlinks(b); err == nil && real != b && check(real) {
		return true
	}
	return false
}

// countTreeEntries counts what a walk of dir would visit (vendor and VCS
// directories skipped, links not followed), stopping past limit.
func countTreeEntries(dir string, limit int) int {
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		if d.IsDir() && excludedGlobDirs[d.Name()] && !skillTreeBuildDirs[d.Name()] {
			return filepath.SkipDir
		}
		if n++; n > limit {
			return errStopWalk
		}
		return nil
	})
	return n
}

var errStopWalk = errors.New("stop walk")

// envRef is a ${NAME} reference in a config value.
var envRef = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)
