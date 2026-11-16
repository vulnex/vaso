package main

import (
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// A manifest skills tree ships its files verbatim (IOC hashes need the
// bytes). A tree reached through a link — the skills dir itself linked to
// ~/.claude, or a skill's folder or file linked into another agent's state
// — can thereby spell an agent's own files under a skills path. Those are
// judged by where they really are:
//   - a credential store (SENSITIVE_SINKS): not shipped (resolvedIntoSink);
//   - a path the manifest ships as metadata only (token files, conversation
//     and history stores): metadata only;
//   - a config the manifest collects by name: disguised like that config.

// resolvedTargets holds what the manifest says about real paths.
type resolvedTargets struct {
	// metadata are the manifest's metadata-only globs, lower-cased, each
	// also with its home spelled as the home really is
	metadata []string
	// configs are the real paths of the manifest's own config files,
	// lower-cased (a case-insensitive volume lists ~/.config/cursor as the
	// Cursor it stores)
	configs map[string]bool
	// configGlobs are its other (non-skill) globs, lower-cased, also with
	// the home spelled as it really is: what they collect is disguised
	configGlobs []string
}

func newResolvedTargets(metadataGlobs, configPaths, configGlobs []string, homes []string) resolvedTargets {
	t := resolvedTargets{configs: make(map[string]bool)}
	type pair struct{ spelled, real string }
	var homePairs []pair
	for _, h := range homes {
		if real, err := filepath.EvalSymlinks(h); err == nil && real != h {
			homePairs = append(homePairs, pair{filepath.ToSlash(filepath.Clean(h)), filepath.ToSlash(real)})
		}
	}
	// Each glob as written and with its home as it really is. A skills glob
	// (NanoClaw's checkout skills, listed for discovery) is skill code
	// wherever it is reached from
	globs := func(in []string) []string {
		var out []string
		seen := make(map[string]bool)
		add := func(g string) {
			g = strings.ToLower(g)
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
		for _, g := range in {
			if !filepath.IsAbs(g) || isSkillPattern(g) {
				continue
			}
			slash := filepath.ToSlash(g)
			add(slash)
			for _, hp := range homePairs {
				if strings.HasPrefix(slash, hp.spelled+"/") {
					add(hp.real + slash[len(hp.spelled):])
				}
			}
		}
		return out
	}
	t.metadata = globs(metadataGlobs)
	// Whole trees too (~/.claude/plugins/**, ~/.claude/rules/**): what they
	// hold ships disguised under its own path already
	t.configGlobs = globs(configGlobs)
	for _, p := range configPaths {
		if real, err := realPath(p); err == nil {
			t.configs[strings.ToLower(filepath.Clean(real))] = true
		}
	}
	return t
}

// skillTarget is where the skills-tree file p really is, when that differs
// from how it is spelled ("" otherwise, or when it can't be resolved).
func skillTarget(p string) string {
	real, err := realPath(p)
	if err != nil {
		return ""
	}
	real = filepath.Clean(real)
	if real == filepath.Clean(p) {
		return ""
	}
	return real
}

// metadataOnly: real is a path the manifest ships as metadata only.
func (t resolvedTargets) metadataOnly(real string) bool {
	return matchesAny(t.metadata, real)
}

// config: real is a file the manifest collects (and disguises) as a config.
func (t resolvedTargets) config(real string) bool {
	return t.configs[strings.ToLower(real)] || matchesAny(t.configGlobs, real)
}

func matchesAny(globs []string, p string) bool {
	slash := strings.ToLower(filepath.ToSlash(p))
	for _, g := range globs {
		if ok, _ := doublestar.Match(g, slash); ok {
			return true
		}
	}
	return false
}
