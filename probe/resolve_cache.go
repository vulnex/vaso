package main

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// A skills tree reached through a directory link has every file spelled
// through the link: judging each by where it really is resolved the whole
// path per file (twice), and matched it against every metadata glob. What
// a file's folder resolves to, and whether a folder below a glob's base is a
// link into a credential store, are the same for every file in it — worked
// out once per folder here. The decisions are those of the uncached
// functions they stand for (resolvedIntoSink, escapesToSink,
// filepath.EvalSymlinks, a match against every glob).

// resolveCache remembers per collection what folders resolve to.
type resolveCache struct {
	// dirs maps a folder to where it resolves ("" when it can't be)
	dirs map[string]string
	// sinks caches sinkSet by path (bases repeat for every file)
	sinks map[string]map[int]bool
	// linkSinks caches linkIntoSink for a folder under a base, by base and folder
	linkSinks map[string]bool
}

// realDir is realPath(dir) (resolved, in its stored spelling), remembered.
func (c *collector) realDir(dir string) (string, bool) {
	if c.resolved.dirs == nil {
		c.resolved.dirs = make(map[string]string)
	}
	if r, ok := c.resolved.dirs[dir]; ok {
		return r, r != ""
	}
	r, err := realPath(dir)
	if err != nil {
		r = ""
	}
	c.resolved.dirs[dir] = r
	return r, r != ""
}

// resolveFile is realPath(p), cleaned, for a file whose own
// link status is known: a file that is no link resolves as its folder does.
func (c *collector) resolveFile(p string, isLink bool) (string, bool) {
	if isLink {
		r, err := realPath(p)
		if err != nil {
			return "", false
		}
		return filepath.Clean(r), true
	}
	p = filepath.Clean(p)
	dir, name := filepath.Split(p)
	if name == "" || dir == "" {
		r, err := realPath(p)
		if err != nil {
			return "", false
		}
		return filepath.Clean(r), true
	}
	d, ok := c.realDir(filepath.Clean(dir))
	if !ok {
		return "", false
	}
	return filepath.Join(d, name), true
}

// sinkSetOf is a copy of sinkSet(p), remembered.
func (c *collector) sinkSetOf(p string) map[int]bool {
	if c.resolved.sinks == nil {
		c.resolved.sinks = make(map[string]map[int]bool)
	}
	s, ok := c.resolved.sinks[p]
	if !ok {
		s = sinkSet(p)
		c.resolved.sinks[p] = s
	}
	out := make(map[int]bool, len(s))
	for i := range s {
		out[i] = true
	}
	return out
}

// resolvedIntoSinkAt is resolvedIntoSink for p, which resolves to real.
func (c *collector) resolvedIntoSinkAt(p, real, base string) bool {
	if real == "" || real == filepath.Clean(p) {
		return false
	}
	named := c.sinkSetOf(base)
	for i := range c.sinkSetOf(p) {
		named[i] = true
	}
	for i := range c.sinkSetOf(real) {
		if !named[i] {
			return true
		}
	}
	return false
}

// escapesToSinkAt is escapesToSink for the file p, whose own link status is
// known: the folders between base and p are judged once each.
func (c *collector) escapesToSinkAt(p, base string, isLink bool) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	if c.folderIntoSink(base, base) {
		return true
	}
	if rel == "." {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	cur := base
	for _, comp := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, comp)
		if c.folderIntoSink(base, cur) {
			return true
		}
	}
	return isLink && linkIntoSink(filepath.Join(cur, parts[len(parts)-1]), c.sinkSetOf(base))
}

// folderIntoSink is linkIntoSink(dir, sinkSet(base)), remembered.
func (c *collector) folderIntoSink(base, dir string) bool {
	if c.resolved.linkSinks == nil {
		c.resolved.linkSinks = make(map[string]bool)
	}
	key := base + "\x00" + dir
	v, ok := c.resolved.linkSinks[key]
	if !ok {
		v = linkIntoSink(dir, c.sinkSetOf(base))
		c.resolved.linkSinks[key] = v
	}
	return v
}

// globIndex holds lower-cased absolute globs by their static base
// (doublestar.SplitPattern): a path can match only a glob whose base is the
// path or one of its folders.
type globIndex struct {
	byBase map[string][]string
	// loose are globs whose base holds an escape, matched against every path
	loose []string
}

func newGlobIndex(globs []string) globIndex {
	idx := globIndex{byBase: make(map[string][]string)}
	for _, g := range globs {
		base, _ := doublestar.SplitPattern(g)
		if strings.Contains(base, `\`) || !strings.HasPrefix(base, "/") {
			idx.loose = append(idx.loose, g)
			continue
		}
		idx.byBase[base] = append(idx.byBase[base], g)
	}
	return idx
}

// matches: p (any case) matches one of the globs — matchesAny's answer.
func (idx globIndex) matches(p string) bool {
	slash := strings.ToLower(filepath.ToSlash(p))
	for _, g := range idx.loose {
		if ok, _ := doublestar.Match(g, slash); ok {
			return true
		}
	}
	if len(idx.byBase) == 0 {
		return false
	}
	for cur := slash; ; cur = path.Dir(cur) {
		for _, g := range idx.byBase[cur] {
			if ok, _ := doublestar.Match(g, slash); ok {
				return true
			}
		}
		if cur == "/" || cur == "." || cur == "" {
			return false
		}
	}
}

// lstatThenStat is os.Stat(p) — the same answer and error — plus whether p
// itself is a link, from one lstat when it is not.
func lstatThenStat(p string) (os.FileInfo, bool, error) {
	li, err := os.Lstat(p)
	if err != nil {
		return nil, false, err
	}
	if li.Mode()&os.ModeSymlink == 0 {
		return li, false, nil
	}
	info, err := os.Stat(p)
	return info, true, err
}
