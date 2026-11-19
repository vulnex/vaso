package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// homeRef is a ${HOME} reference (Hermes also reads ${env:HOME}) in a config
// value: the agent expands it to the user's home, as the CLI does.
var homeRef = regexp.MustCompile(`\$\{\s*(?:env:\s*)?HOME\s*\}`)

// configPathsWithin are the absolute paths a config value names besides
// itself, as the CLI judges an MCP launch (src/mcp/writable-command.ts):
// with ${HOME} expanded, an option's value (`--require=/x/pre.js`), a
// file:// URL, and each word of a command line (`env -S "node /x/s.js"`,
// `bash -c "/x/run.sh --flag"`).
func configPathsWithin(raw, home string) []string {
	var out []string
	v := strings.TrimSpace(raw)
	if expanded := homeRef.ReplaceAllLiteralString(v, home); expanded != v && home != "" {
		v = expanded
		if strings.HasPrefix(v, "/") {
			out = append(out, v)
		}
	}
	if strings.HasPrefix(v, "-") {
		if i := strings.Index(v, "="); i > 0 && strings.HasPrefix(v[i+1:], "/") {
			out = append(out, v[i+1:])
		}
	}
	if strings.HasPrefix(v, "file:///") {
		out = append(out, strings.TrimPrefix(v, "file://"))
	}
	if words := strings.Fields(v); len(words) > 1 {
		for _, w := range words {
			if strings.HasPrefix(w, "/") {
				out = append(out, w)
			}
		}
	}
	if p, ok := userTildePath(v, runtime.GOOS); ok {
		out = append(out, p)
	}
	// The CLI judges a path where it leads (`/p/safe/../ww/x` as `/p/ww/x`):
	// the cleaned spelling too
	named := out
	if strings.HasPrefix(v, "/") {
		named = append([]string{v}, out...)
	}
	for _, p := range named {
		if c := filepath.Clean(p); c != p {
			out = append(out, c)
		}
	}
	return out
}

// tildeUser is `~name` or `~name/…` (POSIX portable user names).
var tildeUser = regexp.MustCompile(`^~([A-Za-z_][A-Za-z0-9._-]*)(/.*)?$`)

// userTildePath is `~name/…` with the user's home where the OS puts homes,
// as the CLI expands a Hermes command (expandUserTilde in
// src/mcp/writable-command.ts) — not from the password database, which the
// CLI can't read, so both judge the same path.
func userTildePath(v, goos string) (string, bool) {
	m := tildeUser.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	var home string
	switch {
	case m[1] == "root" && goos == "darwin":
		home = "/var/root"
	case m[1] == "root":
		home = "/root"
	case goos == "darwin":
		home = "/Users/" + m[1]
	default:
		home = "/home/" + m[1]
	}
	return home + m[2], true
}

// recordMissingTarget records, for a config-named path that doesn't exist
// (or a link that leads nowhere), what a local scan stats to tell who can
// create it: each missing directory above it as absent, and the mode and
// owner of every existing directory up to the root. A link that leads
// nowhere (or that the kernel won't follow: Linux protected_symlinks, a
// denied stat) has its chain and own owner recorded, and the same for where
// it leads.
func (c *collector) recordMissingTarget(snapshot *ProbeSnapshot, p string) {
	e, ok := snapshot.Files[p]
	if !ok || e.Exists {
		return
	}
	if !e.Denied {
		recordAbsentAncestors(snapshot, p)
	}
	if info, err := os.Lstat(p); err != nil || info.Mode()&os.ModeSymlink == 0 {
		return
	}
	c.recordLinkChain(snapshot, p)
	cur := p
	for hops := 0; hops < maxExplicitLinkHops; hops++ {
		target, ok := snapshot.Symlinks[cur]
		if !ok {
			return
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		cur = filepath.Clean(target)
		// whether it is there (metadata only), and the directories above it
		if _, done := snapshot.Files[cur]; !done {
			c.collectPath(snapshot, cur, cur, true, false)
		}
		recordAbsentAncestors(snapshot, cur)
	}
}

// recordAbsentAncestors walks up from p's directory: directories that don't
// exist are recorded as absent entries, the existing ones (from the nearest
// up to the root) by mode and owner.
func recordAbsentAncestors(snapshot *ProbeSnapshot, p string) {
	missing := true
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		if missing {
			if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
				if _, ok := snapshot.Files[dir]; !ok {
					snapshot.Files[dir] = FileEntry{Exists: false}
				}
			} else {
				missing = false
			}
		}
		if !missing {
			if _, ok := snapshot.DirectoryModes[dir]; !ok {
				recordDirMode(snapshot, dir)
			}
		}
		if filepath.Dir(dir) == dir {
			return
		}
	}
}

// recordLinkOwner stores a link's own [uid, gid] (from its lstat).
func recordLinkOwner(snapshot *ProbeSnapshot, p string, info os.FileInfo) {
	if uid, gid, ok := fileOwner(info); ok {
		if snapshot.LinkOwners == nil {
			snapshot.LinkOwners = make(map[string][2]int)
		}
		snapshot.LinkOwners[p] = [2]int{uid, gid}
	}
}

// dotDotSpelling is p as the kernel reads a `..` in it (launchPathSpelling in
// src/mcp/writable-command.ts): each `..` taken from where the path before it
// leads, its links followed first (`/p/safe/lnk/../bin/cmd` with `lnk` →
// `/p/ww/bin` is `/p/ww/bin/cmd`); what follows the last `..` keeps its
// spelling. The links it follows are recorded so the CLI walks the same way
// on the snapshot. A link that is a scanned home or above one is neither
// followed nor recorded (see linkCandidates). ok is false without a `..`.
func (c *collector) dotDotSpelling(snapshot *ProbeSnapshot, p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
		return "", false
	}
	var parts []string
	for _, comp := range strings.Split(p, "/") {
		if comp != "" && comp != "." {
			parts = append(parts, comp)
		}
	}
	last := -1
	for i, comp := range parts {
		if comp == ".." {
			last = i
		}
	}
	if last < 0 {
		return "", false
	}
	queue := append([]string{}, parts[:last+1]...)
	cur := "/"
	for hops := 0; len(queue) > 0; {
		comp := queue[0]
		queue = queue[1:]
		if comp == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		target, ok := c.followableLink(snapshot, next, hops)
		if !ok {
			cur = next
			continue
		}
		hops++
		if strings.HasPrefix(target, "/") {
			cur = "/"
		}
		var rest []string
		for _, t := range strings.Split(target, "/") {
			if t != "" && t != "." {
				rest = append(rest, t)
			}
		}
		queue = append(rest, queue...)
	}
	return filepath.Join(append([]string{cur}, parts[last+1:]...)...), true
}

// followableLink is the target of link p, recorded with its owner, when a
// walk may follow it.
func (c *collector) followableLink(snapshot *ProbeSnapshot, p string, hops int) (string, bool) {
	if hops >= maxExplicitLinkHops {
		return "", false
	}
	for _, h := range c.homes {
		if within(filepath.Clean(h), p) {
			return "", false
		}
	}
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	target, err := os.Readlink(p)
	if err != nil {
		return "", false
	}
	if snapshot.Symlinks == nil {
		snapshot.Symlinks = make(map[string]string)
	}
	snapshot.Symlinks[p] = target
	recordLinkOwner(snapshot, p, info)
	return target, true
}

// recordDeniedLink records a link a wildcard segment (seg, not the last of
// its pattern) matches in dir whose target can't be stat'd for lack of
// permission (`extensions/evil -> ~/locked/evil`, ~/locked mode 000): its
// target, and a denied entry — the CLI reports what it hides as a read
// failure, as a local stat of it fails, instead of finding nothing there.
// Skills trees are left as their walk records them.
func (c *collector) recordDeniedLink(snapshot *ProbeSnapshot, dir string, e fs.DirEntry, seg string) {
	if c.inSkillTree || seg == "**" || e.Type()&os.ModeSymlink == 0 {
		return
	}
	if ok, _ := doublestar.Match(seg, e.Name()); !ok {
		return
	}
	p := filepath.Join(dir, e.Name())
	if _, err := os.Stat(p); err == nil || !os.IsPermission(err) {
		return
	}
	if _, done := snapshot.Files[p]; done {
		return
	}
	if snapshot.Symlinks == nil {
		snapshot.Symlinks = make(map[string]string)
	}
	recordSymlink(snapshot.Symlinks, p)
	if info, err := os.Lstat(p); err == nil {
		recordLinkOwner(snapshot, p, info)
	}
	snapshot.Files[p] = FileEntry{Exists: false, Denied: true}
}
