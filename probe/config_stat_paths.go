package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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
