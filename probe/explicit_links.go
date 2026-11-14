package main

import (
	"os"
	"path/filepath"
	"strings"
)

// maxExplicitLinkHops bounds how many links one explicit path's chain may
// take (a local realpath gives up with ELOOP at 40).
const maxExplicitLinkHops = 40

// recordExplicitLinks records the symlinks a local realpath of an explicit
// manifest path goes through: the path itself and, below a scanned home, its
// directories — then the same along each link's target. A credential file
// linked from a private directory into an open one is reachable by its real
// path; the CLI resolves it through these links (SnapshotFSProvider.realpath)
// and judges the real parents, whose modes recordAncestorModes stores.
// Directories above a home (/var → /private/var on macOS) are left as they
// are: a stat through them answers with the same modes, and resolving every
// collected path through them would leave the snapshot's keys behind.
func (c *collector) recordExplicitLinks(snapshot *ProbeSnapshot, p string) {
	c.explicit = append(c.explicit, p)
	pending := []string{filepath.Clean(p)}
	seen := make(map[string]bool)
	for hops := 0; len(pending) > 0 && hops < maxExplicitLinkHops; hops++ {
		cur := pending[0]
		pending = pending[1:]
		for _, comp := range c.linkCandidates(cur) {
			if seen[comp] {
				continue
			}
			seen[comp] = true
			info, err := os.Lstat(comp)
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			target, err := os.Readlink(comp)
			if err != nil {
				break
			}
			snapshot.Symlinks[comp] = target
			abs := target
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(filepath.Dir(comp), target)
			}
			rest, err := filepath.Rel(comp, cur)
			if err != nil {
				break
			}
			// the rest of cur now lies behind the link's target
			pending = append(pending, filepath.Clean(filepath.Join(abs, rest)))
			break
		}
	}
}

// linkCandidates are the components of p whose links are recorded, from the
// top: p itself, and each directory strictly below a scanned home.
func (c *collector) linkCandidates(p string) []string {
	var out []string
	for dir := filepath.Dir(p); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		for _, h := range c.homes {
			if h = filepath.Clean(h); dir != h && within(dir, h) {
				out = append(out, dir)
				break
			}
		}
	}
	// top first, as a realpath walks
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return append(out, p)
}

// resolveRecordedLinks resolves p through the recorded links only, component
// by component — what the CLI's snapshot realpath returns for it.
func resolveRecordedLinks(p string, symlinks map[string]string) string {
	rest := splitPath(filepath.Clean(p))
	current := string(filepath.Separator)
	for hops := 0; len(rest) > 0; {
		next := filepath.Join(current, rest[0])
		rest = rest[1:]
		target, ok := symlinks[next]
		if !ok {
			current = next
			continue
		}
		if hops++; hops > maxExplicitLinkHops {
			return p
		}
		resolved := target
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(filepath.Dir(next), target)
		}
		rest = append(splitPath(filepath.Clean(resolved)), rest...)
		current = string(filepath.Separator)
	}
	return current
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.Split(p, string(filepath.Separator)) {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}
