package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// On a case-insensitive filesystem (macOS APFS by default) `/Users/U/FX/hu`
// opens the home `/Users/u/fx/hu`, but filepath.EvalSymlinks keeps the case
// it was given — so a home spelled in other letters wouldn't compare equal to
// the home. canonicalCase spells an existing path as the filesystem stores
// it, as a local scan's realpath does. Nothing is assumed about the
// filesystem: a name is respelled only where its other-case spelling opens
// the same file (the directory is case-insensitive) and the listing holds the
// stored name.

// maxCaseCache bounds the per-run memo of canonical spellings.
const maxCaseCache = 1 << 16

var (
	caseMu    sync.Mutex
	caseCache = map[string]string{}
	// caseNames memoizes directory listings (names only) read to respell.
	caseNames = map[string][]string{}
	// caseRecorder, while set, is told every path canonicalCase respelled
	// (written → stored), so a snapshot can carry the resolution.
	caseRecorder func(written, stored string)
)

// canonicalCase is p (absolute, cleaned, links already resolved) with every
// existing component spelled as stored; p itself when nothing differs.
func canonicalCase(p string) string {
	if !filepath.IsAbs(p) {
		return p
	}
	caseMu.Lock()
	defer caseMu.Unlock()
	return canonicalCaseLocked(filepath.Clean(p))
}

func canonicalCaseLocked(p string) string {
	if c, ok := caseCache[p]; ok {
		return c
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p
	}
	name := filepath.Base(p)
	dir := canonicalCaseLocked(parent)
	out := filepath.Join(dir, storedName(dir, name))
	if len(caseCache) >= maxCaseCache {
		caseCache = map[string]string{}
		caseNames = map[string][]string{}
	}
	caseCache[p] = out
	return out
}

// storedName is how dir's listing spells the entry name opens, or name.
//
// A name with letters beyond ASCII may also be stored in another Unicode
// normalization form (é as U+00E9, or e + U+0301; APFS opens either): when
// the listing doesn't hold name itself, the entry that is the same file is
// the stored spelling — a directory (never hard-linked), or the only entry
// that is that file.
func storedName(dir, name string) string {
	other := swapCase(name)
	ascii := isASCII(name)
	if other == name && ascii {
		return name
	}
	st, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		return name
	}
	// Case-sensitive here (or two distinct entries): the name is the entry
	if ascii {
		if ost, err := os.Lstat(filepath.Join(dir, other)); err != nil || !os.SameFile(st, ost) {
			return name
		}
	}
	names, ok := caseNames[dir]
	if !ok {
		if f, err := os.Open(dir); err == nil {
			names, _ = f.Readdirnames(-1)
			f.Close()
		}
		caseNames[dir] = names
	}
	for _, n := range names {
		if n == name {
			return name
		}
	}
	for _, n := range names {
		if strings.EqualFold(n, name) {
			if nst, err := os.Lstat(filepath.Join(dir, n)); err == nil && os.SameFile(st, nst) {
				return n
			}
		}
	}
	if ascii {
		return name
	}
	var same []string
	for _, n := range names {
		if nst, err := os.Lstat(filepath.Join(dir, n)); err == nil && os.SameFile(st, nst) {
			same = append(same, n)
		}
	}
	if len(same) == 1 || (len(same) > 0 && st.IsDir()) {
		return same[0]
	}
	return name
}

// isASCII: s holds only ASCII bytes (no other normalization form exists).
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// swapCase is s with the case of every letter that has another case swapped.
func swapCase(s string) string {
	return strings.Map(func(r rune) rune {
		if u := unicode.ToUpper(r); u != r {
			return u
		}
		return unicode.ToLower(r)
	}, s)
}

// realPath is filepath.EvalSymlinks spelled as stored (canonicalCase).
func realPath(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	return storedSpelling(real), nil
}

// storedSpelling is canonicalCase, reported to caseRecorder when it differs.
func storedSpelling(p string) string {
	c := canonicalCase(p)
	if c != p {
		noteRespelled(p, c)
	}
	return c
}

// noteRespelled tells caseRecorder (when set) that written is stored.
func noteRespelled(written, stored string) {
	caseMu.Lock()
	rec := caseRecorder
	caseMu.Unlock()
	if rec != nil {
		rec(written, stored)
	}
}

// recordRespellings makes every respelling canonicalCase does while the
// collector runs a ResolvedDirs entry — the CLI resolves a home written in
// other letters through it, as a local realpath does. The returned func
// stops recording.
func recordRespellings(snapshot *ProbeSnapshot) func() {
	caseMu.Lock()
	caseCache, caseNames = map[string]string{}, map[string][]string{}
	caseRecorder = func(written, stored string) {
		if !filepath.IsAbs(written) || !filepath.IsAbs(stored) {
			return
		}
		if snapshot.ResolvedDirs == nil {
			snapshot.ResolvedDirs = make(map[string]string)
		}
		key := filepath.ToSlash(filepath.Clean(written))
		if _, done := snapshot.ResolvedDirs[key]; done || len(snapshot.ResolvedDirs) >= maxResolvedDirs {
			return
		}
		snapshot.ResolvedDirs[key] = filepath.ToSlash(stored)
	}
	caseMu.Unlock()
	return func() {
		caseMu.Lock()
		caseRecorder = nil
		caseMu.Unlock()
	}
}
