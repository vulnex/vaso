package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sensitiveSinkPatterns mirrors SENSITIVE_SINKS in
// src/analyzers/sensitive-paths.ts pattern for pattern, in the same order
// (all case-insensitive there). The two lists must stay identical:
// TestSensitiveSinksMatchTS here and src/analyzers/sensitive-paths.test.ts
// on the TS side both fail when they drift.
var sensitiveSinkPatterns = []string{
	`(^|\/)\.ssh(\/|$)`,
	`authorized_keys`,
	`(^|\/)\.aws(\/|$)`,
	`(^|\/)\.gnupg(\/|$)`,
	`(^|\/)\.kube(\/|$)`,
	`(^|\/)\.docker(\/|$)`,
	`(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin)$`,
	`^\/etc(\/|$)`,
}

var sensitiveSinks = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(sensitiveSinkPatterns))
	for i, p := range sensitiveSinkPatterns {
		res[i] = regexp.MustCompile("(?i)" + p)
	}
	return res
}()

// sinkSet is the set of sensitive sinks (by index) a path matches.
func sinkSet(p string) map[int]bool {
	set := make(map[int]bool)
	slash := filepath.ToSlash(p)
	for i, re := range sensitiveSinks {
		if re.MatchString(slash) {
			set[i] = true
		}
	}
	return set
}

// escapesToSink reports whether p is reached through a symlink — base
// itself or a path component below it — that points into a sensitive
// location base does not already name. base is the part of the path VASO
// chose: an explicit manifest path, or a glob's static prefix. A skill linking
// to ~/.ssh or ~/.aws/credentials is the GhostApproval artefact SKL-013
// reports from the link target; the content behind it never leaves the host.
// A unit under /etc/systemd/system linking elsewhere in /etc is not an
// escape, and neither is a real directory that happens to be named .ssh.
// Mirrors sinkLink in src/core/skill-walk.ts.
func escapesToSink(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	named := sinkSet(base)
	if linkIntoSink(base, named) {
		return true
	}
	if rel == "." {
		return false
	}
	cur := base
	for _, comp := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, comp)
		if linkIntoSink(cur, named) {
			return true
		}
	}
	return false
}

// linkIntoSink: link is a symlink whose target — resolved, or as written
// (macOS resolves /etc to /private/etc) — matches a sink outside named.
func linkIntoSink(link string, named map[int]bool) bool {
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	var targets []string
	if real, err := filepath.EvalSymlinks(link); err == nil {
		targets = append(targets, real)
	}
	if raw, err := os.Readlink(link); err == nil {
		if !filepath.IsAbs(raw) {
			raw = filepath.Join(filepath.Dir(link), raw)
		}
		targets = append(targets, filepath.Clean(raw))
	}
	for _, t := range targets {
		for i := range sinkSet(t) {
			if !named[i] {
				return true
			}
		}
	}
	return false
}
