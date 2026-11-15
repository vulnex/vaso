package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Where a skills tree may be walked from, and where a link met while walking
// one may lead. A skills directory — one an agent's config sets, or an
// agent's own default one that a link takes out of the home — is walked
// wherever it is, except in these places, judged on the path as written and
// once resolved:
//
//   - the filesystem root;
//   - the scanned user's home itself, or a directory above it;
//   - another user's home (/home/<u>, /Users/<u>, /root, and /home or /Users
//     themselves) — one holding the scanned home is that home's ancestor,
//     not another user's;
//   - an OS directory (/etc, /usr, /var, /bin, /sbin, /lib*, /System,
//     /Library, /dev, /proc, /sys, /boot, /run; /private/etc and
//     /private/var) — unless inside the scanned home;
//   - a credential store or sensitive location (SENSITIVE_SINKS).
//
// /opt, /srv, /nix/store, /Volumes/*, /mnt/*, /media/* and /tmp are not
// refused: skills live there (a home-manager store, a team volume).
// src/core/skill-root-scope.ts applies the same rule to local scans;
// testdata/skill-scope-cases.json holds the table both sides test.

// systemTops are the top-level OS directories (lower case) a skills tree is
// never walked in (also under /private on macOS: etc, var).
var systemTops = map[string]bool{
	"etc": true, "usr": true, "var": true, "bin": true, "sbin": true,
	"system": true, "library": true, "dev": true, "proc": true, "sys": true,
	"boot": true, "run": true,
}

// scopeLabel names why a path is not a place a skills tree is walked:
// "root", "home" (the scanned home or above), "other-home:<dir>",
// "system:/<top>" or "sink:<index into SENSITIVE_SINKS>".
//
// own are the spellings of the home of the user whose tree it is (written
// and resolved; none for a tree in no scanned home); all are every scanned
// home's spellings (own included) — a directory above any of them is refused,
// and an area holding one is not another user's home.
func scopeLabels(p string, own, all []string) []string {
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "/" {
		return []string{"root"}
	}
	for _, h := range all {
		if within(filepath.Clean(h), p) {
			return []string{"home"}
		}
	}
	var out []string
	for i := range sinkSet(p) {
		out = append(out, "sink:"+itoa(i))
	}
	for _, h := range own {
		if strictlyWithin(p, filepath.ToSlash(filepath.Clean(h))) {
			sort.Strings(out)
			return out
		}
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	top := strings.ToLower(parts[0])
	sys := parts
	if top == "private" {
		if len(parts) == 1 {
			out = append(out, "system:/private")
		} else if t := strings.ToLower(parts[1]); t == "etc" || t == "var" {
			sys = parts[1:]
		}
	}
	if t := strings.ToLower(sys[0]); systemTops[t] || strings.HasPrefix(t, "lib") {
		out = append(out, "system:/"+t)
	}
	if homeDir := otherHomeDir(parts); homeDir != "" {
		holdsScanned := false
		for _, h := range all {
			if within(filepath.ToSlash(filepath.Clean(h)), homeDir) {
				holdsScanned = true
				break
			}
		}
		if !holdsScanned {
			out = append(out, "other-home:"+homeDir)
		}
	}
	sort.Strings(out)
	return out
}

// otherHomeDir is the user home (or home area) p lies in, by location:
// /home, /Users, /home/<u>, /Users/<u>, /root; "" otherwise.
func otherHomeDir(parts []string) string {
	switch strings.ToLower(parts[0]) {
	case "home", "users":
		if len(parts) == 1 {
			return "/" + parts[0]
		}
		return "/" + parts[0] + "/" + parts[1]
	case "root":
		return "/" + parts[0]
	}
	return ""
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

// scopeHomes are the spellings of home (written and resolved) and of every
// home a tree is judged against (home, the probe user's, the scanned ones).
func scopeHomes(home string, others []string) (own, all []string) {
	add := func(list []string, h string) []string {
		if h == "" || !filepath.IsAbs(h) {
			return list
		}
		for _, s := range []string{filepath.Clean(h), resolveExisting(filepath.Clean(h))} {
			dup := false
			for _, x := range list {
				if x == s {
					dup = true
					break
				}
			}
			if !dup {
				list = append(list, s)
			}
		}
		return list
	}
	own = add(nil, home)
	all = append([]string(nil), own...)
	if h, err := os.UserHomeDir(); err == nil {
		all = add(all, h)
	}
	for _, h := range others {
		all = add(all, h)
	}
	return own, all
}

// pathScope is every label of p once resolved, and as written — of the
// written spelling only its credential stores when p resolves into the home
// (a link to the home is the home, wherever the link is).
func pathScope(p string, own, all []string) map[string]bool {
	set := make(map[string]bool)
	p = filepath.Clean(p)
	real := resolveExisting(p)
	for _, l := range scopeLabels(real, own, all) {
		set[l] = true
	}
	inHome := false
	for _, h := range own {
		if strictlyWithin(filepath.ToSlash(real), filepath.ToSlash(filepath.Clean(h))) {
			inHome = true
			break
		}
	}
	for _, l := range scopeLabels(p, own, all) {
		if !inHome || strings.HasPrefix(l, "sink:") {
			set[l] = true
		}
	}
	return set
}

// treeAllowed: a skills tree may be walked from p, or a link met while
// walking one (from an allowed base) may lead to p — for the tree of the
// user whose home is home. See the rule above.
func treeAllowed(p, home string) bool {
	p, home = filepath.Clean(p), filepath.Clean(home)
	if !filepath.IsAbs(p) || !filepath.IsAbs(home) || home == string(filepath.Separator) {
		return false
	}
	own, all := scopeHomes(home, nil)
	return len(pathScope(p, own, all)) == 0
}

// baseScope is what linkInScope needs of a manifest skills glob's base.
type baseScope struct {
	own, all []string
	labels   map[string]bool
}

// skillLinkOutOfScope: while walking a manifest skills tree (not a
// config-derived one, which treeAllowed bounds), the file at p is behind a
// link that leads somewhere the tree's base may not (linkInScope). A link
// into a credential store is escapesToSink's (it names the sink locally).
func (c *collector) skillLinkOutOfScope(base, p string) bool {
	if !c.inSkillTree || c.configTree {
		return false
	}
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	return !c.linkInScope(base, p)
}

// linkInScope: a link at p met while walking the manifest skills tree based
// at base may be followed (or the file behind it read) — what it leads to, as
// written and resolved, carries no label the base itself doesn't (a bundled
// tree under /usr may link within /usr; a tree in the home may not link into
// /etc, another user's home or a credential store). Mirrors walkSkillTree in
// src/core/skill-walk.ts.
func (c *collector) linkInScope(base, p string) bool {
	base = filepath.Clean(base)
	sc, ok := c.baseScopes[base]
	if !ok {
		sc.own, sc.all = scopeHomes(c.homeOf(base), c.homes)
		sc.labels = pathScope(base, sc.own, sc.all)
		if c.baseScopes == nil {
			c.baseScopes = make(map[string]baseScope)
		}
		c.baseScopes[base] = sc
	}
	targets := []string{p}
	if raw, err := os.Readlink(p); err == nil {
		if !filepath.IsAbs(raw) {
			raw = filepath.Join(filepath.Dir(p), raw)
		}
		targets = append(targets, raw)
	}
	for _, t := range targets {
		for l := range pathScope(t, sc.own, sc.all) {
			if !sc.labels[l] {
				return false
			}
		}
	}
	return true
}

// linkedOutRefused: dir lies in a scanned home as written (outside its
// credential stores), but a link takes it to a place no skills tree is walked
// (treeAllowed: an OS directory, another user's home, a credential store) — a
// directory listing there would ship what that place holds.
func (c *collector) linkedOutRefused(dir string) bool {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || len(sinkSet(dir)) > 0 {
		return false
	}
	home := ""
	for _, h := range c.homes {
		if h = filepath.Clean(h); strictlyWithin(dir, h) && len(h) > len(home) {
			home = h
		}
	}
	return home != "" && !treeAllowed(dir, home)
}
