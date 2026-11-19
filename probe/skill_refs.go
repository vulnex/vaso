package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// vendorReference is a relative path in a SKILL.md that goes through a
// vendor-named folder (`node node_modules/helper/index.js`, `bash
// .cache/run.sh`): the skills walk skips those folders, so the file a skill
// runs from one is collected by name. Mirrors VENDOR_REFERENCE in
// src/core/skill-tree-files.ts (TestVendorReferenceMatchesTS).
var vendorReference = regexp.MustCompile("(?:^|[\\s\\x60'\"(=:])(?:\\./)?((?:[\\w.@+-]+/)*(?:node_modules|\\.git|\\.next|\\.cache|\\.venv|venv|__pycache__)/(?:[\\w.@+-]+/)*[\\w.@+-]+)")

// maxVendorReferences mirrors MAX_VENDOR_REFERENCES: references read from one SKILL.md.
const maxVendorReferences = 64

// vendorReferences: the vendor-folder paths a SKILL.md names, relative to
// its folder, in order, without duplicates, none with a `.` or `..` segment
// (vendorReferences in src/core/skill-tree-files.ts).
func vendorReferences(text string) []string {
	var out []string
	seen := map[string]bool{}
	// FindAll does not overlap matches, as the TS loop (lastIndex) doesn't
	for _, m := range vendorReference.FindAllStringSubmatch(text, -1) {
		if len(out) >= maxVendorReferences {
			break
		}
		ref := m[1]
		dot := false
		for _, s := range strings.Split(ref, "/") {
			if s == "." || s == ".." {
				dot = true
				break
			}
		}
		if dot || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

// collectVendorReferences collects, for each SKILL.md among a skills glob's
// matches, the files and folders it names inside vendor folders the glob
// skips (folders as their mode only): the CLI reads such a file as a skill
// file and reports such a folder as not scanned, as a local scan does.
//
// It returns the regular files among them (collected now or before): with
// the glob's own files, the sources collectVendorLoads starts from.
func (c *collector) collectVendorReferences(snapshot *ProbeSnapshot, pattern string, matches []string) []string {
	var files []string
	for _, match := range matches {
		if !strings.EqualFold(filepath.Base(match), "SKILL.md") {
			continue
		}
		entry, ok := snapshot.Files[match]
		if !ok || !entry.Exists || entry.ContentOmitted || entry.Denied {
			continue
		}
		text := entry.Content
		if entry.Encoding == "base64" {
			raw, err := base64.StdEncoding.DecodeString(entry.Content)
			if err != nil {
				continue
			}
			text = string(raw)
		}
		dir := filepath.Dir(match)
		for _, ref := range vendorReferences(text) {
			p := filepath.Join(dir, filepath.FromSlash(path.Clean(ref)))
			if !c.excluded(pattern, p) {
				continue
			}
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				files = append(files, p)
			}
			if _, done := snapshot.Files[p]; done {
				continue
			}
			if _, done := snapshot.DirectoryModes[p]; done {
				continue
			}
			if _, err := os.Stat(p); err != nil {
				continue
			}
			c.collectPath(snapshot, p, globBase(pattern), false, false)
		}
	}
	return files
}

// relativeLoad is a relative module a script loads (`require('../node_modules/x')`,
// `import y from './.cache/boot.js'`); mirrors RELATIVE_LOAD in
// src/core/skill-tree-files.ts (TestRelativeLoadMatchesTS).
var relativeLoad = regexp.MustCompile(`(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+)(?:'(\.\.?/[^'\n]{1,256})'|"(\.\.?/[^"\n]{1,256})")`)

// loadSourceExtensions mirrors LOAD_SOURCE_EXTENSIONS; maxVendorLoads and
// maxVendorLoadDepth mirror MAX_VENDOR_LOADS and MAX_VENDOR_LOAD_DEPTH.
var loadSourceExtensions = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true}

const (
	maxVendorLoads     = 64
	maxVendorLoadDepth = 3
)

// isLoadSource: a file whose loads are followed (isLoadSource in TS).
func isLoadSource(p string) bool {
	return filepath.Base(p) == "package.json" || loadSourceExtensions[strings.ToLower(filepath.Ext(p))]
}

// loadReferences: what a source loads, relative to its folder (loadReferences in TS).
func loadReferences(p, text string) []string {
	if filepath.Base(p) == "package.json" {
		return vendorReferences(text)
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range relativeLoad.FindAllStringSubmatch(text, -1) {
		if len(out) >= maxVendorReferences {
			break
		}
		spec := m[1]
		if spec == "" {
			spec = m[2]
		}
		if !seen[spec] {
			seen[spec] = true
			out = append(out, spec)
		}
	}
	return out
}

// loadCandidates mirrors loadCandidates in TS: a folder's package.json main
// first, then the path, its .js/.mjs/.cjs forms and its index files.
func loadCandidates(p, main string, hasMain bool) []string {
	var out []string
	if hasMain {
		m := filepath.Join(p, filepath.FromSlash(main))
		out = append(out, m, m+".js", filepath.Join(m, "index.js"))
	}
	return append(out, p, p+".js", p+".mjs", p+".cjs", filepath.Join(p, "index.js"), filepath.Join(p, "index.mjs"), filepath.Join(p, "index.cjs"))
}

// snapshotText is a collected file's content, decoded; false when it has none.
func snapshotText(snapshot *ProbeSnapshot, p string) (string, bool) {
	entry, ok := snapshot.Files[p]
	if !ok || !entry.Exists || entry.ContentOmitted || entry.Denied {
		return "", false
	}
	if entry.Encoding == "base64" {
		raw, err := base64.StdEncoding.DecodeString(entry.Content)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
	return entry.Content, true
}

// collectVendorLoads collects the vendor-folder files a skills glob's
// scripts load from there and its package.json scripts run, followed from
// the files they add — vendorLoads in src/core/utils.ts, in the same order
// and to the same bounds. referenced are the files collectVendorReferences
// found (the CLI lists them among the tree's files).
func (c *collector) collectVendorLoads(snapshot *ProbeSnapshot, pattern string, matches, referenced []string) {
	known := map[string]bool{}
	var level []string
	add := func(p string) {
		if known[p] {
			return
		}
		if info, err := os.Stat(p); err != nil || !info.Mode().IsRegular() {
			return
		}
		known[p] = true
		if isLoadSource(p) {
			level = append(level, p)
		}
	}
	for _, m := range matches {
		if !c.excluded(pattern, m) {
			add(m)
		}
	}
	for _, p := range referenced {
		add(p)
	}
	sort.Strings(level)
	added := 0
	for depth := 0; depth < maxVendorLoadDepth && len(level) > 0 && added < maxVendorLoads; depth++ {
		var next []string
		for _, source := range level {
			text, ok := snapshotText(snapshot, source)
			if !ok {
				continue
			}
			for _, ref := range loadReferences(source, text) {
				if added >= maxVendorLoads {
					return
				}
				p := filepath.Join(filepath.Dir(source), filepath.FromSlash(ref))
				if !c.excluded(pattern, p) {
					continue
				}
				target, ok := c.resolveLoad(snapshot, pattern, p)
				if !ok || known[target] {
					continue
				}
				known[target] = true
				ext := strings.ToLower(filepath.Ext(target))
				if metadataOnlyExtensions[ext] && !skillBinaryExtensions[ext] {
					continue
				}
				if credentialName.MatchString(filepath.Base(target)) && !programHeader(target) {
					continue
				}
				if _, done := snapshot.Files[target]; !done {
					c.collectPath(snapshot, target, globBase(pattern), false, false)
				}
				added++
				if isLoadSource(target) {
					next = append(next, target)
				}
			}
		}
		sort.Strings(next)
		level = next
	}
}

// resolveLoad: the first load candidate of p that is a regular file in a
// vendor folder of the tree. A folder's package.json is collected when its
// main is read: the CLI reads it there too.
func (c *collector) resolveLoad(snapshot *ProbeSnapshot, pattern, p string) (string, bool) {
	main, hasMain := "", false
	if info, err := os.Stat(p); err == nil && info.IsDir() {
		pj := filepath.Join(p, "package.json")
		if st, err := os.Stat(pj); err == nil && st.Mode().IsRegular() {
			if _, done := snapshot.Files[pj]; !done {
				c.collectPath(snapshot, pj, globBase(pattern), false, false)
			}
			if text, ok := snapshotText(snapshot, pj); ok {
				var pkg struct {
					Main interface{} `json:"main"`
				}
				if json.Unmarshal([]byte(text), &pkg) == nil {
					if m, ok := pkg.Main.(string); ok && strings.TrimSpace(m) != "" {
						main, hasMain = m, true
					}
				}
			}
		}
	}
	for _, cand := range loadCandidates(p, main, hasMain) {
		if !c.excluded(pattern, cand) {
			continue
		}
		if info, err := os.Stat(cand); err == nil && info.Mode().IsRegular() {
			return cand, true
		}
	}
	return "", false
}
