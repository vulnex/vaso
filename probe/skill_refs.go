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
// builtLoad mirrors BUILT_LOAD in src/core/skill-tree-files.ts: a module
// path built from the script's folder out of literal segments
// (path.join(__dirname, ...), new URL(..., import.meta.url),
// os.path.join(os.path.dirname(__file__), ...)) and Python sys.path folders.
var builtLoad = regexp.MustCompile(`\b(?:path\.)?(?:join|resolve)\s*\(\s*(?:__dirname|import\.meta\.dirname)\s*((?:,\s*(?:'[^'\n]*'|"[^"\n]*")\s*)+)\)|\bnew\s+URL\s*\(\s*(?:'([^'\n]{1,256})'|"([^"\n]{1,256})")\s*,\s*import\.meta\.url\s*\)|\bos\.path\.join\s*\(\s*os\.path\.dirname\s*\(\s*(?:os\.path\.(?:abspath|realpath)\s*\(\s*__file__\s*\)|__file__)\s*\)\s*((?:,\s*(?:'[^'\n]*'|"[^"\n]*")\s*)+)\)|\bsys\.path\.(?:insert\s*\(\s*\d+\s*,|append\s*\()\s*(?:'([^'\n]{1,256})'|"([^"\n]{1,256})"|os\.path\.join\s*\(\s*os\.path\.dirname\s*\(\s*(?:os\.path\.(?:abspath|realpath)\s*\(\s*__file__\s*\)|__file__)\s*\)\s*((?:,\s*(?:'[^'\n]*'|"[^"\n]*")\s*)+)\))`)

var loadSegment = regexp.MustCompile(`'([^'\n]*)'|"([^"\n]*)"`)

var pyImport = regexp.MustCompile(`(?m)^[ \t]*(?:import[ \t]+([\w.]+(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[\w.]+(?:[ \t]+as[ \t]+\w+)?)*)|from[ \t]+(\w[\w.]*)[ \t]+import\b)`)

var loadSourceExtensions = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true, ".py": true}

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
	var found []foldedLoad
	for _, m := range relativeLoad.FindAllStringSubmatchIndex(text, -1) {
		g := 2
		if m[2] < 0 {
			g = 4
		}
		found = append(found, foldedLoad{m[0], text[m[g]:m[g+1]]})
	}
	loads, dirs := foldedLoads(text)
	found = append(found, loads...)
	// a sys.path folder: the modules the script imports from it
	if len(dirs) > 0 {
		modules := pythonImports(text)
		for _, d := range dirs {
			for _, mod := range modules {
				found = append(found, foldedLoad{d.at, d.spec + "/" + mod + ".py"}, foldedLoad{d.at, d.spec + "/" + mod + "/__init__.py"})
			}
		}
	}
	// in source order (a stable sort keeps a sys.path folder's modules together)
	sort.SliceStable(found, func(i, j int) bool { return found[i].at < found[j].at })
	var out []string
	seen := map[string]bool{}
	for _, f := range found {
		if len(out) >= maxVendorReferences {
			break
		}
		if !seen[f.spec] {
			seen[f.spec] = true
			out = append(out, f.spec)
		}
	}
	return out
}

// foldedLoad is a load specifier and its offset in the source.
type foldedLoad struct {
	at   int
	spec string
}

// relativeSpec mirrors relativeSpec in src/core/skill-tree-files.ts: literal
// segments as a relative specifier, refused when one is absolute.
func relativeSpec(segs []string) (string, bool) {
	if len(segs) > 16 {
		return "", false
	}
	var parts []string
	for _, s := range segs {
		if len([]rune(s)) > 256 || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.Contains(s, `\`) || strings.Contains(s, ":") {
			return "", false
		}
		for _, p := range strings.Split(s, "/") {
			if p != "" && p != "." {
				parts = append(parts, p)
			}
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return "./" + strings.Join(parts, "/"), true
}

// foldedLoads mirrors foldedLoads in src/core/skill-tree-files.ts: builtLoad
// matches as relative specifiers with their offsets — module paths, and
// Python sys.path folders.
func foldedLoads(text string) (loads, dirs []foldedLoad) {
	for _, m := range builtLoad.FindAllStringSubmatchIndex(text, -1) {
		group := func(g int) (string, bool) {
			if m[2*g] < 0 {
				return "", false
			}
			return text[m[2*g]:m[2*g+1]], true
		}
		var segs []string
		listed := false
		for _, g := range []int{1, 4, 7} {
			if list, ok := group(g); ok {
				for _, q := range loadSegment.FindAllStringSubmatch(list, -1) {
					if strings.HasPrefix(q[0], "'") {
						segs = append(segs, q[1])
					} else {
						segs = append(segs, q[2])
					}
				}
				listed = true
				break
			}
		}
		if !listed {
			for _, g := range []int{2, 3, 5, 6} {
				if single, ok := group(g); ok {
					segs = []string{single}
					break
				}
			}
		}
		spec, ok := relativeSpec(segs)
		if !ok {
			continue
		}
		_, d5 := group(5)
		_, d6 := group(6)
		_, d7 := group(7)
		if d5 || d6 || d7 {
			dirs = append(dirs, foldedLoad{m[0], spec})
		} else {
			loads = append(loads, foldedLoad{m[0], spec})
		}
	}
	return loads, dirs
}

// pythonImports mirrors pythonImports in src/core/skill-tree-files.ts: the
// top-level module names a Python file imports, in order, without duplicates.
func pythonImports(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range pyImport.FindAllStringSubmatchIndex(text, -1) {
		var names []string
		if m[2] >= 0 {
			for _, n := range strings.Split(text[m[2]:m[3]], ",") {
				n = strings.TrimSpace(n)
				if i := strings.IndexAny(n, " \t"); i >= 0 {
					n = n[:i]
				}
				names = append(names, n)
			}
		} else {
			names = []string{text[m[4]:m[5]]}
		}
		for _, n := range names {
			top := strings.Split(n, ".")[0]
			if top != "" && !seen[top] {
				seen[top] = true
				out = append(out, top)
			}
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
