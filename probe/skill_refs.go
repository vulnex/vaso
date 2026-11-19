package main

import (
	"encoding/base64"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
func (c *collector) collectVendorReferences(snapshot *ProbeSnapshot, pattern string, matches []string) {
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
}
