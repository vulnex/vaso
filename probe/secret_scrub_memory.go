package main

import (
	"regexp"
	"strings"
)

// Memory and instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, rules
// files) are prose; the CLI's memory checks (CC-012, DEV-007, QC-010,
// GHC-008, …) also report a quoted high-entropy string with no key name in
// them (findHighEntropyBlocks in src/analyzers/entropy.ts, called by
// scanMemorySecrets with 5.5 bits and 40 characters). No keyed rule finds
// it, so it shipped whole.

// memoryEntropyThreshold and memoryEntropyMinLen are ENTROPY_THRESHOLD and
// MIN_BLOCK_LEN in src/analyzers/memory-secrets.ts.
const (
	memoryEntropyThreshold = 5.5
	memoryEntropyMinLen    = 40
)

// quotedRuns are extractStrings' patterns, in its order.
var quotedRuns = []*regexp.Regexp{
	regexp.MustCompile(`"([^"]{10,})"`),
	regexp.MustCompile(`'([^']{10,})'`),
	regexp.MustCompile("`([^`]{10,})`"),
}

// proseBullet is the `* item` bullet scanMemorySecrets reads as prose (not a
// block comment's `*`).
var proseBullet = regexp.MustCompile(`^[ \t]*\*[ \t]`)

// memoryEntropyStrings are the strings of line findHighEntropyBlocks
// reports for a memory file: on a line of 40+ characters (trimmed) that is
// no comment, each quoted run of 40+ characters above 5.5 bits.
func memoryEntropyStrings(line string) []string {
	t := strings.TrimSpace(line)
	if utf16Len(t) < memoryEntropyMinLen {
		return nil
	}
	if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "*") && !proseBullet.MatchString(line) {
		return nil
	}
	var out []string
	for _, re := range quotedRuns {
		for _, m := range re.FindAllStringSubmatch(t, -1) {
			if utf16Len(m[1]) >= memoryEntropyMinLen && shannonEntropy(m[1]) > memoryEntropyThreshold {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// memoryAddressHead is what stays of a URL or a path the memory rule flags:
// its scheme and host, or its leading / or ~/.
var memoryAddressHead = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9+.-]*://[^/?#\s]*|~?/)`)

// disguiseMemoryAddress is the stand-in of a flagged string the stand-in
// rules keep whole (a URL, a path — dt24 g9-S3: the CLI flags those too):
// after its head, its letters and digits laid out anew with the counts they
// had (arrangeLike), so the entropy the check computes is the same number;
// punctuation stays where it is.
func disguiseMemoryAddress(v string) string {
	head := memoryAddressHead.FindString(v)
	for try := 0; try < 16; try++ {
		if out := head + arrangeLike("", head, v[len(head):], nil, false); out != v {
			return out
		}
	}
	return v
}

// disguiseMemoryEntropy replaces each string memoryEntropyStrings finds with
// its stand-in (same length, classes and entropy band: the check reports it
// alike) — a URL or a path too, whose head stays (disguiseMemoryAddress).
func (c *collector) disguiseMemoryEntropy(s string) string {
	lines := strings.Split(s, "\n")
	changed := false
	for i, line := range lines {
		for _, v := range memoryEntropyStrings(line) {
			d := c.disguise(v)
			if d == v {
				d = disguiseMemoryAddress(v)
			}
			if d != v {
				lines[i] = strings.ReplaceAll(lines[i], v, d)
				changed = true
			}
		}
	}
	if !changed {
		return s
	}
	return strings.Join(lines, "\n")
}
