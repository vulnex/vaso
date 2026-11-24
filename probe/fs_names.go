package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// File names that are not UTF-8 (Linux names are bytes: `\xfe.js`) are
// written without loss: each byte that is not part of a well-formed UTF-8
// sequence becomes the JSON escape `\udcXX` (the lone surrogate U+DC00+byte,
// as Python's surrogateescape writes it), which is how the CLI lists such a
// name locally (src/core/fs-names.ts). encoding/json replaces invalid bytes
// with U+FFFD, which made `\xfe.js` and `\xff.js` one key — only one of the
// two files reached the checks.
//
// encoding/json can't write a lone surrogate, so the snapshot's path strings
// first carry each such byte as NUL + a per-run random token + two hex digits
// (NUL never occurs in a path); the encoded output then has `\u0000<token>`
// turned into `\udc`. The token keeps file content that happens to hold a
// NUL from being rewritten. Shared corpus: testdata/fs-name-escapes.json.

// newEscapeToken returns the per-run marker (16 lowercase hex digits).
func newEscapeToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a fixed marker; NUL never occurs in a path anyway.
		return "7f3a9c51e2d84b06"
	}
	return hex.EncodeToString(b)
}

// escapeName returns s with every byte outside a well-formed UTF-8 sequence
// replaced by the marker, and whether it changed anything.
func escapeName(s, token string) (string, bool) {
	if utf8.ValidString(s) {
		return s, false
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			b.WriteByte(0)
			b.WriteString(token)
			b.WriteString(hex.EncodeToString([]byte{s[i]}))
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String(), true
}

// escapeSnapshotNames rewrites every path the snapshot holds (map keys,
// listing names, link targets) that is not UTF-8; it reports whether any was.
func escapeSnapshotNames(s *ProbeSnapshot, token string) bool {
	changed := false
	name := func(p string) string {
		out, ok := escapeName(p, token)
		changed = changed || ok
		return out
	}
	names := func(list []string) []string {
		for i, p := range list {
			list[i] = name(p)
		}
		return list
	}
	if s.Files != nil {
		files := make(map[string]FileEntry, len(s.Files))
		for k, v := range s.Files {
			v.HardLinkOf = name(v.HardLinkOf)
			files[name(k)] = v
		}
		s.Files = files
	}
	if s.Directories != nil {
		dirs := make(map[string][]string, len(s.Directories))
		for k, v := range s.Directories {
			dirs[name(k)] = names(v)
		}
		s.Directories = dirs
	}
	s.DirectoryModes = escapeKeys(s.DirectoryModes, name)
	s.Owners = escapeKeys(s.Owners, name)
	s.LinkOwners = escapeKeys(s.LinkOwners, name)
	s.ConfigTrees = escapeKeys(s.ConfigTrees, name)
	if s.Symlinks != nil {
		links := make(map[string]string, len(s.Symlinks))
		for k, v := range s.Symlinks {
			links[name(k)] = name(v)
		}
		s.Symlinks = links
	}
	if s.ResolvedDirs != nil {
		dirs := make(map[string]string, len(s.ResolvedDirs))
		for k, v := range s.ResolvedDirs {
			dirs[name(k)] = name(v)
		}
		s.ResolvedDirs = dirs
	}
	if s.WildcardNames != nil {
		wn := make(map[string][]string, len(s.WildcardNames))
		for k, v := range s.WildcardNames {
			wn[name(k)] = names(v)
		}
		s.WildcardNames = wn
	}
	s.Homedir = name(s.Homedir)
	s.Privilege.SkippedPaths = names(s.Privilege.SkippedPaths)
	return changed
}

func escapeKeys[V any](m map[string]V, name func(string) string) map[string]V {
	if m == nil {
		return nil
	}
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[name(k)] = v
	}
	return out
}

// restoreEscapes turns the markers in encoded JSON into `\udcXX` escapes.
func restoreEscapes(encoded []byte, token string) []byte {
	return bytes.ReplaceAll(encoded, []byte(`\u0000`+token), []byte(`\udc`))
}
