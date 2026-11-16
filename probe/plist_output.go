package main

import (
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// runManifestCommand runs a manifest command. plutil's conversion of a
// preference plist to XML (`plutil -convert xml1 -o - <file>`) is the plist
// itself, which the CLI reads as a config: its output is disguised like a
// collected file — stand-ins keep a key's shape, so the CLI judges it as a
// local scan does (CFG-002) — and an account's email address is disguised as
// in any file. Other commands' output is redacted (runCommand).
func (c *collector) runManifestCommand(req CommandRequest, path string) CommandOutput {
	if plistConversion(req) {
		return runCommandScrubbed(req, path, c.disguisePlistXML)
	}
	return runCommand(req, path)
}

func plistConversion(req CommandRequest) bool {
	a := req.Args
	return filepath.Base(req.Cmd) == "plutil" && len(a) == 5 && a[0] == "-convert" && a[1] == "xml1" && a[2] == "-o" && a[3] == "-"
}

// plistKeyString: <key>NAME</key> then <string>VALUE</string> (groups: name 1, value 2).
var plistKeyString = regexp.MustCompile(`<key>([^<]{1,128})</key>\s*<string>([^<]*)</string>`)

// disguisePlistXML disguises an XML plist's text: what the file rules find
// (token shapes, URLs, email addresses), and a string under a credential
// key, which the line rules can't pair with its <key> line.
func (c *collector) disguisePlistXML(s string) string {
	s = string(c.scrubSecrets("plutil-output.plist", []byte(s)))
	s = replaceMatches(plistKeyString, s, func(m submatch) string {
		key, _ := m.group(1)
		value, _ := m.group(2)
		if value == "" || !isSecretKeyName(key) || !keyedSecret(key, value) {
			return m.text()
		}
		return m.with(2, 2, c.disguiseKeyed(key, value))
	})
	return c.disguisePlistStructure(s)
}

// plistToken: the plist XML elements the structure walk follows — a <key>,
// a container opening or closing (or an empty one), a <string>, a <data>.
var plistToken = regexp.MustCompile(`<key>([^<]{0,128})</key>|<(array|dict)>|</(array|dict)>|<(?:array|dict)/>|<string>([^<]*)</string>|<data>([^<]*)</data>`)

// disguisePlistStructure applies what secretContainers does for JSON to the
// plist's structure: under a credential container key (creds, tokens,
// secrets…), at any depth, a string that is a credential by its own key or
// looks like one is disguised (`creds` → array → dict → `k` → <string>). A
// <data> blob is bytes the line rules never see: decoded, its email
// addresses are disguised (and, when it is text, what the file rules find),
// and it is written back base64.
func (c *collector) disguisePlistStructure(s string) string {
	type frame struct{ key string }
	var stack []frame
	pending := ""
	container := func() string {
		for i := len(stack) - 1; i >= 0; i-- {
			if secretContainerKey(stack[i].key) {
				return stack[i].key
			}
		}
		return ""
	}
	return replaceMatches(plistToken, s, func(m submatch) string {
		switch {
		case m.g[2] >= 0: // <key>
			pending, _ = m.group(1)
			return m.text()
		case m.g[4] >= 0: // <array> / <dict>
			stack = append(stack, frame{pending})
			pending = ""
			return m.text()
		case m.g[6] >= 0: // </array> / </dict>
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			pending = ""
			return m.text()
		case m.g[8] >= 0: // <string>
			own := pending
			pending = ""
			value, _ := m.group(4)
			parent := container()
			if value == "" || parent == "" {
				return m.text()
			}
			if own != "" {
				if name := containerChildKey(parent, own); name != "" && keyedSecret(name, value) {
					return m.with(4, 4, c.disguiseKeyed(name, value))
				}
				if settingChildName.MatchString(own) {
					return m.text()
				}
			}
			if looksRandom(value, 16) || looksLikeSecret(value) {
				return m.with(4, 4, c.disguise(value))
			}
			return m.text()
		case m.g[10] >= 0: // <data>
			pending = ""
			blob, _ := m.group(5)
			if out, ok := c.disguisePlistData(blob); ok {
				return m.with(5, 5, out)
			}
			return m.text()
		}
		pending = ""
		return m.text()
	})
}

// disguisePlistData is a <data> blob (base64, wrapped) with what it holds
// disguised, re-encoded on one line; false when nothing changed.
func (c *collector) disguisePlistData(blob string) (string, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, blob)
	raw, err := base64.StdEncoding.DecodeString(compact)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	text := string(raw)
	out := c.disguiseEmails(text)
	if utf8.ValidString(out) {
		out = string(c.scrubSecrets("plutil-data.txt", []byte(out)))
	}
	if out == text {
		return "", false
	}
	return base64.StdEncoding.EncodeToString([]byte(out)), true
}
