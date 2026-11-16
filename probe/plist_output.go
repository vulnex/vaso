package main

import (
	"path/filepath"
	"regexp"
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
	return replaceMatches(plistKeyString, s, func(m submatch) string {
		key, _ := m.group(1)
		value, _ := m.group(2)
		if value == "" || !isSecretKeyName(key) || !keyedSecret(key, value) {
			return m.text()
		}
		return m.with(2, 2, c.disguiseKeyed(key, value))
	})
}
