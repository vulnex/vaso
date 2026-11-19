package main

import (
	"regexp"
	"strings"
)

// shellDefault is a ${VAR:-default} (${VAR-…}, ${VAR:=…}) value: the part
// before the default, the default, and the closing brace.
var shellDefault = regexp.MustCompile(`^(\s*(?:(?i:bearer|basic|token)\s+)?\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=])(.*)(\}\s*)$`)

// storedFallback is storedFallback in src/core/patterns.ts: under a
// credential-named key, the default a ${VAR:-default} value stores is the
// credential itself, however short (DB_PASS: ${DB_PASS:-Xe5rT2yQ8u}) — the
// reference rules count only a 16+ character one, and it shipped whole. The
// probe judges the name by isSecretKeyName (wider than the CLI's: a default
// disguised under a name the CLI doesn't read as a credential's is judged
// alike there, a reference with a default).
func storedFallback(key, value string) (head, fallback, tail string, ok bool) {
	if !isSecretKeyName(key) {
		return "", "", "", false
	}
	m := shellDefault.FindStringSubmatch(value)
	if m == nil {
		return "", "", "", false
	}
	fb := strings.TrimSpace(m[2])
	if fb == "" || isPlaceholderSecret(fb) || isSecretReference(fb) {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// disguiseFallback is the value with its stored default disguised (the
// reference around it kept), or ok false when it has none.
func (c *collector) disguiseFallback(key, value string) (string, bool) {
	head, fb, tail, ok := storedFallback(key, value)
	if !ok {
		return "", false
	}
	lead := len(fb) - len(strings.TrimLeft(fb, " \t"))
	core := strings.TrimSpace(fb)
	trail := len(fb) - lead - len(core)
	out := c.disguiseAs(core, strongCredentialKey(key), true)
	if out == core && !isPlaceholderSecret(core) {
		// not worth a stand-in as a value (a lowercase word): as a password
		out = c.disguiseAs(core, true, true)
	}
	return head + fb[:lead] + out + fb[len(fb)-trail:] + tail, true
}
