package main

import "strings"

// dotenvEscapedTail disguises what follows a single-quoted dotenv value
// closed by an escaped-looking quote: KEY='Ab3d\'Kl8m…' is read up to the
// \' (no escapes in single quotes, as VASO and dotenv read it), so only
// that part was disguised and the rest of the secret shipped as written.
// raw is the value as keyedValue left it; the tail up to the line's last
// quote gets a stand-in of its own.
func (c *collector) dotenvEscapedTail(key, raw string) string {
	if len(raw) < 2 || raw[0] != '\'' || !isSecretKeyName(key) {
		return raw
	}
	j := strings.IndexByte(raw[1:], '\'') + 1
	if j <= 1 || raw[j-1] != '\\' {
		return raw
	}
	rest := raw[j+1:]
	if i := strings.Index(rest, " #"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimRight(rest, " \t")
	if len(rest) < 2 || rest[len(rest)-1] != '\'' {
		return raw
	}
	tail := rest[:len(rest)-1]
	out := c.disguiseArgv(tail)
	if len(out) != len(tail) {
		return raw
	}
	return raw[:j+1] + out + raw[j+1+len(tail):]
}
