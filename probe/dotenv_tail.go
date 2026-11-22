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

// dotenvGluedTail disguises the pieces a shell glues onto a quoted dotenv
// value: two single-quoted pieces around an escaped quote, KEY="Ab3d"'Kl8m…'
// or KEY='Ab3d'Kl8m…. VASO and dotenv read the first quoted piece, so only that was judged and the
// rest of the secret, which `source .env` reads as the same value, shipped
// as written. raw is the value as written; done is what the keyed rules made
// of it. Each glued piece gets a same-shape stand-in of its own when the key
// names a secret or the first piece was disguised; the quotes, escapes and
// anything after unquoted whitespace (a comment) are kept.
func (c *collector) dotenvGluedTail(key, raw, done string) string {
	if len(raw) < 3 || len(done) != len(raw) {
		return done
	}
	q := raw[0]
	if q != '\'' && q != '"' && q != '`' {
		return done
	}
	var end int
	if q == '\'' {
		end = strings.IndexByte(raw[1:], '\'')
	} else {
		end = dotenvQuoteEnd(raw[1:], q)
	}
	if end < 0 {
		return done
	}
	end += 1
	// the escaped-quote form is dotenvEscapedTail's
	if q == '\'' && raw[end-1] == '\\' && done[end+1:] != raw[end+1:] {
		return done
	}
	if !isSecretKeyName(key) && done[:end] == raw[:end] {
		return done
	}
	rest := done[end+1:]
	if rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '#' {
		return done
	}
	out := []byte(done)
	at := end + 1
	put := func(from, to int) {
		if to-from < 1 {
			return
		}
		piece := done[from:to]
		if s := c.disguiseGluedPiece(piece); len(s) == len(piece) {
			copy(out[from:to], s)
		}
	}
	for i := at; i < len(done); {
		switch ch := done[i]; ch {
		case ' ', '\t':
			return string(out)
		case '\\':
			i += 2
		case '\'', '"':
			var k int
			if ch == '\'' {
				k = strings.IndexByte(done[i+1:], '\'')
			} else {
				k = quoteEnd(done[i+1:], '"', false)
			}
			if k < 0 {
				return string(out)
			}
			put(i+1, i+1+k)
			i += k + 2
		default:
			j := i
			for j < len(done) && !strings.ContainsRune(" \t'\"\\", rune(done[j])) {
				j++
			}
			put(i, j)
			i = j
		}
	}
	return string(out)
}

// disguiseGluedPiece: a stand-in for a piece from the middle of a secret.
// The first-8/last-4 characters a stand-in keeps are the secret's own ends
// only for a whole value; here they would be characters from its middle, so
// the piece is replaced whole (same classes, judged like it), falling back
// to disguiseArgv when no such stand-in keeps its verdicts.
func (c *collector) disguiseGluedPiece(v string) string {
	if isPlaceholderSecret(v) || isSecretReference(v) {
		return v
	}
	want := verdictsOf(v)
	for try := 0; try < 64; try++ {
		if cand := randomLike(v, nil); cand != v && verdictsOf(cand) == want {
			if c.disguised == nil {
				c.disguised = map[string]string{}
			}
			c.disguised[v] = cand
			c.disguised[cand] = cand
			return cand
		}
	}
	return c.disguiseArgv(v)
}
