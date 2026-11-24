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
	// the piece before the \' is the start of the same secret: judged by
	// the joined length, like dotenvGluedTail's first piece
	head := raw[:j-1]
	if h := c.gluedHead(head[1:], head[1:], j-2+len(tail)); len(h) == j-2 {
		head = head[:1] + h
	}
	return head + raw[j-1:j+1] + out + raw[j+1+len(tail):]
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
	// the glued pieces after the first; the whole value is all of them
	var pieces [][2]int
	joined := end - 1
	put := func(from, to int) {
		if to-from >= 1 {
			pieces = append(pieces, [2]int{from, to})
			joined += to - from
		}
	}
scan:
	for i := end + 1; i < len(done); {
		switch ch := done[i]; ch {
		case ' ', '\t':
			break scan
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
				break scan
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
	if len(pieces) == 0 {
		return done
	}
	// The first piece is the start of the whole value: it keeps only the
	// head a stand-in of the joined value keeps (none under 16 characters),
	// not what its own length allowed — and is disguised even when, short on
	// its own, the keyed rules left it as written ("S3cr3tP"'!').
	if h := c.gluedHead(raw[1:end], done[1:end], joined); len(h) == end-1 {
		copy(out[1:end], h)
	}
	for _, p := range pieces {
		piece := done[p[0]:p[1]]
		if s := c.disguiseGluedPiece(piece); len(s) == len(piece) {
			copy(out[p[0]:p[1]], s)
		}
	}
	return string(out)
}

// gluedHead: a stand-in for the first piece of a value glued from several
// (raw as written, done what the keyed rules made of it alone) that keeps
// the head keepBounds allows for the joined value's length and the piece's
// verdicts. Falls back to done when that was disguised or may be kept
// whole, else to disguiseArgv.
func (c *collector) gluedHead(raw, done string, joined int) string {
	if isPlaceholderSecret(raw) || isSecretReference(raw) {
		return done
	}
	pre, _ := keepBounds(joined)
	if pre >= len(raw) {
		return raw
	}
	fixed := make([]bool, len(raw))
	for i := 0; i < pre; i++ {
		fixed[i] = true
	}
	want := verdictsOf(raw)
	for try := 0; try < 64; try++ {
		if cand := randomLike(raw, fixed); cand != raw && verdictsOf(cand) == want {
			if c.disguised == nil {
				c.disguised = map[string]string{}
			}
			c.disguised[cand] = cand
			return cand
		}
	}
	if done != raw {
		return done
	}
	return c.disguiseArgv(raw)
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
