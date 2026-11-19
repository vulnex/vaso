package main

import (
	"math/big"
	"regexp"
	"strings"
)

// What a scalar parses as, for stand-ins that must parse the same: a stand-in
// drawn from a number's classes lost an exponent's e (933336529534e11 →
// 7568306c8827858), a hex prefix or a TOML underscore, and one for a date,
// .inf or nan turned it into a string — remotely the config parsed to
// another shape, or not at all.
type scalarType int

const (
	scalarText   scalarType = iota // any other value: disguised as text
	scalarNumber                   // a number literal: its digits change, nothing else
	scalarKept                     // a date, time or keyword: no secret, kept as written
)

var (
	// decimal: sign, digits with TOML/YAML underscores, JSON5's leading or
	// trailing dot, exponent
	decimalLiteral = regexp.MustCompile(`^[-+]?(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][-+]?[0-9][0-9_]*)?$`)
	// TOML, YAML 1.2 and JSON5 prefixed integers
	prefixedLiteral = regexp.MustCompile(`^[-+]?0(?:[xX][0-9a-fA-F_]+|[oO][0-7_]+|[bB][01_]+)$`)
	// inf / nan (TOML), .inf / .nan (YAML), Infinity / NaN (JSON5), booleans, null
	keywordScalar = regexp.MustCompile(`^(?i:[-+]?\.?(?:inf|infinity|nan)|true|false|null|~)$`)
	// TOML / YAML dates, date-times and times
	dateTimeScalar = regexp.MustCompile(`^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?(?:[Zz]|[-+][0-9]{2}:[0-9]{2})?)?|[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)$`)
)

// scalarKind is what v parses as when written unquoted.
func scalarKind(v string) scalarType {
	switch {
	case keywordScalar.MatchString(v), dateTimeScalar.MatchString(v):
		return scalarKept
	case decimalLiteral.MatchString(v), prefixedLiteral.MatchString(v):
		return scalarNumber
	}
	return scalarText
}

// numberStandIn is a stand-in for a number literal: each digit outside the
// kept head and tail replaced by a random digit of its base (hex keeps a
// letter's case), every sign, prefix, dot, exponent marker and underscore
// where it was, and a run of digits starts with 0 exactly when the
// original's does (no leading zero JSON or TOML reject; YAML reads
// 0123 as it did). Drawn again until every verdict holds.
func numberStandIn(core string, pre, suf int, want secretVerdicts) (string, bool) {
	body := 0 // where the digits begin: after a sign and a 0x / 0o / 0b prefix
	if core[0] == '-' || core[0] == '+' {
		body = 1
	}
	digits := "0123456789"
	if prefixedLiteral.MatchString(core) {
		switch core[body+1] {
		case 'x', 'X':
			digits = "0123456789abcdef"
		case 'o', 'O':
			digits = "01234567"
		case 'b', 'B':
			digits = "01"
		}
		body += 2
	}
	isDigit := func(i int) bool {
		ch := core[i]
		return i >= body && (ch >= '0' && ch <= '9' || len(digits) == 16 && (ch|0x20) >= 'a' && (ch|0x20) <= 'f')
	}
	draw := func() string {
		b := []byte(core)
		for i := max(pre, body); i < len(core)-suf; i++ {
			if !isDigit(i) {
				continue
			}
			runStart := i == body || !isDigit(i-1)
			switch {
			case runStart && core[i] == '0':
				continue
			case runStart && len(digits) == 10:
				b[i] = digits[1+randIndex(9)]
			default:
				b[i] = digits[randIndex(len(digits))]
			}
			if core[i] >= 'A' && core[i] <= 'F' && b[i] >= 'a' {
				b[i] -= 0x20
			}
		}
		return string(b)
	}
	// first the value's own digits rearranged (its entropy exact, as
	// arrangeLike keeps it), then independent ones
	var pos []int
	runStart := func(i int) bool { return i == body || !isDigit(i-1) }
	for i := max(pre, body); i < len(core)-suf; i++ {
		if isDigit(i) && !(runStart(i) && core[i] == '0') {
			pos = append(pos, i)
		}
	}
	arrange := func() string {
		vals := make([]byte, len(pos))
		for k, i := range pos {
			vals[k] = core[i]
		}
		shuffleBytes(vals)
		// a run that started with another digit doesn't start with 0
		for k, i := range pos {
			if vals[k] != '0' || !runStart(i) {
				continue
			}
			for j, o := range pos {
				if vals[j] != '0' && !runStart(o) {
					vals[k], vals[j] = vals[j], vals[k]
					break
				}
			}
		}
		b := []byte(core)
		for k, i := range pos {
			b[i] = vals[k]
		}
		return string(b)
	}
	// an integer a JavaScript number holds exactly holds a stand-in that
	// is one too: smol-toml rejects a TOML integer past 2^53 - 1
	safe := safeInteger(core)
	fits := func(cand string) bool {
		if cand == core || verdictsOf(cand) != want || safe && !safeInteger(cand) {
			return false
		}
		for _, i := range pos {
			if runStart(i) && cand[i] == '0' {
				return false
			}
		}
		return true
	}
	var cand string
	for _, next := range []func() string{arrange, draw} {
		for try := 0; try < 64; try++ {
			if cand = next(); fits(cand) {
				return cand, true
			}
		}
	}
	return cand, false
}

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER, 2^53 - 1.
var maxSafeInteger = big.NewInt(1<<53 - 1)

// safeInteger: v is an integer literal (decimal, or 0x / 0o / 0b; signs and
// underscores allowed) whose magnitude is at most 2^53 - 1 — one smol-toml
// parses (it rejects a larger one) and JSON.parse reads exactly. A
// fraction, an exponent or anything else is no such integer.
func safeInteger(v string) bool {
	digits := strings.ReplaceAll(strings.TrimLeft(v, "+-"), "_", "")
	if len(v)-len(strings.TrimLeft(v, "+-")) > 1 || digits == "" {
		return false
	}
	base := 10
	if len(digits) > 2 && digits[0] == '0' {
		switch digits[1] | 0x20 {
		case 'x':
			base = 16
		case 'o':
			base = 8
		case 'b':
			base = 2
		}
		if base != 10 {
			digits = digits[2:]
		}
	}
	n, ok := new(big.Int).SetString(digits, base)
	return ok && n.CmpAbs(maxSafeInteger) <= 0
}

// sameNumberLayout: cand has a digit wherever number has one and its other
// bytes (sign, dot, exponent marker) where number has them, and no run of
// digits starts with 0 unless number's does — the same literal, other digits.
func sameNumberLayout(number, cand string) bool {
	if len(cand) != len(number) {
		return false
	}
	digit := func(ch byte) bool { return ch >= '0' && ch <= '9' }
	for i := 0; i < len(number); i++ {
		if digit(number[i]) != digit(cand[i]) || !digit(number[i]) && number[i] != cand[i] {
			return false
		}
		if digit(number[i]) && (i == 0 || !digit(number[i-1])) && (number[i] == '0') != (cand[i] == '0') {
			return false
		}
	}
	return true
}

// remember records out as v's stand-in (in the snapshot and this file) and
// returns it.
func (c *collector) remember(v, out string) string {
	if c.disguised == nil {
		c.disguised = map[string]string{}
	}
	c.disguised[v] = out
	c.disguised[out] = out
	if c.inFile != nil {
		c.inFile[v] = out
	}
	return out
}
