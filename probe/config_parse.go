package main

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// Config parsing for configRoots: the probe reads only path values out of a
// config it already collects (a workspace, an MCP server's command), never
// ships what it parses here. A config it can't parse yields no values, and
// the CLI then reports those paths as not verified.

// maxParseDepth bounds nesting (a 200k-deep array must not exhaust the stack).
const maxParseDepth = 256

var errTooDeep = errors.New("nesting too deep")

// parseConfig parses data as format: "json" (JSON, JSONC and JSON5 — a
// superset reader), "toml" or "yaml" (block-style subset, see parseYAMLSubset).
func parseConfig(format string, data []byte) (value interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			value, err = nil, fmt.Errorf("parse %s: %v", format, r)
		}
	}()
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	switch format {
	case "json", "json5", "jsonc":
		return parseJSON5(data)
	case "toml":
		var m map[string]interface{}
		if _, err := toml.Decode(string(data), &m); err != nil {
			return nil, err
		}
		return m, nil
	case "yaml":
		return parseYAMLSubset(data), nil
	}
	return nil, fmt.Errorf("unknown config format %q", format)
}

// ---------------------------------------------------------------- JSON5

type json5Parser struct {
	s     string
	i     int
	depth int
}

// parseJSON5 reads JSON5 (and so JSONC and JSON): comments, trailing
// commas, single-quoted strings, unquoted identifier keys, hex numbers,
// Infinity/NaN. Numbers become float64 (only strings and booleans are
// looked up). Duplicate keys: the last one wins, as in JavaScript.
func parseJSON5(data []byte) (interface{}, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("config is not UTF-8")
	}
	p := &json5Parser{s: string(data)}
	p.skip()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing content at offset %d", p.i)
	}
	return v, nil
}

func (p *json5Parser) skip() {
	for p.i < len(p.s) {
		r, n := utf8.DecodeRuneInString(p.s[p.i:])
		switch {
		case r == '/' && strings.HasPrefix(p.s[p.i:], "//"):
			end := strings.IndexAny(p.s[p.i:], "\n\r\u2028\u2029")
			if end < 0 {
				p.i = len(p.s)
			} else {
				p.i += end
			}
		case r == '/' && strings.HasPrefix(p.s[p.i:], "/*"):
			end := strings.Index(p.s[p.i+2:], "*/")
			if end < 0 {
				p.i = len(p.s)
			} else {
				p.i += end + 4
			}
		case r == '\uFEFF' || unicode.IsSpace(r):
			p.i += n
		default:
			return
		}
	}
}

func (p *json5Parser) value() (interface{}, error) {
	if p.i >= len(p.s) {
		return nil, errors.New("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"' || c == '\'':
		return p.str()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	default:
		return p.number()
	}
}

func (p *json5Parser) object() (interface{}, error) {
	if p.depth++; p.depth > maxParseDepth {
		return nil, errTooDeep
	}
	defer func() { p.depth-- }()
	p.i++ // {
	m := make(map[string]interface{})
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, errors.New("unterminated object")
		}
		if p.s[p.i] == '}' {
			p.i++
			return m, nil
		}
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("expected ':' at offset %d", p.i)
		}
		p.i++
		p.skip()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		m[key] = v
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return m, nil
		}
		return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.i)
	}
}

func (p *json5Parser) key() (string, error) {
	if c := p.s[p.i]; c == '"' || c == '\'' {
		return p.str()
	}
	start := p.i
	for p.i < len(p.s) {
		r, n := utf8.DecodeRuneInString(p.s[p.i:])
		if r == '$' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || r == '\\' || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r) {
			p.i += n
			continue
		}
		break
	}
	if p.i == start {
		return "", fmt.Errorf("expected a key at offset %d", p.i)
	}
	key := p.s[start:p.i]
	if strings.Contains(key, `\u`) {
		// an identifier with \uXXXX escapes
		if s, err := strconv.Unquote(`"` + key + `"`); err == nil {
			key = s
		}
	}
	return key, nil
}

func (p *json5Parser) array() (interface{}, error) {
	if p.depth++; p.depth > maxParseDepth {
		return nil, errTooDeep
	}
	defer func() { p.depth-- }()
	p.i++ // [
	var out []interface{}
	for {
		p.skip()
		if p.i >= len(p.s) {
			return nil, errors.New("unterminated array")
		}
		if p.s[p.i] == ']' {
			p.i++
			if out == nil {
				out = []interface{}{}
			}
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.i)
	}
}

func (p *json5Parser) str() (string, error) {
	quote := p.s[p.i]
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == quote:
			p.i++
			return b.String(), nil
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", errors.New("unterminated string")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'v':
				b.WriteByte('\v')
			case '0':
				b.WriteByte(0)
			case '\n':
				// line continuation
			case '\r':
				if p.i < len(p.s) && p.s[p.i] == '\n' {
					p.i++
				}
			case 'x', 'u':
				n := 2
				if e == 'u' {
					n = 4
				}
				if p.i+n > len(p.s) {
					return "", errors.New("bad escape")
				}
				v, err := strconv.ParseUint(p.s[p.i:p.i+n], 16, 32)
				if err != nil {
					return "", errors.New("bad escape")
				}
				p.i += n
				r := rune(v)
				// a surrogate pair 😀
				if r >= 0xD800 && r < 0xDC00 && strings.HasPrefix(p.s[p.i:], `\u`) && p.i+6 <= len(p.s) {
					if lo, err := strconv.ParseUint(p.s[p.i+2:p.i+6], 16, 32); err == nil && lo >= 0xDC00 && lo < 0xE000 {
						r = 0x10000 + (r-0xD800)<<10 + (rune(lo) - 0xDC00)
						p.i += 6
					}
				}
				b.WriteRune(r)
			default:
				// \" \' \\ \/ and any other character stands for itself
				r, n := utf8.DecodeRuneInString(p.s[p.i-1:])
				b.WriteRune(r)
				p.i += n - 1
			}
		case c == '\n' || c == '\r':
			return "", errors.New("newline in string")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", errors.New("unterminated string")
}

func (p *json5Parser) number() (interface{}, error) {
	start := p.i
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == ',' || c == '}' || c == ']' || c == '/' || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			break
		}
		p.i++
	}
	raw := strings.TrimLeft(p.s[start:p.i], "+")
	if raw == "" {
		return nil, fmt.Errorf("unexpected character at offset %d", start)
	}
	neg := strings.HasPrefix(raw, "-")
	body := strings.TrimPrefix(raw, "-")
	switch {
	case body == "Infinity" || body == "NaN":
		return 0.0, nil
	case strings.HasPrefix(body, "0x") || strings.HasPrefix(body, "0X"):
		v, err := strconv.ParseUint(body[2:], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad number at offset %d", start)
		}
		f := float64(v)
		if neg {
			f = -f
		}
		return f, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil, fmt.Errorf("bad number at offset %d", start)
	}
	return f, nil
}

// ---------------------------------------------------------------- YAML

type yamlLine struct {
	indent int
	text   string
}

type yamlParser struct {
	lines []yamlLine
	i     int
	depth int
}

// parseYAMLSubset reads the block-style YAML agents write by hand: nested
// mappings, sequences ("- item", "- key: value"), plain and quoted scalars,
// comments, block scalars (skipped) and the first document of a stream.
// Flow collections, aliases and merge keys are not resolved: what they hold
// is not read (the CLI reports such a path as not verified), and a value
// continued on more-indented lines is skipped as a whole.
func parseYAMLSubset(data []byte) map[string]interface{} {
	var lines []yamlLine
	started := false
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "%") {
			continue
		}
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") {
			if started {
				break
			}
			started = true
			continue
		}
		if trimmed == "..." {
			break
		}
		started = true
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		lines = append(lines, yamlLine{indent, strings.TrimRight(raw[indent:], " \t\r")})
	}
	p := &yamlParser{lines: lines}
	if len(lines) == 0 {
		return nil
	}
	m, _ := p.node(lines[0].indent).(map[string]interface{})
	return m
}

func isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func (p *yamlParser) node(indent int) interface{} {
	if p.i >= len(p.lines) || p.lines[p.i].indent < indent {
		return nil
	}
	if p.depth++; p.depth > maxParseDepth {
		p.i = len(p.lines)
		return nil
	}
	defer func() { p.depth-- }()
	ind := p.lines[p.i].indent
	if isSeqItem(p.lines[p.i].text) {
		return p.seq(ind)
	}
	return p.mapping(ind)
}

// skipDeeper skips the lines indented past ind: the rest of a value that
// went on over several lines (a flow collection, a folded scalar).
func (p *yamlParser) skipDeeper(ind int) {
	for p.i < len(p.lines) && p.lines[p.i].indent > ind {
		p.i++
	}
}

func (p *yamlParser) mapping(ind int) map[string]interface{} {
	m := make(map[string]interface{})
	for p.i < len(p.lines) && p.lines[p.i].indent == ind && !isSeqItem(p.lines[p.i].text) {
		key, rest, ok := splitYAMLKey(p.lines[p.i].text)
		p.i++
		if !ok {
			p.skipDeeper(ind)
			continue
		}
		rest = stripYAMLProps(rest)
		switch {
		case rest == "":
			// a nested block, or a sequence at the key's own indent
			if p.i < len(p.lines) && (p.lines[p.i].indent > ind || (p.lines[p.i].indent == ind && isSeqItem(p.lines[p.i].text))) {
				m[key] = p.node(p.lines[p.i].indent)
			} else {
				m[key] = nil
			}
		default:
			m[key] = yamlScalar(rest)
			p.skipDeeper(ind)
		}
	}
	return m
}

func (p *yamlParser) seq(ind int) []interface{} {
	out := []interface{}{}
	for p.i < len(p.lines) && p.lines[p.i].indent == ind && isSeqItem(p.lines[p.i].text) {
		text := p.lines[p.i].text
		rest := strings.TrimLeft(strings.TrimPrefix(text, "-"), " ")
		rest = stripYAMLProps(rest)
		if rest == "" {
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > ind {
				out = append(out, p.node(p.lines[p.i].indent))
			} else {
				out = append(out, nil)
			}
			continue
		}
		if _, _, isKey := splitYAMLKey(rest); isKey || isSeqItem(rest) {
			// "- key: value": a mapping (or nested sequence) whose first line
			// starts where the item's content does
			p.lines[p.i] = yamlLine{ind + (len(text) - len(rest)), rest}
			out = append(out, p.node(p.lines[p.i].indent))
			continue
		}
		p.i++
		out = append(out, yamlScalar(rest))
		p.skipDeeper(ind)
	}
	return out
}

// splitYAMLKey splits "key: value" (key plain or quoted). A flow collection
// or a quoted scalar is never a key line.
func splitYAMLKey(text string) (key, rest string, ok bool) {
	if text == "" || text[0] == '{' || text[0] == '[' {
		return "", "", false
	}
	if text[0] == '"' || text[0] == '\'' {
		end := quotedEnd(text)
		if end < 0 {
			return "", "", false
		}
		after := strings.TrimLeft(text[end+1:], " ")
		if !strings.HasPrefix(after, ":") || (len(after) > 1 && after[1] != ' ' && after[1] != '\t') {
			return "", "", false
		}
		return yamlScalar(text[:end+1]).(string), strings.TrimSpace(after[1:]), true
	}
	for i := 0; i < len(text); i++ {
		if text[i] == ':' && (i+1 == len(text) || text[i+1] == ' ' || text[i+1] == '\t') {
			key = strings.TrimSpace(text[:i])
			if key == "" || strings.HasPrefix(key, "#") {
				return "", "", false
			}
			return key, strings.TrimSpace(text[i+1:]), true
		}
		if text[i] == ' ' && i+1 < len(text) && text[i+1] == '#' {
			return "", "", false
		}
	}
	return "", "", false
}

// quotedEnd is the index of the quote closing the scalar text starts with.
func quotedEnd(text string) int {
	q := text[0]
	for i := 1; i < len(text); i++ {
		switch {
		case q == '"' && text[i] == '\\':
			i++
		case text[i] == q:
			if q == '\'' && i+1 < len(text) && text[i+1] == '\'' {
				i++ // '' inside a single-quoted scalar
				continue
			}
			return i
		}
	}
	return -1
}

// stripYAMLProps drops a leading anchor (&a) or tag (!!str) and a comment.
func stripYAMLProps(rest string) string {
	for rest != "" && (rest[0] == '&' || rest[0] == '!') {
		sp := strings.IndexAny(rest, " \t")
		if sp < 0 {
			return ""
		}
		rest = strings.TrimSpace(rest[sp:])
	}
	if strings.HasPrefix(rest, "#") {
		return ""
	}
	return rest
}

// yamlScalar reads a scalar: quoted (with its escapes), a block scalar
// indicator or flow collection (unread: nil), an alias (nil), or plain text
// up to a comment. Booleans are recognised for `when` conditions.
func yamlScalar(rest string) interface{} {
	switch rest[0] {
	case '"':
		end := quotedEnd(rest)
		if end < 0 {
			return nil
		}
		s, err := strconv.Unquote(rest[:end+1])
		if err != nil {
			return strings.ReplaceAll(rest[1:end], `\"`, `"`)
		}
		return s
	case '\'':
		end := quotedEnd(rest)
		if end < 0 {
			return nil
		}
		return strings.ReplaceAll(rest[1:end], "''", "'")
	case '|', '>', '{', '[', '*':
		return nil
	}
	if i := strings.Index(rest, " #"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "\t#"); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSpace(rest)
	switch rest {
	case "true", "True", "TRUE":
		return true
	case "false", "False", "FALSE":
		return false
	case "null", "Null", "NULL", "~":
		return nil
	}
	return rest
}
