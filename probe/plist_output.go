package main

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// runManifestCommand runs a manifest command. plutil's conversion of a
// preference plist to XML (`plutil -convert xml1 -o - <file>`) is the plist
// itself, which the CLI reads as a config: its output is disguised like a
// collected plist (scrubPlist) — stand-ins keep a key's shape, so the CLI
// judges it as a local scan does (CFG-002) — and an account's email address
// is disguised as in any file. Other commands' output is redacted
// (runCommand).
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

// disguisePlistXML disguises an XML plist's text (scrubPlistXML).
func (c *collector) disguisePlistXML(s string) string {
	if out, ok := c.scrubPlistXML(s); ok {
		return out
	}
	return string(c.scrubSecrets("plutil-output.txt", []byte(s)))
}

// A plist, XML or binary, is judged by its structure, not as lines of text
// (dt25 g9-F2): LaunchAgents keep credentials in EnvironmentVariables
// (<key>DB_PASSWORD</key> on one line, its <string> on the next) and in
// ProgramArguments (--authtoken, then the token, as two strings), which the
// line rules can't pair; a binary plist's strings sit between length bytes
// the line rules would read as letters. Each string is scrubbed on its own,
// so a stand-in never runs past </string> (g9-F6), and
//   - a string under a credential key (DB_PASSWORD, authToken) is disguised
//     as that key's value;
//   - under a credential container key (creds, tokens, secrets…), at any
//     depth, a string that is a credential by its own key or looks like one;
//   - an array of strings is an argv (the shared argv rules: --authtoken X,
//     -p<pw>), and a string holding a command line is judged as one;
//   - a <data> blob is decoded, its text scrubbed and email addresses
//     disguised.
// A binary plist is edited in place: stand-ins keep a string's length in
// bytes (or UTF-16 units), so every offset stays valid.

// plistNode is one value of a plist: a dict, array, string, data blob or
// anything else (number, date, bool), with the dict key it sits under.
type plistNode struct {
	kind  byte // 'd' dict, 'a' array, 's' string, 'b' data, 'o' other
	key   string
	value string // a string's text, a data blob's bytes
	items []*plistNode
	// set writes a new value back; false when it can't be (a binary plist
	// string object that is also a dict key, a length change in place)
	set func(string) bool
}

func (n *plistNode) update(v string) {
	if v != n.value && n.set != nil && n.set(v) {
		n.value = v
	}
}

// maxPlistNodes bounds the walk: a binary plist's objects can be shared, so
// a small file can describe a tree with exponentially many nodes.
const maxPlistNodes = 200000

// maxPlistDepth bounds container nesting.
const maxPlistDepth = 128

// scrubPlist is scrubSecrets for a plist file; false when content is no
// plist it can parse (the line rules then scrub it as text).
func (c *collector) scrubPlist(path string, content []byte) ([]byte, bool) {
	if strings.ToLower(filepath.Ext(path)) != ".plist" {
		return nil, false
	}
	if bytes.HasPrefix(content, []byte("bplist00")) {
		return c.scrubBinaryPlist(content)
	}
	if utf8.Valid(content) {
		out, ok := c.scrubPlistXML(string(content))
		return []byte(out), ok
	}
	// UTF-16 (a plist may be written so) or a stray Latin-1 byte: through a
	// copy of the same length, written back the same way (scrubbableText)
	text, restore := scrubbableText(content)
	out, ok := c.scrubPlistXML(text)
	if !ok || len(out) != len(text) {
		return nil, false
	}
	return restore(out), true
}

// plistXMLToken: the elements of an XML plist — a <key>, a container opening
// or closing (or an empty one), a <string>, a <data>, a scalar.
var plistXMLToken = regexp.MustCompile(`<key>([^<]*)</key>|<(array|dict)>|</(?:array|dict)>|<(?:array|dict|string)/>|<string>([^<]*)</string>|<data>([^<]*)</data>|<(?:integer|real|date)>[^<]*</(?:integer|real|date)>|<(?:true|false)/>`)

// scrubPlistXML disguises an XML plist; false when s holds no plist.
func (c *collector) scrubPlistXML(s string) (string, bool) {
	if !strings.Contains(s, "<plist") && !strings.Contains(s, "<dict>") {
		return "", false
	}
	type span struct{ from, to int }
	edits := map[span]string{}
	root := &plistNode{kind: 'a'}
	stack := []*plistNode{root}
	pending := ""
	count := 0
	add := func(n *plistNode) {
		top := stack[len(stack)-1]
		if top.kind == 'd' {
			n.key = pending
		}
		pending = ""
		top.items = append(top.items, n)
		count++
	}
	for _, g := range plistXMLToken.FindAllStringSubmatchIndex(s, -1) {
		if count > maxPlistNodes {
			return "", false
		}
		m := submatch{s, g}
		switch {
		case g[2] >= 0: // <key>
			pending, _ = m.group(1)
		case g[4] >= 0: // <array> / <dict>
			kind, _ := m.group(2)
			n := &plistNode{kind: kind[0]}
			add(n)
			if len(stack) > maxPlistDepth {
				return "", false
			}
			stack = append(stack, n)
		case strings.HasPrefix(m.text(), "</"):
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			pending = ""
		case g[6] >= 0: // <string>
			value, _ := m.group(3)
			sp := span{g[6], g[7]}
			add(&plistNode{kind: 's', value: value, set: func(v string) bool { edits[sp] = v; return true }})
		case g[8] >= 0: // <data>
			blob, _ := m.group(4)
			sp := span{g[8], g[9]}
			raw, err := base64.StdEncoding.DecodeString(strings.Map(dropSpace, blob))
			if err != nil {
				add(&plistNode{kind: 'o'})
				continue
			}
			add(&plistNode{kind: 'b', value: string(raw), set: func(v string) bool {
				edits[sp] = base64.StdEncoding.EncodeToString([]byte(v))
				return true
			}})
		default: // a scalar, an empty container or string
			add(&plistNode{kind: 'o'})
		}
	}
	c.disguisePlistTree(root)
	if len(edits) == 0 {
		return s, true
	}
	var b strings.Builder
	last := 0
	for _, g := range plistXMLToken.FindAllStringSubmatchIndex(s, -1) {
		for _, i := range []int{6, 8} {
			if g[i] < 0 {
				continue
			}
			if v, ok := edits[span{g[i], g[i+1]}]; ok {
				b.WriteString(s[last:g[i]])
				b.WriteString(v)
				last = g[i+1]
			}
		}
	}
	b.WriteString(s[last:])
	return b.String(), true
}

func dropSpace(r rune) rune {
	if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
		return -1
	}
	return r
}

// disguisePlistTree applies the plist rules (above) to every value under root.
func (c *collector) disguisePlistTree(root *plistNode) {
	changed := map[string]string{}
	var strs []*plistNode
	var walk func(n *plistNode, container string, depth int)
	walk = func(n *plistNode, container string, depth int) {
		if depth > maxPlistDepth {
			return
		}
		switch n.kind {
		case 'd', 'a':
			if n.kind == 'a' {
				c.plistArgv(n, changed)
			}
			inner := container
			if n.key != "" && secretContainerKey(n.key) {
				inner = n.key
			}
			for _, it := range n.items {
				walk(it, inner, depth+1)
			}
		case 's':
			strs = append(strs, n)
			c.plistString(n, container, changed)
		case 'b':
			c.plistData(n)
		}
	}
	walk(root, "", 0)
	// what is left of a disguised value elsewhere (half a token in a label)
	if len(changed) > 0 {
		saved := c.inFile
		c.inFile = changed
		for _, n := range strs {
			n.update(c.disguiseCopies(n.value))
		}
		c.inFile = saved
	}
}

// plistString judges one string: under its own key, under the credential
// container around it, then by the file rules on its text alone.
func (c *collector) plistString(n *plistNode, container string, changed map[string]string) {
	v := n.value
	if v == "" {
		return
	}
	out := v
	switch {
	case n.key != "" && isSecretKeyName(n.key) && keyedSecret(n.key, v):
		out = c.disguiseKeyed(n.key, v)
	case container != "":
		if n.key != "" {
			if name := containerChildKey(container, n.key); name != "" && keyedSecret(name, v) {
				out = c.disguiseKeyed(name, v)
				break
			}
			if settingChildName.MatchString(n.key) {
				break
			}
		}
		if looksRandom(v, 16) || looksLikeSecret(v) {
			out = c.disguise(v)
		}
	}
	if out == v {
		// the file rules on this string alone (token shapes, --flag=<value>,
		// URLs with credentials, email addresses), and a command line in it
		out = c.scrubText("plist-string", v)
		if strings.ContainsAny(out, " \t") && hasArgvHint(out) {
			if cmd := commandCredentials(out, c.disguiseArgv); len(cmd) == len(out) {
				out = cmd
			}
		}
	}
	if out != v {
		n.update(out)
		if n.value == out && len(out) == len(v) {
			changed[v] = out
		}
	}
}

// plistArgv judges an array of strings as an argv (ProgramArguments).
func (c *collector) plistArgv(n *plistNode, changed map[string]string) {
	if len(n.items) < 2 {
		return
	}
	words := make([]string, len(n.items))
	for i, it := range n.items {
		if it.kind != 's' {
			return
		}
		words[i] = it.value
	}
	hits := judgeArgv(words)
	// right to left within a word, so earlier offsets stay valid
	for i := len(hits) - 1; i >= 0; i-- {
		h := hits[i]
		it := n.items[h.tok]
		w := it.value
		if h.from < 0 || h.to > len(w) || h.from >= h.to {
			continue
		}
		secret := w[h.from:h.to]
		out := c.disguiseArgv(secret)
		if out == secret || len(out) != len(secret) {
			continue
		}
		it.update(w[:h.from] + out + w[h.to:])
		changed[secret] = out
	}
}

// plistData scrubs a data blob: its email addresses, and the file rules when
// it is text.
func (c *collector) plistData(n *plistNode) {
	raw := n.value
	if raw == "" {
		return
	}
	out := c.disguiseEmails(raw)
	if utf8.ValidString(out) {
		out = string(c.scrubSecrets("plist-data.txt", []byte(out)))
	}
	n.update(out)
}

// scrubBinaryPlist disguises a bplist00 file in place; false when it can't
// be parsed (then it is scrubbed as text).
func (c *collector) scrubBinaryPlist(content []byte) ([]byte, bool) {
	b := append([]byte(nil), content...)
	root, ok := parseBinaryPlist(b)
	if !ok {
		return nil, false
	}
	c.disguisePlistTree(root)
	return b, true
}

// parseBinaryPlist reads a bplist00 file into plist nodes whose set writes
// into b in place.
func parseBinaryPlist(b []byte) (*plistNode, bool) {
	const trailerLen = 32
	if len(b) < 8+trailerLen+1 || string(b[:8]) != "bplist00" {
		return nil, false
	}
	t := b[len(b)-trailerLen:]
	offSize, refSize := int(t[6]), int(t[7])
	numObjects, top, tableOff := beUint(t[8:16]), beUint(t[16:24]), beUint(t[24:32])
	end := uint64(len(b) - trailerLen)
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObjects == 0 || numObjects > end ||
		top >= numObjects || tableOff < 8 || tableOff > end || (end-tableOff)/uint64(offSize) < numObjects {
		return nil, false
	}
	offset := func(obj uint64) (int, bool) {
		if obj >= numObjects {
			return 0, false
		}
		at := tableOff + obj*uint64(offSize)
		o := beUint(b[at : at+uint64(offSize)])
		if o < 8 || o >= tableOff {
			return 0, false
		}
		return int(o), true
	}
	// count: a container's or string's length, from the marker's low nibble
	// or the integer object after it; returns where the payload starts
	count := func(at int) (int, int, bool) {
		low := int(b[at] & 0x0f)
		if low != 0x0f {
			return low, at + 1, true
		}
		if at+1 >= int(tableOff) || b[at+1]>>4 != 0x1 || b[at+1]&0x0f > 3 {
			return 0, 0, false
		}
		n := 1 << (b[at+1] & 0x0f)
		if at+2+n > int(tableOff) {
			return 0, 0, false
		}
		v := beUint(b[at+2 : at+2+n])
		if v > uint64(len(b)) {
			return 0, 0, false
		}
		return int(v), at + 2 + n, true
	}
	ref := func(at int) uint64 { return beUint(b[at : at+refSize]) }
	keyObjects := map[uint64]bool{}
	nodes := 0
	failed := false

	// stringAt decodes a string object (ASCII or UTF-16BE).
	stringAt := func(obj uint64) (string, int, int, byte, bool) {
		at, ok := offset(obj)
		if !ok {
			return "", 0, 0, 0, false
		}
		typ := b[at] >> 4
		if typ != 0x5 && typ != 0x6 {
			return "", 0, 0, 0, false
		}
		n, start, ok := count(at)
		if !ok {
			return "", 0, 0, 0, false
		}
		size := n
		if typ == 0x6 {
			size = 2 * n
		}
		if start+size > int(tableOff) {
			return "", 0, 0, 0, false
		}
		raw := b[start : start+size]
		if typ == 0x5 {
			return string(raw), start, size, typ, true
		}
		units := make([]uint16, n)
		for i := range units {
			units[i] = uint16(raw[2*i])<<8 | uint16(raw[2*i+1])
		}
		return string(utf16.Decode(units)), start, size, typ, true
	}

	var build func(obj uint64, key string, depth int, path map[uint64]bool) *plistNode
	build = func(obj uint64, key string, depth int, path map[uint64]bool) *plistNode {
		nodes++
		if nodes > maxPlistNodes || depth > maxPlistDepth || path[obj] {
			failed = true
			return &plistNode{kind: 'o', key: key}
		}
		at, ok := offset(obj)
		if !ok {
			failed = true
			return &plistNode{kind: 'o', key: key}
		}
		switch b[at] >> 4 {
		case 0x5, 0x6:
			v, start, size, typ, ok := stringAt(obj)
			if !ok {
				failed = true
				return &plistNode{kind: 'o', key: key}
			}
			return &plistNode{kind: 's', key: key, value: v, set: func(nv string) bool {
				if keyObjects[obj] {
					return false
				}
				var enc []byte
				if typ == 0x5 {
					enc = []byte(nv)
				} else {
					for _, u := range utf16.Encode([]rune(nv)) {
						enc = append(enc, byte(u>>8), byte(u))
					}
				}
				if len(enc) != size || (typ == 0x5 && !isASCII(nv)) {
					return false
				}
				copy(b[start:start+size], enc)
				return true
			}}
		case 0x4:
			n, start, ok := count(at)
			if !ok || start+n > int(tableOff) {
				failed = true
				return &plistNode{kind: 'o', key: key}
			}
			return &plistNode{kind: 'b', key: key, value: string(b[start : start+n]), set: func(nv string) bool {
				if len(nv) != n {
					return false
				}
				copy(b[start:start+n], nv)
				return true
			}}
		case 0xA, 0xC, 0xD:
			typ := b[at] >> 4
			n, start, ok := count(at)
			refs := n
			if typ == 0xD {
				refs = 2 * n
			}
			if !ok || start+refs*refSize > int(tableOff) {
				failed = true
				return &plistNode{kind: 'o', key: key}
			}
			path[obj] = true
			defer delete(path, obj)
			node := &plistNode{kind: 'a', key: key}
			if typ == 0xD {
				node.kind = 'd'
				for i := 0; i < n; i++ {
					kobj := ref(start + i*refSize)
					k, _, _, _, ok := stringAt(kobj)
					if !ok {
						failed = true
						continue
					}
					keyObjects[kobj] = true
					node.items = append(node.items, build(ref(start+(n+i)*refSize), k, depth+1, path))
				}
				return node
			}
			for i := 0; i < n; i++ {
				node.items = append(node.items, build(ref(start+i*refSize), "", depth+1, path))
			}
			return node
		}
		return &plistNode{kind: 'o', key: key}
	}
	root := build(top, "", 0, map[uint64]bool{})
	if failed {
		return nil, false
	}
	return root, true
}

func beUint(p []byte) uint64 {
	var v uint64
	for _, x := range p {
		v = v<<8 | uint64(x)
	}
	return v
}
