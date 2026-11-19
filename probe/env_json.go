package main

import (
	"regexp"
	"strings"
)

// jsoncTrailingComma is the trailing-comma rule of stripJsonc.
var jsoncTrailingComma = regexp.MustCompile(`,(\s*[\]}])`)

// stripJSONC is stripJsonc in src/core/jsonc.ts, which the CLI parses an
// inline JSON config with (OPENCODE_CONFIG_CONTENT): // and /* */ comments
// outside strings ('…' strings too) left out, then every comma before a
// closing bracket. A value written as JSONC was redacted whole, so its
// checks saw "[redacted]" remotely.
func stripJSONC(raw string) string {
	raw = strings.TrimPrefix(raw, "\xef\xbb\xbf")
	var out strings.Builder
	var quote byte
	for i := 0; i < len(raw); {
		c := raw[i]
		if quote != 0 {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(raw) {
				out.WriteByte(raw[i+1])
				i += 2
				continue
			}
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		switch {
		case c == '"' || c == '\'':
			quote = c
			out.WriteByte(c)
			i++
		case c == '/' && i+1 < len(raw) && raw[i+1] == '/':
			for i < len(raw) && raw[i] != '\n' && raw[i] != '\r' {
				i++
			}
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			i += 2
			for i < len(raw) && !(raw[i] == '*' && i+1 < len(raw) && raw[i+1] == '/') {
				i++
			}
			i += 2
		default:
			out.WriteByte(c)
			i++
		}
	}
	return jsoncTrailingComma.ReplaceAllString(out.String(), "$1")
}

// envJSONText is the JSON document a variable's trimmed value holds, and
// whether it holds one: a value opening with a comment ("// the token\n{…}",
// "/* … */ {…}") is JSONC to the CLI (stripJsonc, then JSON.parse) and is
// the document without its comments — they are left out of the snapshot.
func envJSONText(trimmed string) (string, bool) {
	if strings.HasPrefix(trimmed, "/") {
		trimmed = strings.TrimSpace(stripJSONC(trimmed))
	}
	return trimmed, strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// disguiseJSONValue disguises, inside an inline JSON config a variable holds
// (OPENCODE_CONFIG_CONTENT), what was redacted there before — every string
// under a credential-named key (apiKey, headers, environment…) and an
// argv's credentials — with same-shape stand-ins, as in a config file:
// "[redacted]" read as a placeholder, so CFG-002 flagged a plaintext key
// locally and passed remotely. Other strings are redacted as before
// (URL credentials, token-shaped values).
func (c *collector) disguiseJSONValue(v interface{}, key string, secret bool) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			t[k] = c.disguiseJSONValue(val, k, secret || isSecretJSONKey(k))
		}
		return t
	case []interface{}:
		var argv []string
		index := map[int]int{}
		for i, val := range t {
			if str, ok := val.(string); ok {
				index[len(argv)] = i
				argv = append(argv, str)
			}
		}
		hit := map[int][2]int{}
		for _, h := range judgeArgv(argv) {
			hit[index[h.tok]] = [2]int{h.from, h.to}
		}
		for i, val := range t {
			if sp, ok := hit[i]; ok {
				str := val.(string)
				t[i] = str[:sp[0]] + c.disguiseArgv(str[sp[0]:sp[1]]) + str[sp[1]:]
				continue
			}
			t[i] = c.disguiseJSONValue(val, key, secret)
		}
		return t
	case string:
		if secret {
			if out := c.disguiseKeyed(key, t); out != t || isPlaceholderSecret(t) || isSecretReference(t) {
				return out
			}
			// a value the file rules would leave (too short to judge) still
			// never ships under a credential name: drawn like an argv password
			return c.disguiseArgv(t)
		}
		return redactSecretValues(t)
	}
	return v
}
