package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// escapeAll writes every character of v as a \u escape (lower-case hex), as
// some JSON writers do.
func escapeAll(v string) string {
	var b strings.Builder
	for _, r := range v {
		fmt.Fprintf(&b, bs+"u%04x", r)
	}
	return b.String()
}

func sameChars(a, b string) int {
	n := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			n++
		}
	}
	return n
}

var hexEscape = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)

func TestScrubDisguisesEscapedCharacters(t *testing.T) {
	key := "sk-ant-api03-Qw7Rt2Yp9Lk4Mn8Bv3Cx6Zs1Df5Gh0Jk-AAAA"
	weak := bs + "x50" + bs + "x61ss" + bs + "x77ord" + bs + "x21Geheim77" // Password!Geheim77
	upper := bs + "u004A" + bs + "u004B" + "q7Lm2Vx9Rt4Np8Wz"              // upper-case hex
	jsonDoc := `{"env": {"ANTHROPIC_API_KEY": "` + escapeAll(key) + `", "API_SECRET": "` + upper + `",` +
		` "DB_PASSWORD": "` + bs + `ud83d` + bs + `ude00P` + bs + `u00e4ss` + bs + `u0077` + bs + `u00f6rd-Geheim-` + bs + `u0041b9"}}`
	yamlDoc := "password: \"" + weak + "\"\n"
	for run := 0; run < 100; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.claude/settings.json", []byte(jsonDoc)))
		escapesKept(t, "json", jsonDoc, got)
		var v struct{ Env map[string]string }
		if err := json.Unmarshal([]byte(got), &v); err != nil {
			t.Fatalf("scrubbed JSON doesn't parse: %v\n%s", err, got)
		}
		d := v.Env["ANTHROPIC_API_KEY"]
		if d == key || len(d) != len(key) || d[:8] != key[:8] || d[len(d)-4:] != key[len(key)-4:] {
			t.Fatalf("all-escaped key: %q → %q", key, d)
		}
		if same := sameChars(key[13:len(key)-5], d[13:len(d)-5]); same > len(key)/2 {
			t.Fatalf("all-escaped key kept %d hidden characters: %q", same, d)
		}
		if tokenFormats(d) != tokenFormats(key) || verdictsOf(d) != verdictsOf(key) {
			t.Fatalf("all-escaped key %q → %q changed its verdicts", key, d)
		}
		if strings.Contains(got, escapeAll(key[13:21])) {
			t.Fatalf("a run of the key's escapes shipped:\n%s", got)
		}
		at := strings.Index(got, `"API_SECRET": "`) + len(`"API_SECRET": "`)
		if v.Env["API_SECRET"] == unescapeValue(upper) {
			t.Fatalf("upper-case escaped secret shipped as is:\n%s", got)
		}
		for _, m := range hexEscape.FindAllStringSubmatch(got[at:at+12], -1) {
			if strings.ToUpper(m[1]) != m[1] {
				t.Fatalf("an upper-case escape written in lower case:\n%s", got)
			}
		}
		if pw := v.Env["DB_PASSWORD"]; !strings.HasPrefix(pw, "\U0001F600Pä") || !strings.Contains(pw, "ö") || strings.Contains(pw, "Geheim") {
			t.Fatalf("non-ASCII escapes: %q", pw)
		}
		gotYAML := string(c.scrubSecrets("/h/.hermes/config.yaml", []byte(yamlDoc)))
		escapesKept(t, "yaml", yamlDoc, gotYAML)
		value := strings.TrimSuffix(strings.TrimPrefix(gotYAML, "password: \""), "\"\n")
		if value == weak {
			t.Fatalf("escaped weak password shipped as is")
		}
		if dec := unescapeValue(value); !isWeakCredential(dec) || verdictsOf(dec) != verdictsOf("Password!Geheim77") {
			t.Fatalf("escaped weak password %q → %q (%q) is judged differently", weak, value, dec)
		}
	}
}

func TestDecodeEscapes(t *testing.T) {
	cases := map[string]string{
		"plain": "plain",
		bs + "u0041" + bs + "x62" + bs + "U00000063":         "Abc",
		bs + "ud83d" + bs + "ude00!":                         "\U0001F600!",
		bs + "n" + bs + "t" + bs + "\"" + bs + bs + bs + "/": "\n\t\"\\/",
		"a" + bs + "u00e9":                                   "aé",
	}
	for in, want := range cases {
		got, units := decodeEscapes(in)
		if got != want {
			t.Errorf("decodeEscapes(%q) = %q, want %q", in, got, want)
		}
		if units != nil && encodeLike(units, got) != in {
			t.Errorf("encodeLike(decodeEscapes(%q)) = %q", in, encodeLike(units, got))
		}
	}
}
