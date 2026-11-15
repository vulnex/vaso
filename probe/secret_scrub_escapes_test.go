package main

import (
	"encoding/json"
	"testing"

	"github.com/BurntSushi/toml"
)

// bs is one backslash: the escapes below are spelled out, as in the files.
const bs = "\\"

// escapesKept: every backslash escape of in is at the same offset of out,
// byte for byte — a stand-in never draws from an escape's hex digits.
func escapesKept(t *testing.T, name, in, out string) {
	t.Helper()
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' {
			continue
		}
		n := escapeLen(in, i)
		if i+n > len(out) || out[i:i+n] != in[i:i+n] {
			t.Fatalf("%s: escape %q at %d became %q:\n%s", name, in[i:i+n], i, out[i:min(i+n, len(out))], out)
		}
		i += n - 1
	}
}

// A non-ASCII character escaped by an ASCII-only writer (Python json.dump,
// YAML \xNN, TOML \UXXXXXXXX) straddling the kept head or tail of a
// disguised value: the stand-in keeps the escape whole, so the file still
// parses and judges as it did.
func TestScrubKeepsEscapesWhole(t *testing.T) {
	e := bs + "u00e9" // é as json.dump writes it
	jsonDoc := `{"env": {"GITHUB_TOKEN": "ghp_` + e + `AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",` +
		` "OPENAI_API_KEY": "sk-proj-Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl` + e + `"},` +
		` "apiKeys": ["` + e + `HunterTwoEsc99"], "password": "Pa` + e + `ss` + bs + `"w0rd` + bs + bs + `Zx9!Kq` + bs + `n7Lm"}`
	yamlDoc := "password: \"Esc" + bs + "x61pedPw33\"\n" +
		"token: \"ab" + bs + "u00e9cdEfGhIjKlMnOpQrStUv12\"\n" +
		"api_key: \"Zr8Ty3Uw" + bs + "x41Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl" + bs + "U0001F600\"\n"
	tomlDoc := "[provider]\napi_key = \"Zr8Ty3U" + bs + "U0001F600w6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl\"\n" +
		"password = \"Q7rT2mZ9" + bs + "u00e9kLp4Vw8NcB1d\"\n"
	var wantJSON, wantTOML map[string]interface{}
	if err := json.Unmarshal([]byte(jsonDoc), &wantJSON); err != nil {
		t.Fatalf("fixture JSON: %v", err)
	}
	if _, err := toml.Decode(tomlDoc, &wantTOML); err != nil {
		t.Fatalf("fixture TOML: %v", err)
	}
	// stand-ins are drawn at random: many draws, each from a fresh snapshot
	for run := 0; run < 200; run++ {
		c := &collector{}
		gotJSON := string(c.scrubSecrets("/h/.claude/settings.json", []byte(jsonDoc)))
		if gotJSON == jsonDoc {
			t.Fatalf("nothing disguised:\n%s", gotJSON)
		}
		escapesKept(t, "json", jsonDoc, gotJSON)
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(gotJSON), &v); err != nil {
			t.Fatalf("scrubbed JSON doesn't parse: %v\n%s", err, gotJSON)
		}
		gotYAML := string(c.scrubSecrets("/h/.hermes/config.yaml", []byte(yamlDoc)))
		if gotYAML == yamlDoc {
			t.Fatalf("nothing disguised:\n%s", gotYAML)
		}
		escapesKept(t, "yaml", yamlDoc, gotYAML)
		gotTOML := string(c.scrubSecrets("/h/.codex/config.toml", []byte(tomlDoc)))
		escapesKept(t, "toml", tomlDoc, gotTOML)
		var w map[string]interface{}
		if _, err := toml.Decode(gotTOML, &w); err != nil {
			t.Fatalf("scrubbed TOML doesn't parse: %v\n%s", err, gotTOML)
		}
		for v, d := range c.disguised {
			if verdictsOf(d) != verdictsOf(v) {
				t.Fatalf("%q → %q: verdicts %+v → %+v", v, d, verdictsOf(v), verdictsOf(d))
			}
		}
	}
}

func TestAlignToEscapes(t *testing.T) {
	e := bs + "u00e9"
	cases := []struct {
		core     string
		pre, suf int
		wantPre  int
		wantSuf  int
	}{
		{"ghp_" + e + "AbCdEfGhIjKlMnOpQrSt", 8, 4, 10, 4},  // head ends inside \u00e9
		{"AbCdEfGhIjKlMnOpQrStUv" + e, 8, 4, 8, 6},          // tail starts inside it
		{"Esc" + bs + "x61pedPw33AbCdEfGhIj", 4, 0, 7, 0},   // \x61 under a 4-character head
		{"AbCdEfGh" + bs + "\"IjKlMnOpQrStUvWx", 9, 0, 10, 0}, // \"
		{"AbCdEfGhIjKlMnOpQrStUvWx", 8, 4, 8, 4},           // no escape
		{bs + bs + "u00e9AbCdEfGhIjKlMnOp", 1, 0, 2, 0},     // an escaped backslash, then plain text
	}
	for _, tc := range cases {
		pre, suf := alignToEscapes(tc.core, tc.pre, tc.suf)
		if pre != tc.wantPre || suf != tc.wantSuf {
			t.Errorf("alignToEscapes(%q, %d, %d) = %d, %d; want %d, %d", tc.core, tc.pre, tc.suf, pre, suf, tc.wantPre, tc.wantSuf)
		}
		if pre+suf >= len(tc.core) {
			t.Errorf("alignToEscapes(%q): nothing left to hide", tc.core)
		}
	}
}
