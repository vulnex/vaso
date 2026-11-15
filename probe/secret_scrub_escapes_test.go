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
// escapesKept: every escape of in is at the same place in out, of the same
// kind and width; one of a letter or digit may spell another letter or digit
// (it is disguised like one), any other is unchanged.
func escapesKept(t *testing.T, name, in, out string) {
	t.Helper()
	if len(out) != len(in) {
		t.Fatalf("%s: length changed:\n%s", name, out)
	}
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' {
			continue
		}
		n := escapeLen(in, i)
		was, got := in[i:i+n], out[i:i+n]
		_, wu := decodeEscapes(was)
		_, gu := decodeEscapes(got)
		switch {
		case was == got:
		case len(wu) == 1 && wu[0].alnum && len(gu) == 1 && gu[0].alnum && got[:2] == was[:2]:
		default:
			t.Fatalf("%s: escape %q at %d became %q:\n%s", name, was, i, got, out)
		}
		i += n - 1
	}
}

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
		// judged as the CLI reads them: decoded
		for v, d := range c.disguised {
			if verdictsOf(unescapeValue(d)) != verdictsOf(unescapeValue(v)) {
				t.Fatalf("%q → %q: verdicts %+v → %+v", v, d, verdictsOf(v), verdictsOf(d))
			}
		}
	}
}
