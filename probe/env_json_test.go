package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// dt24 g3-F8: a credential inside OPENCODE_CONFIG_CONTENT shipped as
// "[redacted]" (a placeholder to the checks), so CFG-002 passed remotely.
func TestEnvJSONConfigDisguised(t *testing.T) {
	const token, key, short = "Zq7Wm3Kv8Rb2LpXyT4nQ", "sk-proj-Hq4Tz9Wm2Vb7Kc5Rn8Ld3Fs6Gj1Py0Aa", "hunter2"
	val := `{"mcp":{"z":{"type":"local","command":["npx","-y","unpinned-pkg","--api-key","` + key + `"],` +
		`"environment":{"API_TOKEN":"` + token + `","DB_PASSWORD":"` + short + `","HOME_DIR":"/srv/app","REF":"{env:OPENAI_API_KEY}"}}},"share":"auto"}`
	got := redactEnvValue("OPENCODE_CONFIG_CONTENT", val)
	if strings.Contains(got, redactedEnvValue) {
		t.Errorf("redacted rather than disguised: %s", got)
	}
	for _, s := range []string{token, key, short} {
		if strings.Contains(got, hiddenPart(s)) {
			t.Errorf("%s shipped: %s", s, got)
		}
	}
	var a, b map[string]interface{}
	_ = json.Unmarshal([]byte(val), &a)
	if err := json.Unmarshal([]byte(got), &b); err != nil {
		t.Fatalf("not JSON: %s", got)
	}
	env := func(m map[string]interface{}) map[string]interface{} {
		return m["mcp"].(map[string]interface{})["z"].(map[string]interface{})["environment"].(map[string]interface{})
	}
	ea, eb := env(a), env(b)
	for k, v := range ea {
		w, _ := eb[k].(string)
		if len(w) != len(v.(string)) {
			t.Errorf("%s: %q → %q", k, v, w)
		}
	}
	if eb["REF"] != "{env:OPENAI_API_KEY}" {
		t.Errorf("reference changed: %v", eb["REF"])
	}
	if s := eb["API_TOKEN"].(string); verdictsOf(s) != verdictsOf(token) {
		t.Errorf("stand-in %q judged unlike %q", s, token)
	}
	if !strings.Contains(got, `"--api-key","sk-proj-`) || !strings.Contains(got, `"share":"auto"`) {
		t.Errorf("structure lost: %s", got)
	}
}

// dt24 g9-R3: OPENCODE_CONFIG_CONTENT written as JSONC (comments, a
// trailing comma), which the CLI reads (stripJsonc), was redacted whole.
func TestEnvJSONCConfigDisguised(t *testing.T) {
	const token = "Zq7Wm3Kv8Rb2LpXyT4nQ"
	for _, val := range []string{
		`{"mcp": {"z": {"environment": {"API_TOKEN": "` + token + `"}}}, /* note */ "share": "auto",}`,
		"{\n  // the token\n  \"mcp\": {\"z\": {\"environment\": {\"API_TOKEN\": \"" + token + "\",},},},\n  \"share\": \"auto\"\n}",
	} {
		got := redactEnvValue("OPENCODE_CONFIG_CONTENT", val)
		if got == redactedEnvValue || strings.Contains(got, hiddenPart(token)) {
			t.Errorf("%q → %s", val, got)
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(got), &m); err != nil || m["share"] != "auto" {
			t.Errorf("not the config as JSON: %s", got)
			continue
		}
		s := m["mcp"].(map[string]interface{})["z"].(map[string]interface{})["environment"].(map[string]interface{})["API_TOKEN"].(string)
		if verdictsOf(s) != verdictsOf(token) || len(s) != len(token) {
			t.Errorf("stand-in %q judged unlike %q", s, token)
		}
	}
	// a comment marker inside a string stays; broken JSON is still redacted
	if got := redactEnvValue("OPENCODE_CONFIG_CONTENT", `{"url": "https://x.example/a", "n": 1,}`); !strings.Contains(got, `https://x.example/a`) {
		t.Errorf("string content lost: %s", got)
	}
	if got := redactEnvValue("OPENCODE_CONFIG_CONTENT", `{"mcp": {`); got != redactedEnvValue {
		t.Errorf("broken JSON shipped: %s", got)
	}
}

// dt24 g9-S2: a value opening with a comment ("// …\n{…}", "/* … */ {…}")
// is JSONC to the CLI too; it was redacted whole (CFG-002 passed remotely)
// and a random string inside the block comment shipped as written.
func TestEnvJSONCLeadingComment(t *testing.T) {
	const token, inComment = "Zq7Wm3Kv8Rb2LpXyT4nQ", "Qp8Lm2Xv7Rt4Kw9Zb3Nc6Hd5"
	doc := `{"mcp":{"z":{"environment":{"API_TOKEN":"` + token + `"}}},"share":"auto"}`
	for _, val := range []string{
		"// the token\n" + doc,
		"  /* " + inComment + " */ " + doc,
		"/* a */ // b\n" + doc,
	} {
		got := redactEnvValue("OPENCODE_CONFIG_CONTENT", val)
		if strings.Contains(got, redactedEnvValue) || strings.Contains(got, hiddenPart(token)) || strings.Contains(got, inComment[4:]) {
			t.Errorf("%q → %s", val, got)
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(got), &m); err != nil || m["share"] != "auto" {
			t.Errorf("not the config as JSON: %s", got)
		}
	}
	// a path is no comment
	if got := redactEnvValue("SOME_DIR", "/srv/app"); got != "/srv/app" {
		t.Errorf("path changed: %s", got)
	}
}
