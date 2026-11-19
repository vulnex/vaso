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
