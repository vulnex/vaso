package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// dt24 g4-R3: a short default under a credential name (${DB_PASS:-…})
// counted as a reference, so it shipped whole in snapshots.
func TestScrubStoredFallback(t *testing.T) {
	const pw, word = "Xe5rT2yQ8u", "hunterpass"
	settings := `{"mcpServers": {"x": {"command": "npx", "env": {` +
		`"DB_PASS": "${DB_PASS:-` + pw + `}", "API_TOKEN": "${API_TOKEN-` + word + `}", ` +
		`"AUTH": "Bearer ${API_TOK:-Zq1wE6rT3y}", "LOG_LEVEL": "${LOG_LEVEL:-info}", "EMPTY_TOKEN": "${EMPTY_TOKEN:-}", ` +
		`"DOC_PASSWORD": "${DOC_PASSWORD:-changeme}"}}}}`
	files := map[string]string{
		"/h/.gemini/settings.json": settings,
		"/h/.hermes/.env":          "DB_PASS=${DB_PASS:-" + pw + "}\nLOG_LEVEL=${LOG_LEVEL:-info}\n",
		"/h/.hermes/config.yaml":   "mcp_servers:\n  x:\n    env:\n      DB_PASS: ${DB_PASS:-" + pw + "}\n      LOG_LEVEL: ${LOG_LEVEL:-info}\n",
	}
	for name, content := range files {
		c := &collector{}
		out := string(c.scrubSecrets(name, []byte(content)))
		if strings.Contains(out, pw) || strings.Contains(out, word) || strings.Contains(out, "Zq1wE6rT3y") {
			t.Errorf("%s ships the default:\n%s", name, out)
		}
		if !strings.Contains(out, "${DB_PASS:-") || !strings.Contains(out, "${LOG_LEVEL:-info}") {
			t.Errorf("%s: reference or a setting's default changed:\n%s", name, out)
		}
		if len(out) != len(content) {
			t.Errorf("%s: length changed", name)
		}
	}
	c := &collector{}
	var m map[string]map[string]map[string]interface{}
	out := c.scrubSecrets("/h/.gemini/settings.json", []byte(settings))
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	env := map[string]string{}
	for k, v := range m["mcpServers"]["x"]["env"].(map[string]interface{}) {
		env[k] = v.(string)
	}
	for _, k := range []string{"EMPTY_TOKEN", "DOC_PASSWORD"} {
		if !strings.Contains(settings, `"`+k+`": "`+env[k]+`"`) {
			t.Errorf("%s changed: %s", k, env[k])
		}
	}
	// the stand-in is a stored default the CLI flags alike
	for _, k := range []string{"DB_PASS", "API_TOKEN", "AUTH"} {
		if _, _, _, ok := storedFallback(k, env[k]); !ok {
			t.Errorf("%s stand-in %q is no stored default", k, env[k])
		}
	}
}
