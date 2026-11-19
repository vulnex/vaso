package main

import (
	"strings"
	"testing"
)

// dt24 g9-R4: a single-quoted password that ends the string a command is
// written in (YAML "… -P 'pw'", a flow sequence's ["-c", "htpasswd … 'pw'"])
// and an Authorization header with its spaces escaped shipped whole.
func TestScrubPasswordClosingItsString(t *testing.T) {
	const pw = "Ab3dEf9hIjKlMn7q"
	files := map[string]string{
		"/h/.hermes/config.yaml#flow":  "mcp_servers:\n  x:\n    command: sh\n    args: [\"-c\", \"htpasswd -b f u '" + pw + "'\"]\n",
		"/h/.hermes/config.yaml#block": "mcp_servers:\n  x:\n    command: sh\n    args:\n      - -c\n      - \"sqlcmd -S h -U sa -P '" + pw + "'\"\n",
		"/h/.hermes/config.yaml#hook":  "hooks:\n  pre:\n    command: \"ldapsearch -x -D cn=x -w '" + pw + "'\"\n",
		"/h/.claude/settings.json":     `{"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "mongosh --host h -p '` + pw + `'"}]}]}}`,
		"/h/.claude/settings.json#hdr": `{"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "curl -H Authorization:\\ Bearer\\ ` + pw + ` https://x.example"}]}]}}`,
		"/h/.hermes/config.yaml#hdr":   "hooks:\n  pre:\n    command: \"curl -H Authorization:\\\\ Bearer\\\\ " + pw + " https://x.example\"\n",
	}
	for name, content := range files {
		path := strings.SplitN(name, "#", 2)[0]
		c := &collector{}
		out := string(c.scrubSecrets(path, []byte(content)))
		if strings.Contains(out, pw[4:]) {
			t.Errorf("%s ships the password:\n%s", name, out)
		}
		if len(out) != len(content) {
			t.Errorf("%s: length changed", name)
		}
	}
}
