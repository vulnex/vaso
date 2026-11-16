package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type argvCase struct {
	Name    string
	Argv    []string
	Command string
	Secrets []string
	Keep    []string
}

func loadArgvCases(t *testing.T) []argvCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "argv-verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Cases []argvCase }
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Cases
}

// The probe's argv judgement is the shared one (testdata/argv-verdicts.json;
// the report masker and MCP-003 are held to the same corpus in TypeScript).
func TestArgvVerdicts(t *testing.T) {
	for _, c := range loadArgvCases(t) {
		var got []string
		if c.Argv != nil {
			for _, h := range judgeArgv(c.Argv) {
				got = append(got, c.Argv[h.tok][h.from:h.to])
			}
		} else {
			commandCredentials(c.Command, func(v string) string {
				got = append(got, v)
				return v
			})
		}
		want := append([]string(nil), c.Secrets...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s: credentials %q, corpus says %q", c.Name, got, want)
		}
	}
}

// …and the snapshot disguises exactly those: as an MCP server's args array
// and as a command string, every secret is replaced, every kept part stays.
func TestArgvVerdictsInSnapshots(t *testing.T) {
	for _, c := range loadArgvCases(t) {
		var doc map[string]interface{}
		if c.Argv != nil {
			doc = map[string]interface{}{"mcpServers": map[string]interface{}{"s": map[string]interface{}{"command": c.Argv[0], "args": c.Argv[1:]}}}
		} else {
			doc = map[string]interface{}{"hooks": map[string]interface{}{"command": c.Command}}
		}
		in, _ := json.MarshalIndent(doc, "", "  ")
		files := map[string]string{"/h/.claude/settings.json": string(in)}
		if c.Argv != nil {
			// the same server in YAML (Hermes) and TOML (Codex)
			q := func(v string) string { b, _ := json.Marshal(v); return string(b) }
			yml := "mcp_servers:\n  s:\n    command: " + q(c.Argv[0]) + "\n    args:\n"
			var items []string
			for _, a := range c.Argv[1:] {
				yml += "      - " + q(a) + "\n"
				items = append(items, q(a))
			}
			files["/h/.hermes/config.yaml"] = yml
			// YAML flow sequences: quoted items under a block mapping's
			// command:, and plain items in an inline mapping
			plainOK := regexp.MustCompile(`^[A-Za-z0-9._/-][^,\[\]{}#'"\s]*$`)
			var plain []string
			for _, a := range c.Argv[1:] {
				if plainOK.MatchString(a) && !strings.Contains(a, ":") {
					plain = append(plain, a)
				} else {
					plain = append(plain, q(a))
				}
			}
			files["/h/.hermes/flow/config.yaml"] = "mcp_servers:\n  s:\n    command: " + c.Argv[0] + "\n    args: [" + strings.Join(items, ", ") + "]\n" +
				"  t: {command: " + c.Argv[0] + ", args: [" + strings.Join(plain, ", ") + "]}\n"
			files["/h/.codex/config.toml"] = "[mcp_servers.s]\ncommand = " + q(c.Argv[0]) + "\nargs = [" + strings.Join(items, ", ") + "]\n"
		}
		for name, content := range files {
			out := string((&collector{}).scrubSecrets(name, []byte(content)))
			for _, s := range c.Secrets {
				if strings.Contains(out, s) {
					t.Errorf("%s (%s): %q shipped:\n%s", c.Name, name, s, out)
				}
			}
			for _, k := range c.Keep {
				if !strings.Contains(out, k) {
					t.Errorf("%s (%s): lost %q:\n%s", c.Name, name, k, out)
				}
			}
		}
	}
}

// Every password VASO's CFG-002 reads in a hook command (src/checks/config/
// cfg-002-hook-secrets.test.ts) is disguised in a snapshot of the settings file.
func TestHookPasswordsInSnapshots(t *testing.T) {
	commands := map[string]string{
		`mysql -p"Top1Quoted9" app`:                                   "Top1Quoted9",
		`mysql -p'Top2Single9' app`:                                   "Top2Single9",
		`sshpass -p "Top3Spaced9" ssh x`:                              "Top3Spaced9",
		`mysql --password="Top4Long9x" app`:                           "Top4Long9x",
		`mysql --password=Ab12 app`:                                   "Ab12",
		`curl -u "adm:Top5Curl9x" https://x`:                          "Top5Curl9x",
		`curl -u 'adm:Top6Curl9y' https://x`:                          "Top6Curl9y",
		`MYSQL_PWD="Top7Env9xx" mysql app`:                            "Top7Env9xx",
		`PGPASSWORD=pg1 psql -h db app`:                               "pg1",
		`ssh host "bash -c 'mysql -pQx7Lm2Vn9Bz4 app'"`:               "Qx7Lm2Vn9Bz4",
		`ssh h 'mysql -p"Qu0ted9Pass" app'`:                           "Qu0ted9Pass",
		`ssh h "sshpass -p \"Esc4Pq8Wd\" ssh x"`:                      "Esc4Pq8Wd",
		`ssh h $'mysql -pAnsi7Cq3Lw app'`:                             "Ansi7Cq3Lw",
		`ssh -p 2222 h "sudo -u svc sh -c 'mysql -pSu8Do4Pw2Rt app'"`: "Su8Do4Pw2Rt",
		`su - app -c "sshpass -p Zq8Wn3Lx7Vb2 ssh deploy@h"`:          "Zq8Wn3Lx7Vb2",
		`docker exec db sh -c "mysql -pDk4Rw9Np2Mz7 app"`:             "Dk4Rw9Np2Mz7",
		`eval "mysql -pEv4Rw9Np2Mz7 app"`:                             "Ev4Rw9Np2Mz7",
	}
	var hooks []map[string]string
	for c := range commands {
		hooks = append(hooks, map[string]string{"type": "command", "command": c})
	}
	doc := map[string]interface{}{"hooks": map[string]interface{}{"PostToolUse": []interface{}{map[string]interface{}{"matcher": "Bash", "hooks": hooks}}}}
	in, _ := json.MarshalIndent(doc, "", " ")
	out := string((&collector{}).scrubSecrets("/h/.claude/settings.json", in))
	for c, pw := range commands {
		if strings.Contains(out, pw) {
			t.Errorf("%s: %q shipped", c, pw)
		}
	}
}

// Quoted command-line credentials: the quotes around and inside a value are
// not part of it, at any depth of escaping, and a quoted flag argument
// stays with its flag.
func TestCommandCredentialsQuoted(t *testing.T) {
	same := func(v string) string { return strings.Repeat("Z", len(v)) }
	cases := []struct{ line, secret string }{
		{`"command": "mysql -p\"Top1Quoted9\" app"`, "Top1Quoted9"},
		{`"command": "sshpass -p \"Top3Spaced9\" ssh x"`, "Top3Spaced9"},
		{`"command": "curl -u \"adm:Top5Curl9x\" https://x"`, "Top5Curl9x"},
		{`"command": "ssh h 'mysql -p\"Qu0ted9Pass\" app'"`, "Qu0ted9Pass"},
		{`"command": "ssh h \"sshpass -p \\\"Esc4Pq8Wd\\\" ssh x\""`, "Esc4Pq8Wd"},
		{`"command": "ssh h $'mysql -pAnsi7Cq3Lw app'"`, "Ansi7Cq3Lw"},
		{`command = "sshpass -p 'Tm9Lq2Wx7Zr' ssh x"`, "Tm9Lq2Wx7Zr"},
		{`  command: mysql -u "root" -p"Rt5Qw8Lm3Zx" app`, "Rt5Qw8Lm3Zx"},
		{`mysql -p"Ab3Cd"5Ef7Gh9 app`, "Ab3Cd5Ef7Gh9"},
	}
	for _, c := range cases {
		var got []string
		out := commandCredentials(c.line, func(v string) string {
			got = append(got, v)
			return same(v)
		})
		if len(got) != 1 || got[0] != c.secret {
			t.Errorf("%s: credentials %q, want %q", c.line, got, c.secret)
		}
		if strings.Contains(out, c.secret) || len(out) != len(c.line) {
			t.Errorf("%s: disguised as %s", c.line, out)
		}
		redacted := commandCredentials(c.line, func(string) string { return "[REDACTED]" })
		if strings.Contains(redacted, c.secret) || !strings.Contains(redacted, "[REDACTED]") {
			t.Errorf("%s: redacted as %s", c.line, redacted)
		}
	}
	// the quotes stay where they were
	if got := commandCredentials(`mysql -p"Ab3Cd"5Ef7Gh9 app`, same); got != `mysql -p"ZZZZZ"ZZZZZZZ app` {
		t.Errorf("in place: %s", got)
	}
	// MySQL takes a separate value after -p as the database, quoted or not;
	// a JSON args array is judged with its server's command (argvArraySpans)
	for _, line := range []string{
		`"command": "mysql -u root -p \"app_db\""`,
		`"args": ["-p", "Xk9Lm2Qw7Zr4"]`,
		`echo "-p" "Xk9Lm2Qw7Zr4"`,
	} {
		if out := commandCredentials(line, same); out != line {
			t.Errorf("%s: changed to %s", line, out)
		}
	}
}
