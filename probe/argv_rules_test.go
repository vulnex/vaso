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
