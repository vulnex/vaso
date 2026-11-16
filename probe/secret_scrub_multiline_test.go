package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestScrubMultiLineYAMLCredentials(t *testing.T) {
	doc := strings.Join([]string{
		"model:",
		"  provider: openrouter",
		"  api_key: >-",
		"    FoldedPartOne11",
		"    FoldedPartTwo22",
		"token:",
		"  PlainMultiAaa44",
		"  PlainMultiBbb55",
		"password: PlainHeadCcc66",
		"  PlainTailDdd77",
		"secret: |",
		"  LiteralOneEee88",
		"",
		"  LiteralTwoFff99",
		"secrets:",
		"  github: >",
		"    ContainerOneGg12",
		"    ContainerTwoHh34",
		"credentials:",
		"  primary:",
		"    value: NestedCredQq77",
		// prose and settings over several lines stay
		"token_help: >",
		"  Paste the token from the Settings page",
		"  into this field.",
		"description:",
		"  KeepThisLineAa11",
		"  KeepThatLineBb22",
		"after: 1",
	}, "\n") + "\n"
	secrets := []string{"FoldedPartOne11", "FoldedPartTwo22", "PlainMultiAaa44", "PlainMultiBbb55", "PlainHeadCcc66", "PlainTailDdd77",
		"LiteralOneEee88", "LiteralTwoFff99", "ContainerOneGg12", "ContainerTwoHh34", "NestedCredQq77"}
	kept := []string{"Paste the token from the Settings page", "into this field.", "KeepThisLineAa11", "KeepThatLineBb22", "after: 1", "provider: openrouter"}
	for run := 0; run < 50; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.hermes/config.yaml", []byte(doc)))
		if len(got) != len(doc) || strings.Count(got, "\n") != strings.Count(doc, "\n") {
			t.Fatalf("layout changed:\n%s", got)
		}
		// each value is one stand-in over its lines: what reports show of
		// it (its first 8, last 4) may stay, the rest is drawn at random by
		// class, so a line may keep a character or two by chance, never most
		for v := 0; v < len(secrets); v += 2 {
			value := secrets[v:min(v+2, len(secrets))]
			changed, hidden := 0, -12
			for _, s := range value {
				i := strings.Index(doc, s)
				changed += changedBytes(s, got[i:i+len(s)])
				hidden += len(s)
			}
			if changed < hidden/2 {
				t.Fatalf("%v shipped (%d of %d changed):\n%s", value, changed, hidden, got)
			}
		}
		for _, k := range kept {
			if !strings.Contains(got, k) {
				t.Fatalf("%q changed:\n%s", k, got)
			}
		}
		// each value is judged as the one string the CLI reads
		gl, dl := strings.Split(got, "\n"), strings.Split(doc, "\n")
		folded := func(l []string, a, b int) string {
			var parts []string
			for _, x := range l[a:b] {
				parts = append(parts, strings.TrimSpace(x))
			}
			return strings.Join(parts, " ")
		}
		for _, span := range [][2]int{{3, 5}, {6, 8}} {
			if verdictsOf(folded(gl, span[0], span[1])) != verdictsOf(folded(dl, span[0], span[1])) {
				t.Fatalf("lines %v judged differently:\n%s", span, got)
			}
		}
	}
}

func TestScrubNestedCredentialValues(t *testing.T) {
	jsonDoc := `{
  "credentials": {"primary": {"value": "NestedCredQq77", "name": "main"}},
  "auth": {"type": "bearer", "value": "AuthValueRr88x"},
  "tokens": [{"data": "TokenDataSs99y", "label": "ci"}],
  "metadata": {"value": "KeepMeValue12A"}
}
`
	tomlDoc := "credentials = { primary = { value = \"TomlNestedTt11\", name = \"main\" } }\n"
	// a plain lowercase value under creds, two inline tables deep
	credsTOML := "[mcp_servers.e]\ncommand = \"npx\"\nenv = { CREDS = { value = \"tomlnestedpw\" } }\n"
	credsJSON := `{"env": {"creds": {"value": "jsonnestedpw"}}}`
	for run := 0; run < 50; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.claude/settings.json", []byte(jsonDoc)))
		var v map[string]interface{}
		if err := json.Unmarshal([]byte(got), &v); err != nil {
			t.Fatalf("scrubbed JSON doesn't parse: %v\n%s", err, got)
		}
		for _, s := range []string{"NestedCredQq77", "AuthValueRr88x", "TokenDataSs99y"} {
			if strings.Contains(got, s) {
				t.Fatalf("%s shipped:\n%s", s, got)
			}
		}
		for _, k := range []string{`"KeepMeValue12A"`, `"name": "main"`, `"type": "bearer"`, `"label": "ci"`} {
			if !strings.Contains(got, k) {
				t.Fatalf("%s changed:\n%s", k, got)
			}
		}
		gotTOML := string(c.scrubSecrets("/h/.codex/config.toml", []byte(tomlDoc)))
		var w map[string]interface{}
		if _, err := toml.Decode(gotTOML, &w); err != nil {
			t.Fatalf("scrubbed TOML doesn't parse: %v\n%s", err, gotTOML)
		}
		if strings.Contains(gotTOML, "TomlNestedTt11") || !strings.Contains(gotTOML, `name = "main"`) {
			t.Fatalf("TOML nested value:\n%s", gotTOML)
		}
		gotCreds := string(c.scrubSecrets("/h/.codex/config.toml", []byte(credsTOML)))
		if _, err := toml.Decode(gotCreds, &w); err != nil {
			t.Fatalf("scrubbed TOML doesn't parse: %v\n%s", err, gotCreds)
		}
		if strings.Contains(gotCreds, "tomlnestedpw") || !strings.Contains(gotCreds, `command = "npx"`) {
			t.Fatalf("TOML creds value:\n%s", gotCreds)
		}
		gotCredsJSON := string(c.scrubSecrets("/h/.claude/settings.json", []byte(credsJSON)))
		if err := json.Unmarshal([]byte(gotCredsJSON), &v); err != nil || strings.Contains(gotCredsJSON, "jsonnestedpw") {
			t.Fatalf("JSON creds value (%v):\n%s", err, gotCredsJSON)
		}
	}
}

func TestScrubKeepsPEMArmorInDotenv(t *testing.T) {
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
	doc := "PRIVATE_KEY=\"-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\"\n" +
		"SSH_KEY='-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----'\n"
	for run := 0; run < 20; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.hermes/.env", []byte(doc)))
		for _, armor := range []string{`PRIVATE_KEY="-----BEGIN PRIVATE KEY-----`, "-----END PRIVATE KEY-----\"", "SSH_KEY='-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----'"} {
			if !strings.Contains(got, armor) {
				t.Fatalf("armor line %q changed:\n%s", armor, got)
			}
		}
		if strings.Contains(got, body) || strings.Contains(got, "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ") {
			t.Fatalf("PEM body shipped:\n%s", got)
		}
	}
}

// changedBytes counts the positions where a and b differ.
func changedBytes(a, b string) int {
	n := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}
