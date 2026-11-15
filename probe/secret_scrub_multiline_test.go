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
		for _, s := range secrets {
			// what reports show (a long value's first 8) may stay; the rest not
			if strings.Contains(got, s) || strings.Contains(got, s[8:]) {
				t.Fatalf("%s shipped:\n%s", s, got)
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
