package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// sameShape: got differs from doc only where doc had an ASCII letter or
// digit and got has one too — every quote, separator, indentation, line
// break, anchor and comment stays, so the file parses to the same shape.
func sameShape(t *testing.T, doc, got string) {
	t.Helper()
	if len(got) != len(doc) {
		t.Fatalf("length changed:\n%s", got)
	}
	for i := 0; i < len(doc); i++ {
		if doc[i] != got[i] && !(isASCIIAlnum(doc[i]) && isASCIIAlnum(got[i])) {
			t.Fatalf("byte %d changed %q -> %q:\n%s", i, doc[i], got[i], got)
		}
	}
}

// hiddenPart is what of a secret may never ship (reports show the rest).
func hiddenPart(s string) string {
	switch {
	case len(s) >= 24:
		return s[8 : len(s)-4]
	case len(s) >= 16:
		return s[4:]
	}
	return s
}

func TestScrubSpreadYAMLValues(t *testing.T) {
	doc := strings.Join([]string{
		"model:",
		"  provider: openrouter",
		`  api_key: "sk-or-v1-Ab3dEf6hIj9kLm2nOp5q`,
		`    Rs8tUv1wXy4zAb7cDe0fGh3iJk6l"`,
		"env:",
		"  SQ_TOKEN: 'SqA1b2C3d4E5f6G7",
		"    MlH8i9J0k1L2m3N4'",
		"  BS_TOKEN: \"BsA1b2C3d4E5f6G7h8\\",
		"    NlI9j0K1l2M3n4O5p6\"",
		"gh_token: 'QyA1b2C3d4E5f6G7h8I9",
		"",
		"  QzJ0k1L2m3N4o5P6q7R8s9T0'  # c",
		"auth_token: PcA1b2C3d4E5f6G7h8",
		"  PdI9j0K1l2M3n4O5p6 # trailing",
		"vars:",
		"  BASE: &k AncA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5",
		"  OPENAI_API_KEY: *k",
		"  COMMON_VALUE: &pw bluehorsebattery",
		"  DB_PASSWORD: *pw",
		"  FLOW: {LOCAL: &fl FlowAncA1b2C3d4E5f6G7h8I9, API_TOKEN: *fl}",
		"x-common: &common",
		"  password: mergelowpw",
		"db:",
		"  <<: *common",
		// prose and settings over several lines, and anchors no credential reads, stay
		"token_help: \"Paste the token from",
		"  the Settings page\"",
		"label: 'KeepThisLineAa11",
		"  KeepThatLineBb22'",
		"shared: &s KeepAnchoredCc33Dd44Ee55Ff66",
		"other: *s",
		"after: 1",
	}, "\n") + "\n"
	secrets := []string{
		"sk-or-v1-Ab3dEf6hIj9kLm2nOp5q", "Rs8tUv1wXy4zAb7cDe0fGh3iJk6l",
		"SqA1b2C3d4E5f6G7", "MlH8i9J0k1L2m3N4", "BsA1b2C3d4E5f6G7h8", "NlI9j0K1l2M3n4O5p6",
		"QyA1b2C3d4E5f6G7h8I9", "QzJ0k1L2m3N4o5P6q7R8s9T0",
		"PcA1b2C3d4E5f6G7h8", "PdI9j0K1l2M3n4O5p6",
		"AncA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5", "bluehorsebattery", "FlowAncA1b2C3d4E5f6G7h8I9", "mergelowpw",
	}
	kept := []string{"the Settings page", "KeepThisLineAa11", "KeepThatLineBb22", "KeepAnchoredCc33Dd44Ee55Ff66", "# trailing", "# c"}
	for run := 0; run < 50; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.hermes/config.yaml", []byte(doc)))
		sameShape(t, doc, got)
		for _, s := range secrets {
			if strings.Contains(got, hiddenPart(s)) {
				t.Fatalf("%s shipped:\n%s", s, got)
			}
		}
		for _, k := range kept {
			if !strings.Contains(got, k) {
				t.Fatalf("%q changed:\n%s", k, got)
			}
		}
		// each value is judged as the one string YAML reads
		gl, dl := strings.Split(got, "\n"), strings.Split(doc, "\n")
		for _, v := range []struct {
			a, b int
			sep  string
		}{{2, 4, " "}, {5, 7, " "}, {12, 14, " "}} {
			fold := func(l []string) string {
				var parts []string
				for _, x := range l[v.a:v.b] {
					x = strings.TrimSpace(x)
					if i := strings.Index(x, ": "); i >= 0 && !strings.HasPrefix(x, "sk-") {
						x = x[i+2:]
					}
					parts = append(parts, strings.Trim(strings.TrimSuffix(x, " # trailing"), `"'`))
				}
				return strings.Join(parts, v.sep)
			}
			if verdictsOf(fold(gl)) != verdictsOf(fold(dl)) {
				t.Fatalf("lines %d-%d judged differently: %q vs %q", v.a, v.b, fold(gl), fold(dl))
			}
		}
	}
}

func TestScrubSpreadDotenvValues(t *testing.T) {
	doc := "SLACK_BOT_TOKEN='xoxb-1234567890\nSsqA1b2C3d4E5f6G7h8I9j0K1'\n" +
		"OPENROUTER_API_KEY=\"EvA1b2C3d4E5f6G7\n  EwH8i9J0k1L2m3N4\"\n" +
		"NOTE='a note written\nover two lines'\nOTHER=1\n"
	for run := 0; run < 50; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.hermes/.env", []byte(doc)))
		sameShape(t, doc, got)
		for _, s := range []string{"SsqA1b2C3d4E5f6G7h8I9j0K1", "EvA1b2C3d4E5f6G7", "EwH8i9J0k1L2m3N4"} {
			if strings.Contains(got, hiddenPart(s)) {
				t.Fatalf("%s shipped:\n%s", s, got)
			}
		}
		if !strings.Contains(got, "NOTE='a note written\nover two lines'\nOTHER=1\n") {
			t.Fatalf("prose changed:\n%s", got)
		}
		// python-dotenv reads each as one value, line breaks kept
		for _, k := range []string{"SLACK_BOT_TOKEN", "OPENROUTER_API_KEY"} {
			value := func(s string) string {
				i := strings.Index(s, k+"=") + len(k) + 2
				q := s[i-1]
				return s[i : i+strings.IndexByte(s[i:], q)]
			}
			if verdictsOf(value(got)) != verdictsOf(value(doc)) {
				t.Fatalf("%s judged differently: %q vs %q", k, value(got), value(doc))
			}
		}
	}
}

func TestScrubSpreadTOMLStrings(t *testing.T) {
	doc := "[mcp_servers.b]\ncommand = \"npx\"\n" +
		"env = { API_KEY = \"\"\"TmA1b2C3d4E5f6\nTnG7h8I9j0K1l2\"\"\", OTHER = \"x\" }\n" +
		"[mcp_servers.c.env]\n" +
		"BS_TOKEN = \"\"\"TbA1b2C3d4E5\\\n   TcF6g7H8i9J0\"\"\"\n" +
		"LIT_SECRET = '''\nLtA1b2C3d4E5f6\n  LuG7h8I9j0K1l2'''\n" +
		"DESCRIPTION = \"\"\"Some words\nover lines\"\"\"\n"
	var want map[string]interface{}
	if _, err := toml.Decode(doc, &want); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 50; run++ {
		c := &collector{}
		got := string(c.scrubSecrets("/h/.codex/config.toml", []byte(doc)))
		sameShape(t, doc, got)
		var have map[string]interface{}
		if _, err := toml.Decode(got, &have); err != nil {
			t.Fatalf("scrubbed TOML doesn't parse: %v\n%s", err, got)
		}
		wantEnv := want["mcp_servers"].(map[string]interface{})["c"].(map[string]interface{})["env"].(map[string]interface{})
		haveEnv := have["mcp_servers"].(map[string]interface{})["c"].(map[string]interface{})["env"].(map[string]interface{})
		if len(wantEnv) != len(haveEnv) {
			t.Fatalf("shape changed: %v vs %v", haveEnv, wantEnv)
		}
		for k, wv := range wantEnv {
			hv := haveEnv[k].(string)
			if len(hv) != len(wv.(string)) || verdictsOf(hv) != verdictsOf(wv.(string)) {
				t.Fatalf("%s: %q judged unlike %q", k, hv, wv)
			}
			if k != "OTHER" && k != "DESCRIPTION" && hv == wv {
				t.Fatalf("%s shipped: %q", k, hv)
			}
		}
		if !reflect.DeepEqual(haveEnv["DESCRIPTION"], wantEnv["DESCRIPTION"]) {
			t.Fatalf("prose changed: %q", haveEnv["DESCRIPTION"])
		}
		for _, s := range []string{"TmA1b2C3d4E5f6", "TnG7h8I9j0K1l2", "TbA1b2C3d4E5", "TcF6g7H8i9J0", "LtA1b2C3d4E5f6", "LuG7h8I9j0K1l2"} {
			if strings.Contains(got, hiddenPart(s)) {
				t.Fatalf("%s shipped:\n%s", s, got)
			}
		}
	}
}
