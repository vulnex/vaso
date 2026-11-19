package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// dt24 g4-R2: a quoted high-entropy string with no key name in a memory
// file (AGENTS.md, QWEN.md, copilot-instructions.md) shipped whole, while
// DEV-007/QC-010/GHC-008 flag it locally. The table is shared with
// src/analyzers/memory-secrets.test.ts: "flagged" is what the CLI reports.
func TestScrubMemoryEntropyStrings(t *testing.T) {
	raw, err := os.ReadFile("testdata/memory-entropy-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Line      string
		Flagged   bool
		Disguised bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/h/.config/devin/AGENTS.md", "/h/.qwen/QWEN.md", "/h/.copilot/copilot-instructions.md", "/h/proj/.windsurfrules"} {
		for _, tc := range cases {
			found := memoryEntropyStrings(tc.Line)
			if (len(found) > 0) != tc.Flagged {
				t.Errorf("%q: flagged %v, want %v", tc.Line, len(found) > 0, tc.Flagged)
				continue
			}
			c := &collector{}
			content := "# Notes\n\n" + tc.Line + "\n"
			out := string(c.scrubSecrets(name, []byte(content)))
			if len(out) != len(content) {
				t.Errorf("%s %q: length changed", name, tc.Line)
			}
			changed := false
			for _, v := range found {
				if !strings.Contains(out, v) {
					changed = true
				}
			}
			if changed != tc.Disguised {
				t.Errorf("%s %q: disguised %v, want %v:\n%s", name, tc.Line, changed, tc.Disguised, out)
			}
			// the stand-in is reported alike: as many strings, each above the bar
			got := memoryEntropyStrings(strings.Split(out, "\n")[2])
			if len(got) != len(found) {
				t.Errorf("%s %q: stand-in flagged %d strings, want %d: %q", name, tc.Line, len(got), len(found), got)
			}
		}
	}
	// a config file is not prose: the keyed rules judge it
	c := &collector{}
	conf := `{"note": "Q9w8E7r6T5y4U3i2O1p0AaSsDdFfGgHhJjKkLlZzXxCcVvBbNnMm+/"}`
	if out := string(c.scrubSecrets("/h/.qwen/settings.json", []byte(conf))); !strings.Contains(out, "Q9w8E7r6T5y4U3i2O1p0") {
		t.Errorf("settings.json note disguised by the memory rule: %s", out)
	}
}
