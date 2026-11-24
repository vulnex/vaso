package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type fsNameCase struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
	JSON string `json:"json"`
}

// TestFsNameEscapesMatchTS: the probe writes a name that is not UTF-8 the
// way the CLI decodes it locally (src/core/fs-names.ts, same corpus).
func TestFsNameEscapesMatchTS(t *testing.T) {
	data, err := os.ReadFile("testdata/fs-name-escapes.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []fsNameCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		raw, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Fatal(err)
		}
		snap := ProbeSnapshot{Files: map[string]FileEntry{string(raw): {Content: "x", Exists: true}}}
		var out bytes.Buffer
		if err := writeSnapshot(&out, &snap); err != nil {
			t.Fatal(err)
		}
		if want := c.JSON + `: {`; !strings.Contains(out.String(), want) {
			t.Errorf("%s: want key %s in\n%s", c.Name, c.JSON, out.String())
		}
	}
}

// Two names encoding/json wrote as one (U+FFFD) stay two, everywhere a path is
// held; file content holding NUL is left alone (dt25 g9-F4).
func TestEscapeSnapshotNamesKeepsNamesApart(t *testing.T) {
	a, b := "/h/.claude/skills/tool/\xfe.js", "/h/.claude/skills/tool/\xff.js"
	snap := ProbeSnapshot{
		Homedir:     "/h",
		Files:       map[string]FileEntry{a: {Content: "evil\x00fe", Exists: true}, b: {Content: "benign", Exists: true}},
		Directories: map[string][]string{"/h/.claude/skills/tool": {"\xfe.js", "\xff.js", "SKILL.md"}},
		Symlinks:    map[string]string{"/h/.claude/skills/\xfelink": "/h/\xfe"},
		Owners:      map[string][2]int{a: {1, 1}},
	}
	var out bytes.Buffer
	if err := writeSnapshot(&out, &snap); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		`"/h/.claude/skills/tool/\udcfe.js": {`, `"/h/.claude/skills/tool/\udcff.js": {`,
		`"\udcfe.js",`, `"\udcff.js",`, `"/h/.claude/skills/\udcfelink": "/h/\udcfe"`,
		`"content": "evil\u0000fe"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("want %s in\n%s", want, s)
		}
	}
	if strings.Contains(s, "�") || strings.Contains(s, `�`) {
		t.Errorf("a name was replaced with U+FFFD:\n%s", s)
	}
}

// A snapshot whose names are all UTF-8 is written as before.
func TestWriteSnapshotUnchangedForUTF8Names(t *testing.T) {
	snap := ProbeSnapshot{Files: map[string]FileEntry{"/h/café.js": {Content: "a\x00b", Exists: true}}}
	var got, want bytes.Buffer
	if err := writeSnapshot(&got, &snap); err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(&want)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() {
		t.Errorf("got\n%s\nwant\n%s", got.String(), want.String())
	}
}
