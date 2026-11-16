package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestPlistConversionOutputDisguised(t *testing.T) {
	key := "sk-proj-" + "Ab3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5pR7tV9xZ1bD3fH5"
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>userEmail</key>
	<string>jane.doe@example.com</string>
	<key>apiKey</key>
	<string>` + key + `</string>
	<key>password</key>
	<string>hunter2hunter2</string>
	<key>trainingAllowed</key>
	<true/>
	<key>theme</key>
	<string>dark</string>
</dict>
</plist>
`
	c := &collector{}
	out := c.disguisePlistXML(xml)
	for _, raw := range []string{"jane.doe@", key[8:40], "hunter2hunter2"} {
		if strings.Contains(out, raw) {
			t.Fatalf("%q shipped:\n%s", raw, out)
		}
	}
	// shapes kept: the key's prefix and length, an address at its domain
	if !regexp.MustCompile(`<string>sk-proj-[A-Za-z0-9]{` + itoa(len(key)-8) + `}</string>`).MatchString(out) {
		t.Fatalf("stand-in lost the key's shape:\n%s", out)
	}
	if !regexp.MustCompile(`<string>j[a-z.]+@example\.com</string>`).MatchString(out) || !strings.Contains(out, "<string>dark</string>") {
		t.Fatalf("layout changed:\n%s", out)
	}
	if !plistConversion(CommandRequest{Cmd: "plutil", Args: []string{"-convert", "xml1", "-o", "-", "/h/Library/Preferences/x.plist"}}) ||
		plistConversion(CommandRequest{Cmd: "plutil", Args: []string{"-p", "/h/x.plist"}}) {
		t.Fatal("plistConversion")
	}
}
