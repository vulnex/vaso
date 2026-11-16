package main

import (
	"encoding/base64"
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

// A credential container in a plist (creds → array → dict → k) and an email
// address inside a <data> blob are disguised; the structure stays.
func TestPlistContainersAndDataDisguised(t *testing.T) {
	secret := "Q7xLm2Kv8Zq9xR7tLm2Kv8Zq9xR7tLm2Kv8Zq9xR7tLm"
	xml := `<plist version="1.0">
<dict>
	<key>creds</key>
	<array>
		<dict>
			<key>label</key>
			<string>work</string>
			<key>k</key>
			<string>` + secret + `</string>
		</dict>
	</array>
	<key>blob</key>
	<data>
	ZGF2ZS5FTUFJTENBTkFSWTRAZGF0YS5leGFtcGxl
	</data>
	<key>theme</key>
	<string>dark</string>
</dict>
</plist>
`
	c := &collector{}
	out := c.disguisePlistXML(xml)
	if strings.Contains(out, secret) || strings.Contains(out, "ZGF2ZS5FTUFJTENBTkFSWTRAZGF0YS5leGFtcGxl") {
		t.Fatalf("shipped:\n%s", out)
	}
	if !strings.Contains(out, "<string>work</string>") || !strings.Contains(out, "<string>dark</string>") {
		t.Fatalf("settings changed:\n%s", out)
	}
	m := regexp.MustCompile(`<data>([^<]*)</data>`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("data element lost:\n%s", out)
	}
	if got := decodeB64(t, m[1]); !regexp.MustCompile(`^d[A-Za-z0-9.]+@data\.example$`).MatchString(got) || strings.Contains(got, "EMAILCANARY") {
		t.Fatalf("data blob = %q", got)
	}
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
