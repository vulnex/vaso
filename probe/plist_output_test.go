package main

import (
	"bytes"
	"encoding/base64"
	"os"
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

// dt25 g9-F2/F6: a collected LaunchAgent plist — credentials under their
// EnvironmentVariables names and in ProgramArguments — is disguised by its
// structure, and no stand-in runs past </string>.
func TestCollectedPlistXMLDisguised(t *testing.T) {
	token := "2Qm7Rk9Lp4Xw8Zt3Vn6Bc1Hj5Df0Gs2Ka7Me9Ny4Pu"
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key><string>com.example.tunnel</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/homebrew/bin/ngrok</string>
		<string>start</string>
		<string>--authtoken</string>
		<string>` + token + `</string>
		<string>--password=Hy7Tg3Rf9Kd2Lp6Mz8Qw</string>
		<string>--port</string>
		<string>18789</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>OPENCLAW_GATEWAY_TOKEN</key>
		<string>f3a9c1e7b2d84f6a9e0c5b7d1a3f8e2c4b6d9a0e1f2c3d4e</string>
		<key>DB_PASSWORD</key>
		<string>Wq3ExRt5Yv8Nb3LcQ9</string>
		<key>PATH</key>
		<string>/usr/bin:/bin</string>
	</dict>
</dict>
</plist>
`
	c := &collector{}
	out := string(c.scrubSecrets("/h/Library/LaunchAgents/com.example.tunnel.plist", []byte(xml)))
	for _, raw := range []string{token[8:30], "Rf9Kd2Lp6Mz8", "c5b7d1a3f8e2c4b6", "Yv8Nb3Lc"} {
		if strings.Contains(out, raw) {
			t.Fatalf("%q shipped:\n%s", raw, out)
		}
	}
	for _, kept := range []string{"<string>--authtoken</string>", "<string>--port</string>", "<string>18789</string>", "<string>/usr/bin:/bin</string>", "<string>com.example.tunnel</string>"} {
		if !strings.Contains(out, kept) {
			t.Fatalf("%q changed:\n%s", kept, out)
		}
	}
	// every element still closes (g9-F6: …</string> became …</vksing>)
	if strings.Count(out, "</string>") != strings.Count(xml, "</string>") || !regexp.MustCompile(`<string>--password=[A-Za-z0-9]{20}</string>`).MatchString(out) {
		t.Fatalf("markup changed:\n%s", out)
	}
	// plutil's XML output gets the same rules
	if got := c.disguisePlistXML(xml); strings.Contains(got, "Yv8Nb3Lc") || strings.Count(got, "</string>") != strings.Count(xml, "</string>") {
		t.Fatalf("plutil output:\n%s", got)
	}
}

// A binary plist is disguised in place: it still parses, with the same
// structure, and only the letters and digits of credentials changed.
func TestCollectedBinaryPlistDisguised(t *testing.T) {
	in, err := os.ReadFile("testdata/agent.bplist")
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{}
	out := c.scrubSecrets("/h/Library/Preferences/com.example.agent.plist", in)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d → %d", len(in), len(out))
	}
	for _, raw := range []string{"Lp4Xw8Zt3Vn6Bc1Hj5Df0Gs2", "Rf9Kd2Lp6Mz8", "Yv8Nb3Lc", "c5b7d1a3f8e2c4b6", "dW09VP8IsHEBTjVSHN47", "eb4a05cf75af6f50"} {
		if bytes.Contains(out, []byte(raw)) {
			t.Fatalf("%q shipped", raw)
		}
	}
	// the UTF-16 password string: its units, not its bytes, are disguised
	if bytes.Contains(out, utf16BE("Kv8Zq9xR7tLm2Kv8Zq9xR7")) {
		t.Fatal("UTF-16 password shipped")
	}
	for _, kept := range []string{"--authtoken", "--password=", "com.example.agent", "dark", "DB_PASSWORD", "/opt/homebrew/bin/ngrok"} {
		if !bytes.Contains(out, []byte(kept)) {
			t.Fatalf("%q changed", kept)
		}
	}
	for i := range in {
		if in[i] != out[i] && !(isASCIIAlnum(in[i]) && isASCIIAlnum(out[i])) {
			t.Fatalf("byte %d changed from %#x to %#x (not a letter or digit)", i, in[i], out[i])
		}
	}
	if _, ok := parseBinaryPlist(append([]byte(nil), out...)); !ok {
		t.Fatal("disguised binary plist no longer parses")
	}
	// truncated or hostile input: no panic, scrubbed as text instead
	for _, bad := range [][]byte{in[:40], append([]byte("bplist00"), make([]byte, 40)...), append(append([]byte(nil), in[:len(in)-8]...), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)} {
		_ = c.scrubSecrets("/h/x.plist", bad)
	}
}

func utf16BE(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r>>8), byte(r))
	}
	return b
}

func decodeB64(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
