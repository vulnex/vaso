package main

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"math"
	"strings"
	"testing"
)

// Secrets in the syntaxes beyond strict JSON, block YAML and dotenv that
// configs and instruction files use: JSON5 (OpenClaw's openclaw.json), YAML
// flow mappings, anchors and tags, TOML multi-line strings, keyed lines in
// markdown, command strings inside configs.
func TestScrubSecretsInEveryConfigSyntax(t *testing.T) {
	const (
		s1  = "f3c9a1b7e5d2468a9b0c1d2e3f405162738495a6b7c8d9e0"
		s2  = "Pq7wX2mZ9kL4vB8n"
		s3  = "MTE5ODc2NTQzMjEwOTg3NjU0Mw.GaBcDe.Xy9Zw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8"
		s4  = "a7f3c9e1b5d24680aa7f3c9e1b5d2468"
		s5  = "c9f5e1a3d7b46802cc9f5e1a3d7b4680"
		s6  = "Zq8wX3mK9pL2vB7nR4tY6uI1oP5aS0dF"
		s7  = "Hn4bV7cX1zM8qW2eR5tY9uI3oP6aS0dG"
		s8  = "d1iaeOV4qBkdfQ1y3GQsMpSscDlkrC"
		s9  = "aqx9vJupc94tnwlavyfErGPmpGXafq"
		s10 = "noVPDF2yeE6RsXcNOPmeMjvqPVSt"
		s11 = "tdbmF4RPAfqoQB7xoFcSvTAxRzmaZs"
		s12 = "Pq7Wz2Lk9Xv4Rt8Ns3Jm6Hb1"
		s13 = "Mq3Zx8Lp2Vn7Rk4Tw9Yb6Hd1Fs5Gj0"
		s14 = "Kp4Ry7Ws2Zn9Lq3Vx8Mb5Td1"
		s15 = "Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl"
		s16 = "SH4487q7J58m1CiAhzCueQpBenQtYh"
		s17 = "5Xj8TPQxjq4i9DoV8gz4"
		s18 = "FkQ1okTBGzvAmwufUxbvJDCTbyvHNs"
		s19 = "G9eh6Yo4gfqrc5XlrWi0B26R08qz"
		s20 = "5DfJXcaYioK6cPTt9iOqHOBSWhgetH"
		s21 = "7770H2DCpYgojjHRg80USP2W"
		s22 = "b8e4d0f2c6a35791bb8e4d0f2c6a3579"
		s23 = "NKiaEdFrRgSnRFsTHsDDDXh5Jmtf"
		s24 = "7EbsDe0G9Cryn687neLfjVHq8xiM"
	)
	files := map[string]string{
		"/h/.openclaw/openclaw.json": "{\n  gateway: {\n    auth: {\n      mode: \"token\",\n      token: \"" + s1 + "\",\n      password: '" + s2 + "',\n    },\n  },\n" +
			"  channels: { discord: { token: '" + s3 + "' } },\n" +
			"  mcp: { servers: {\n    a: { command: \"npx\", args: ['-y', 'x-mcp@1.0.0', '--api-key', '" + s4 + "'], env: { MY_SERVICE_TOKEN: '" + s5 + "' } },\n" +
			"    b: { args: [\"--token\", \"" + s22 + "\"] },\n  } },\n}\n",
		"/h/.hermes/config.yaml": "auxiliary:\n  vision: {provider: custom, base_url: \"https://vision.example.com/v1\", api_key: \"" + s6 + "\"}\n" +
			"mcp_servers:\n  svc: {command: npx, args: [-y, \"svc-mcp@1.2.3\"], env: {SVC_API_TOKEN: " + s7 + "}}\n" +
			"token: &tok " + s8 + "\nsecret: !!str " + s9 + "\nflow: {token: " + s10 + ", name: x}\nmax_tokens: 4096\nlist_tokens: [" + s23 + ", 'short', \"" + s24 + "\"]  # two\n",
		"/h/.codex/config.toml": "model = \"o4\"\napi_key = \"\"\"" + s11 + "\"\"\"\n",
		"/h/.claude/CLAUDE.md": "# Project notes\nDB_PASSWORD=" + s12 + "\n- api_key: " + s13 + "\n" +
			"Use `\"client_secret\": \"" + s14 + "\"` for the staging app.\n" +
			"curl -H \"Authorization: Bearer " + s15 + "\" https://api.example.com\n" +
			"Token: Required. The password: see the team vault. Set max_tokens: 4096.\n",
		"/h/.claude/settings.json": `{"cmd": "curl -H 'Authorization: token ` + s16 + `' -u bob:` + s17 + ` https://x",` +
			`"statusLine": {"type":"command","command":"OPENAI_API_KEY=` + s18 + ` node x.js --api-key ` + s19 + `"}}`,
		"/h/.hermes/.env": "GH_PAT=" + s20 + "\nSLACK_WEBHOOK=https://hooks.slack.com/services/T000/B000/" + s21 + "\n",
	}
	secrets := []string{s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24}
	c := &collector{}
	out := map[string]string{}
	for name, content := range files {
		got := scrubFile(t, c, name, content)
		out[name] = got
		for _, s := range secrets {
			if strings.Contains(got, secretMiddle(s)) {
				t.Errorf("%s still holds secret %q:\n%s", name, s[:10], got)
			}
		}
	}
	for name, keep := range map[string][]string{
		"/h/.openclaw/openclaw.json": {`mode: "token"`, `command: "npx"`, `'-y', 'x-mcp@1.0.0', '--api-key', '`},
		"/h/.hermes/config.yaml":     {"provider: custom", `base_url: "https://vision.example.com/v1"`, "token: &tok ", "secret: !!str ", "name: x}", "max_tokens: 4096", "list_tokens: [NKiaEdFr", ", 'short', \"7EbsDe0G", "Jmtf, 'short'", "\"]  # two"},
		"/h/.codex/config.toml":      {`model = "o4"`, `api_key = """`},
		"/h/.claude/CLAUDE.md":       {"Token: Required. The password: see the team vault. Set max_tokens: 4096.", "https://api.example.com", "Authorization: Bearer Zr8Ty3Uw"},
		"/h/.claude/settings.json":   {"-u bob:", "node x.js --api-key ", "Authorization: token "},
		"/h/.hermes/.env":            {"https://hooks.slack.com/services/T000/B000/"},
	} {
		for _, k := range keep {
			if !strings.Contains(out[name], k) {
				t.Errorf("%s lost %q:\n%s", name, k, out[name])
			}
		}
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out["/h/.claude/settings.json"]), &parsed); err != nil {
		t.Fatalf("scrubbed JSON no longer parses: %v\n%s", err, out["/h/.claude/settings.json"])
	}
	for _, s := range secrets {
		if d, ok := c.disguised[s]; ok && verdictsOf(d) != verdictsOf(s) {
			t.Errorf("%q: verdicts %+v → %+v", s[:10], verdictsOf(s), verdictsOf(d))
		}
	}
}

// Command output: the value redaction stops where a URL or a value ends in
// XML and JSON (plutil -convert xml1, -o json), so parsed output stays
// well-formed and keeps what isn't a credential.
func TestRedactSecretValuesKeepsStructuredOutput(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>lastURL</key><string>https://chatgpt.com/cb?state=1&amp;access_token=abc</string>
<key>site</key><string>https://ex.com/?token=Q7rT2mZ9kLp4Vw8N</string>
<key>email</key><string>me@example-corp.com</string>
</dict></plist>
`
	got := redactSecretValues(plist)
	if strings.Contains(got, "Q7rT2mZ9kLp4Vw8N") {
		t.Errorf("token shipped:\n%s", got)
	}
	d := xml.NewDecoder(strings.NewReader(got))
	for {
		if _, err := d.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("redacted plist no longer parses: %v\n%s", err, got)
		}
	}
	if !strings.Contains(got, "<string>me@example-corp.com</string>") {
		t.Errorf("e-mail lost:\n%s", got)
	}

	js := `{"a":{"site":"https://example-corp.com","trainingAllowed":true,"contact":"me@example-corp.com"},` +
		`"proxy":"https://u:Sup3rS3cretPassw0rd@gw.example.com:8080",` +
		`"headers":{"Authorization":"Bearer polsecret_0123456789abcdefABCDEF"}}`
	got = redactSecretValues(js)
	var parsed struct{ A map[string]interface{} }
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("redacted JSON no longer parses: %v\n%s", err, got)
	}
	if parsed.A["site"] != "https://example-corp.com" || parsed.A["contact"] != "me@example-corp.com" || parsed.A["trainingAllowed"] != true {
		t.Errorf("non-secret values changed:\n%s", got)
	}
	for _, s := range []string{"Sup3rS3cretPassw0rd", "polsecret_0123456789"} {
		if strings.Contains(got, s) {
			t.Errorf("%s shipped:\n%s", s, got)
		}
	}
	if !strings.Contains(got, `"Authorization":"Bearer [redacted]"`) || !strings.Contains(got, "@gw.example.com:8080") {
		t.Errorf("structure lost:\n%s", got)
	}

	stderr := "Error: unknown gateway\nAuthorization: Bearer oshtok_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1\nAuthorization: token Q7rT2mZ9kLp4Vw8NcB1d\nversion: 0.1.2\n"
	got = redactSecretValues(stderr)
	if strings.Contains(got, "oshtok_9f8e") || strings.Contains(got, "Q7rT2mZ9kLp4") || !strings.Contains(got, "version: 0.1.2") {
		t.Errorf("command output:\n%s", got)
	}
}

// Round 2: a keyed value is disguised whole — to its closing quote, or in
// free text to the end of the line — whatever punctuation it holds; JSON5
// comments and line continuations, YAML block scalars and explicit keys.
func TestScrubSecretsWholeValues(t *testing.T) {
	part := func(c byte) string { return string(c) + "q7Wz2Lk9Xv4Rt8Ns3Jm" }
	secrets := map[string]string{}
	val := func(name string, a, b byte, sep string) string {
		v := part(a) + sep + part(b)
		secrets[name] = v
		return v
	}
	md := "# notes\n" +
		"signing_secret: \"" + val("amp", 'A', 'B', "&") + "\"\n" +
		"signing_secret: \"" + val("semi", 'E', 'F', ";") + "\"\n" +
		"signing_secret: \"" + val("space", 'G', 'H', " ") + "\"\n" +
		"SECRET_KEY=" + val("pipe", 'I', 'J', "|") + "\n" +
		"password: " + val("comma", 'K', 'L', ",") + " # old\n" +
		"* token = \"" + val("apos", 'M', 'N', "'") + "\"\n" +
		"| API_KEY | " + val("table", 'O', 'P', "") + " |\n" +
		"**API key**: " + val("bold", 'U', 'V', "") + "\n" +
		"| Setting | Value |\n| Auth method | OAuth device flow |\n**Token**: see the vault\n"
	json5 := "{\n  auth: { password: /* inline */ \"" + val("comment", 'B', 'C', "") + "\" },\n" +
		"  slack: { botToken: \"D4e5F6g7H8i9J0k1\\\nL2m3N4o5P6q7R8s9\" },\n}\n"
	secrets["continued"] = "L2m3N4o5P6q7R8s9"
	yml := "vision:\n  api_key: |\n    " + val("literal", 'Y', 'Z', "") + "\n  base_url: \"https://v.example.com/v1\"\n" +
		"compression:\n  api_key: >-\n    " + val("folded", 'X', 'W', "") + "\n" +
		"web:\n  ? api_key2\n  : " + val("explicit", 'V', 'T', "") + "\n" +
		"doc:\n  description: |\n    Token handling is described here\n    in two lines\n"
	c := &collector{}
	out := scrubFile(t, c, "/h/.claude/CLAUDE.md", md) + scrubFile(t, c, "/h/.openclaw/openclaw.json", json5) + scrubFile(t, c, "/h/.hermes/config.yaml", yml)
	for name, s := range secrets {
		for _, piece := range []string{s[8 : len(s)-4], s[len(s)-12:]} {
			if strings.Contains(out, piece) {
				t.Errorf("%s: %q shipped:\n%s", name, piece, out)
			}
		}
	}
	for _, keep := range []string{" # old\n", "| Auth method | OAuth device flow |", "**Token**: see the vault", "Token handling is described here", `base_url: "https://v.example.com/v1"`, "/* inline */ \"Bq7Wz2Lk"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q:\n%s", keep, out)
		}
	}
}

// The stand-in keeps every entropy a check computes (whitespace in the
// value or not, 4.5 for GEM-001, QC-001, CC-004 and the other thresholds)
// and none of the value's hidden characters: a middle position keeps its
// character only when the kept head/tail shows that character anyway.
func TestDisguiseKeepsEntropyNotCharacters(t *testing.T) {
	token := func(alphabet string) string {
		b := make([]byte, 40)
		for j := range b {
			b[j] = alphabet[randIndex(len(alphabet))]
		}
		return string(b)
	}
	// at most half of each class in use: a substitution always exists
	values := []string{"Wq7Wz2Lk9Xv4Rt8Ns3Jm&Xq7Wz2Lk9Xv4Rt8Ns3Jm", "Yq7Wz2Lk9Xv4Rt8Ns3Jm Zq7Wz2Lk9Xv4Rt8Ns3Jm"}
	for i := 0; i < 200; i++ {
		values = append(values, token("ghijklmnopGHIJKLMNOP01234-_"))
	}
	// any token, near-complete classes included
	var any []string
	for i := 0; i < 200; i++ {
		any = append(any, token("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"))
	}
	for _, v := range append(values, any...) {
		c := &collector{}
		d := c.disguise(v)
		if d == v || verdictsOf(d) != verdictsOf(v) {
			t.Fatalf("disguise(%q) = %q: verdicts %+v → %+v", v, d, verdictsOf(v), verdictsOf(d))
		}
		if math.Abs(shannonEntropy(d)-shannonEntropy(v)) > 1e-9 {
			t.Fatalf("disguise(%q) = %q: entropy %.3f → %.3f", v, d, shannonEntropy(v), shannonEntropy(d))
		}
		pre, suf := keepBounds(len(v))
		shown := v[:pre] + v[len(v)-suf:]
		weak := map[int]bool{} // CFG-009 matches stay as they are
		for _, re := range weakRes {
			for _, loc := range re.FindAllStringIndex(v, -1) {
				for j := loc[0]; j < loc[1]; j++ {
					weak[j] = true
				}
			}
		}
		for j := pre; j < len(v)-suf; j++ {
			if isASCIIAlnum(v[j]) && d[j] == v[j] && !weak[j] && strings.IndexByte(shown, v[j]) < 0 {
				t.Fatalf("disguise(%q) = %q keeps %q at %d", v, d, v[j], j)
			}
		}
	}
	// A value using nearly a whole class can't be substituted: the random
	// stand-in still keeps every verdict, entropy band included
	for i := 0; i < 20; i++ {
		c := &collector{}
		if d := c.disguise(genericHigh); d == genericHigh || verdictsOf(d) != verdictsOf(genericHigh) {
			t.Fatalf("disguise(%q) = %q", genericHigh, d)
		}
	}
}

// WHATWG: userinfo ends at the last @ before the host.
func TestURLPasswordToLastAt(t *testing.T) {
	const u = "https://u:p@ssW0rdAtSign99@h.example/x"
	if got := redactSecretValues(u); got != "https://[redacted]@h.example/x" {
		t.Errorf("command output: %q", got)
	}
	c := &collector{}
	got := scrubFile(t, c, "/h/.claude/settings.json", `{"url":"`+u+`","contact":"a@b.example"}`)
	if strings.Contains(got, "ssW0rdAtSign") || !strings.Contains(got, "@h.example/x") || !strings.Contains(got, `"a@b.example"`) {
		t.Errorf("file: %s", got)
	}
}

// An unquoted JSON number under a secret name (`"client_secret": 1234…`) is
// disguised like a string value; a number under another name is kept.
func TestScrubSecretsJSONNumberValue(t *testing.T) {
	const secret = "739104826501938475620193"
	in := "{\"client_secret\": " + secret + ", \"timeout_ms\": 300000000000000, \"port\": 8080}\n"
	out := scrubFile(t, &collector{}, "/h/.config/app/settings.json", in)
	if strings.Contains(out, secret[8:len(secret)-4]) {
		t.Errorf("numeric secret shipped: %s", out)
	}
	for _, keep := range []string{"\"timeout_ms\": 300000000000000", "\"port\": 8080"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q: %s", keep, out)
		}
	}
}

// A random capability token in a URL path is disguised even when it happens
// to have no digit (1 in ~5000 random 48-char tokens), or no upper case.
func TestScrubSecretsURLPathTokenWithoutDigit(t *testing.T) {
	for _, tok := range []string{
		"QwErTyUiOpAsDfGhJkLzXcVbNmQaZwSxEdCrFvTgByHnUjMi",
		"q7w2e9r4t6y1u8i3o5p0a7s2d9f4g6h1j8k3l5z0x7c2v9b4",
	} {
		in := "{\"url\": \"https://mcp.example.com/u/" + tok + "/sse\"}\n"
		out := scrubFile(t, &collector{}, "/h/.qwen/trustedFolders.json", in)
		if strings.Contains(out, tok[8:len(tok)-4]) {
			t.Errorf("path token shipped: %s", out)
		}
		if !strings.Contains(out, "https://mcp.example.com/u/") || !strings.Contains(out, "/sse\"") {
			t.Errorf("URL structure lost: %s", out)
		}
	}
	// a path word that isn't random stays
	in := "{\"url\": \"https://docs.example.com/guides/getting-started-with-the-server\"}\n"
	if out := scrubFile(t, &collector{}, "/h/.qwen/settings.json", in); out != in {
		t.Errorf("ordinary path changed: %s", out)
	}
}
