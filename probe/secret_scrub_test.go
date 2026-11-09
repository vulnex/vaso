package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// tsList extracts the regex literals of one TS array (`const NAME = [ … ];`).
func tsList(t *testing.T, file, name string, item *regexp.Regexp) [][]string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", file))
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(src), name+" = [")
	if start < 0 {
		t.Fatalf("%s not found in %s", name, file)
	}
	body := string(src)[start:]
	body = body[:strings.Index(body, "\n];")]
	return item.FindAllStringSubmatch(body, -1)
}

func TestAPIKeyPatternsMatchTS(t *testing.T) {
	var ts []string
	for _, m := range tsList(t, "src/core/patterns.ts", "API_KEY_PATTERNS", regexp.MustCompile(`\{ pattern: /(.*)/([a-z]*), name:`)) {
		if m[2] != "" {
			t.Fatalf("API key pattern /%s/%s has flags the probe doesn't apply", m[1], m[2])
		}
		ts = append(ts, m[1])
	}
	if strings.Join(ts, "\n") != strings.Join(apiKeyPatterns, "\n") {
		t.Fatalf("probe API key patterns differ from API_KEY_PATTERNS:\nTS:    %q\nprobe: %q", ts, apiKeyPatterns)
	}
}

func TestExtraTokenPatternsMatchTS(t *testing.T) {
	var ts []string
	for _, m := range tsList(t, "src/analyzers/secret-values.ts", "EXTRA_TOKEN_PATTERNS: RegExp[]", regexp.MustCompile(`(?m)^\s*/(.*)/([a-z]*),`)) {
		p := m[1]
		if m[2] == "i" {
			p = "(?i)" + p
		} else if m[2] != "" {
			t.Fatalf("token pattern /%s/%s: unsupported flags", m[1], m[2])
		}
		ts = append(ts, p)
	}
	if strings.Join(ts, "\n") != strings.Join(extraTokenPatterns, "\n") {
		t.Fatalf("probe extra token patterns differ from EXTRA_TOKEN_PATTERNS:\nTS:    %q\nprobe: %q", ts, extraTokenPatterns)
	}
}

func TestWeakPatternsMatchTS(t *testing.T) {
	var ts []string
	for _, m := range tsList(t, "src/checks/config/cfg-009-default-credentials.ts", "WEAK_PATTERNS", regexp.MustCompile(`(?m)^\s*/(.*)/([a-z]*),\s*$`)) {
		p := m[1]
		if m[2] == "i" {
			p = "(?i)" + p
		} else if m[2] != "" {
			t.Fatalf("weak pattern /%s/%s: unsupported flags", m[1], m[2])
		}
		ts = append(ts, p)
	}
	if strings.Join(ts, "\n") != strings.Join(weakPatterns, "\n") {
		t.Fatalf("probe weak patterns differ from WEAK_PATTERNS:\nTS:    %q\nprobe: %q", ts, weakPatterns)
	}
}

func TestProfileWordsMatchTS(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "src", "core", "patterns.ts"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)const PROFILE_WORDS = new Set\(\[(.*?)\]\)`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("PROFILE_WORDS not found")
	}
	var ts []string
	for _, w := range regexp.MustCompile(`'([a-z]+)'`).FindAllStringSubmatch(m[1], -1) {
		ts = append(ts, w[1])
	}
	if strings.Join(ts, " ") != strings.Join(profileWords, " ") {
		t.Fatalf("profile words differ:\nTS:    %q\nprobe: %q", ts, profileWords)
	}
}

// testdata/secret-verdicts.json holds the CLI's verdicts (src/core/secret-verdicts.test.ts
// checks them against the TS functions); the probe's ports must agree.
func TestSecretVerdictsMatchCLI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "secret-verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Value                        string
		Placeholder, Weak, Reference bool
		Token                        *bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if got := isPlaceholderSecret(c.Value); got != c.Placeholder {
			t.Errorf("isPlaceholderSecret(%q) = %v, CLI says %v", c.Value, got, c.Placeholder)
		}
		if got := isWeakCredential(c.Value); got != c.Weak {
			t.Errorf("isWeakCredential(%q) = %v, CLI says %v", c.Value, got, c.Weak)
		}
		if got := isSecretReference(c.Value); got != c.Reference {
			t.Errorf("isSecretReference(%q) = %v, CLI says %v", c.Value, got, c.Reference)
		}
		if c.Token == nil {
			continue
		}
		if got := tokenFormats(c.Value) != 0; got != *c.Token {
			t.Errorf("known token format(%q) = %v, CLI says %v", c.Value, got, *c.Token)
		}
		// a stand-in matches the same formats and keeps the format's prefix
		for i := 0; i < 20 && *c.Token; i++ {
			col := &collector{}
			d := col.disguise(c.Value)
			if d == c.Value || tokenFormats(d) != tokenFormats(c.Value) || knownTokenPrefix.FindString(d) != knownTokenPrefix.FindString(c.Value) {
				t.Fatalf("disguise(%q) = %q changed its token format", c.Value, d)
			}
		}
	}
}

const (
	anthropicKey = "sk-ant-api03-Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri"
	nvidiaKey    = "nvapi-Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5RiPz"
	telegramTok  = "7093846152:AAHw3nB8cK1pZ6vR4tY9mQ2xL7jD5sF0gHe"
	openrouter   = "sk-or-v1-8f1c2e9a7b3d4c5e6f708192a3b4c5d68f1c2e9a7b3d4c5e"
	genericHigh  = "Zq8!Lm3#Rt7$Wp2%Yx6^Bn4&Kd9*Hs5(Gf1)Vc0"
	githubPAT    = "ghp_Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri"
	urlSafe      = "Hc4Xk9Pq2Wm7Ln3Rb8Tv5Zs1Yd6Gf0Je"
)

// secretMiddle is a part of a secret that must never ship.
func secretMiddle(s string) string {
	pre, suf := keepBounds(len(s))
	return s[pre : len(s)-suf]
}

func scrubFile(t *testing.T, c *collector, name, content string) string {
	t.Helper()
	out := string(c.scrubSecrets(name, []byte(content)))
	if len(out) != len(content) {
		t.Fatalf("%s: length changed %d → %d", name, len(content), len(out))
	}
	return out
}

func TestScrubSecretsDisguisesWithoutChangingVerdicts(t *testing.T) {
	c := &collector{}
	files := map[string]string{
		"/h/lyrie/.env": "# LLM\nANTHROPIC_API_KEY=" + anthropicKey + "\nexport LYRIE_TELEGRAM_TOKEN=\"" + telegramTok + "\" # bot\n" +
			"#OPENAI_API_KEY=" + githubPAT + "\nNODE_ENV=development\nHERMES_AUTH_MODE=none\nBROWSER_SESSION_TIMEOUT=300\n" +
			"OPENAI_API_KEY=sk-...\nAPI_SERVER_KEY=changeme\nGITHUB_TOKEN=${GH_TOKEN}\nSECRET_TOKEN=" + genericHigh + "\n",
		"/h/.nemoclaw/credentials.json": "{\n  \"NVIDIA_API_KEY\": \"" + nvidiaKey + "\"\n}\n",
		"/h/.qwen/settings.json": `{"security":{"auth":{"selectedType":"openai","apiKey":"` + openrouter + `"}},` +
			`"mcpServers":{"gh":{"command":"npx","args":["-y","srv","--api-key","` + genericHigh + `"],` +
			`"env":{"GITHUB_TOKEN":"` + githubPAT + `"},"headers":{"Authorization":"Bearer ` + genericHigh + `"},` +
			`"url":"https://user:` + urlSafe + `@mcp.example.com/sse?api_key=` + urlSafe + `&region=eu"}},` +
			`"note":"line\nbreak \"q\" \u00e9","authType":"oauth-personal","tokenizer":"cl100k"}`,
		"/h/.picoclaw/config.yaml": "providers:\n  - name: openai\n    api_key: \"" + anthropicKey + "\"  # key\n    password: hunter2-Q7rT2mZ9kL\n    token: ${TOKEN}\n",
		"/h/.codex/config.toml":    "[model_providers.x]\nbase_url = \"https://api.example.com\"\napi_key = \"" + githubPAT + "\"\nenv = { OPENAI_API_KEY = \"" + anthropicKey + "\" }\n",
		"/h/.claude/CLAUDE.md": "Use " + githubPAT + " for the API. Placeholder: sk-ant-your-key-here.\n" +
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAq7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri\n-----END RSA PRIVATE KEY-----\n",
	}
	secrets := []string{urlSafe, anthropicKey, nvidiaKey, telegramTok, openrouter, genericHigh, githubPAT, "q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri", "hunter2-Q7rT2mZ9kL"}
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

	// What checks read stays: settings, references, placeholders, weak defaults, URLs, PEM armor
	for name, keep := range map[string][]string{
		"/h/lyrie/.env":                 {"NODE_ENV=development", "HERMES_AUTH_MODE=none", "BROWSER_SESSION_TIMEOUT=300", "OPENAI_API_KEY=sk-...", "API_SERVER_KEY=changeme", "GITHUB_TOKEN=${GH_TOKEN}", "# bot"},
		"/h/.qwen/settings.json":        {`"authType":"oauth-personal"`, `"selectedType":"openai"`, `"tokenizer":"cl100k"`, "https://user:", "@mcp.example.com/sse?api_key=", "&region=eu", `"Authorization":"Bearer `, `line\nbreak \"q\" \u00e9`},
		"/h/.picoclaw/config.yaml":      {"name: openai", "token: ${TOKEN}", "# key"},
		"/h/.codex/config.toml":         {`base_url = "https://api.example.com"`},
		"/h/.claude/CLAUDE.md":          {"sk-ant-your-key-here", "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"},
		"/h/.nemoclaw/credentials.json": {`"NVIDIA_API_KEY": "nvapi-Q7`},
	} {
		for _, k := range keep {
			if !strings.Contains(out[name], k) {
				t.Errorf("%s lost %q:\n%s", name, k, out[name])
			}
		}
	}

	// JSON stays valid and keeps its shape
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out["/h/.qwen/settings.json"]), &parsed); err != nil {
		t.Fatalf("scrubbed JSON no longer parses: %v\n%s", err, out["/h/.qwen/settings.json"])
	}

	// Every disguise gets the verdicts its secret gets, keeps what reports show,
	// and one secret gets one stand-in everywhere
	for _, s := range secrets {
		d, ok := c.disguised[s]
		if !ok {
			continue
		}
		if verdictsOf(d) != verdictsOf(s) {
			t.Errorf("%q: verdicts %+v → %+v", s[:10], verdictsOf(s), verdictsOf(d))
		}
		pre, suf := keepBounds(len(s))
		if d[:pre] != s[:pre] || d[len(d)-suf:] != s[len(s)-suf:] {
			t.Errorf("%q: shown prefix/suffix changed: %q", s, d)
		}
	}
	if !strings.Contains(out["/h/.codex/config.toml"], c.disguised[anthropicKey]) || !strings.Contains(out["/h/lyrie/.env"], c.disguised[anthropicKey]) {
		t.Error("the same key got different stand-ins in two files")
	}
}

func TestDisguisePreservesEveryAPIKeyFormat(t *testing.T) {
	samples := []string{
		"sk-proj-Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri", openrouter, "sk-Q7rT2mZ9kLp4Vw8NcB1dYh6J", anthropicKey,
		"AKIAQ7RT2MZ9KLP4VW8N", githubPAT, "gho_Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri", "glpat-Q7rT2mZ9kLp4Vw8NcB1d",
		"xoxb-1234567890-0987654321-Q7rT2mZ9kLp4Vw8NcB1dYh6J", "xoxp-4839201756-9384756102-Q7rT2mZ9kLp4Vw8NcB1dYh6J",
		telegramTok, "devin-" + strings.Repeat("Q7rT2mZ9kLp4$Vw8.NcB1d", 3), "cog_Q7rT2mZ9kLp4Vw8Nc", "apk_user_Q7rT2mZ9kLp4Vw8Nc",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Q7rT2mZ9kLp4Vw8NcB1dYh6J",
	}
	for i := 0; i < 50; i++ { // random replacement: repeat
		c := &collector{}
		for _, s := range samples {
			d := c.disguise(s)
			if d == s || len(d) != len(s) || verdictsOf(d) != verdictsOf(s) {
				t.Fatalf("disguise(%q) = %q (verdicts %+v → %+v)", s, d, verdictsOf(s), verdictsOf(d))
			}
			for _, re := range apiKeyRes {
				if re.MatchString(s) && re.FindString(d) == "" {
					t.Fatalf("disguise(%q) = %q no longer matches %s", s, d, re)
				}
			}
		}
	}
}

func TestCollectScrubsConfigsButNotSkillTrees(t *testing.T) {
	home := t.TempDir()
	write := func(rel, content string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env := write(".lyrie/.env", "ANTHROPIC_API_KEY="+anthropicKey+"\n")
	skill := write(".claude/skills/demo/SKILL.md", "key "+githubPAT+"\n")
	snap := Collect(ProbeManifest{FilePaths: []string{env}, GlobPatterns: []string{filepath.Join(home, ".claude/skills/**")}}, false)
	if strings.Contains(snap.Files[env].Content, secretMiddle(anthropicKey)) {
		t.Errorf(".env shipped its key: %q", snap.Files[env].Content)
	}
	if !strings.Contains(snap.Files[skill].Content, githubPAT) {
		t.Errorf("skill file changed (IOC hashes read it verbatim): %q", snap.Files[skill].Content)
	}
}

// Capability URLs (findUrlSecrets in src/mcp/config-secrets.ts): the path is
// the credential. Only that segment is disguised in files and redacted in
// command output; scheme, host and the rest of the path stay.
func TestURLPathSecrets(t *testing.T) {
	const (
		zapier   = "NjQ4ZTk2YmUtZmY3Ny00ZDQ5LWE1ZjMtYjc2ZTkzN2E2NTRhOjE2MzQ1Njc4OQ=="
		zapierAK = "sk-ak-Zq7XyR9kLmN3pQ8sT2vW5bC6dF1gH4jK"
		discord  = "Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5RiPzQ7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5"
		random   = "Hc4Xk9Pq2Wm7Ln3Rb8Tv5Zs1Yd6Gf0Je"
	)
	cfg := `{"mcpServers":{` +
		`"a":{"url":"https://mcp.zapier.com/api/mcp/s/` + zapier + `/mcp"},` +
		`"b":{"url":"https://actions.zapier.com/mcp/` + zapierAK + `/sse"},` +
		`"c":{"url":"https://discord.com/api/webhooks/123456789012345678/` + discord + `"},` +
		`"d":{"url":"https://mcp.example.com/u/` + random + `/sse"},` +
		`"e":{"url":"https://github.com/modelcontextprotocol/servers/tree/main/src"}}}`
	md := "Use (https://mcp.zapier.com/api/mcp/s/" + zapier + ") for Zapier.\n"
	for i := 0; i < 20; i++ {
		c := &collector{}
		out := scrubFile(t, c, "/h/Library/Application Support/Claude/claude_desktop_config.json", cfg)
		for _, s := range []string{zapier, zapierAK, discord, random} {
			if strings.Contains(out, secretMiddle(s)) {
				t.Fatalf("%s shipped: %s", s, out)
			}
		}
		for _, keep := range []string{"https://mcp.zapier.com/api/mcp/s/", "/mcp\"", "https://actions.zapier.com/mcp/sk-ak-", "/sse\"",
			"https://discord.com/api/webhooks/123456789012345678/", "https://mcp.example.com/u/", "https://github.com/modelcontextprotocol/servers/tree/main/src"} {
			if !strings.Contains(out, keep) {
				t.Fatalf("URL structure lost (%s): %s", keep, out)
			}
		}
		if got := scrubFile(t, c, "/h/.claude/CLAUDE.md", md); strings.Contains(got, secretMiddle(zapier)) || !strings.HasSuffix(got, ") for Zapier.\n") {
			t.Fatalf("Zapier URL in prose: %s", got)
		}
		// the stand-in is still a random path token (same verdict remotely)
		d := c.disguise(random)
		if !randomPathSegment(d) {
			t.Fatalf("stand-in %q no longer a random path token", d)
		}
	}

	out := redactSecretValues(cfg)
	for _, s := range []string{zapier, zapierAK, discord, random} {
		if strings.Contains(out, secretMiddle(s)) {
			t.Fatalf("%s in command output: %s", s, out)
		}
	}
	if !strings.Contains(out, `"https://mcp.zapier.com/api/mcp/s/[redacted]/mcp"`) || !strings.Contains(out, "servers/tree/main/src") {
		t.Fatalf("command output structure: %s", out)
	}
}

// A value in a known token format is disguised under any key name: GEM-001
// and QC-001 flag gsk_/hf_/xai- keys stored under a harmless name too.
func TestTokenShapedCoversEveryFormat(t *testing.T) {
	samples := []string{
		"github_pat_11ABCDEFG0Q7rT2mZ9kLp4Vw8NcB1d_Yh6Ju3Fs0GxEa5Ri", "gho_Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri",
		"sk-or-v1-8f1c2e9a7b3d4c5e6f708192a3b4c5d68f1c2e9a7b3d4c5e", anthropicKey, "sk-ak-Zq7XyR9kLmN3pQ8sT2vW5bC6dF1gH4jK",
		"sk-lf-1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6", "xoxe-1-Q7rT2mZ9kLp4Vw8NcB1d", "AIzaSyQ7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa",
		"ASIAQ7RT2MZ9KLP4VW8N", "gsk_Q7rT2mZ9kLp4Vw8NcB1dYh6J", "hf_Q7rT2mZ9kLp4Vw8NcB1dYh6J",
		"xai-Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri", nvidiaKey, "glpat-Q7rT2mZ9kLp4Vw8NcB1d",
		"patQ7rT2mZ9kLp4Vw.9c1e5b2d4f6a8c0e9c1e5b2d4f6a8c0e9c1e5b2d4f6a8c0e9c1e5b2d4f6a8c0e", // Airtable
	}
	for _, s := range samples {
		if tokenFormats(s) == 0 {
			t.Fatalf("%q matches no known format", s)
		}
		c := &collector{}
		out := scrubFile(t, c, "/h/.gemini/settings.json", `{"FN_ODD_NAME": "`+s+`"}`)
		if strings.Contains(out, secretMiddle(s)) {
			t.Errorf("%s shipped under a harmless key: %s", s, out)
		}
		if strings.Contains(redactSecretValues("x "+s+" y"), secretMiddle(s)) {
			t.Errorf("%s in command output", s)
		}
	}
}

// A passphrase of lowercase words under a password or secret name is the
// credential; the same shape under any other key is a setting and is kept.
func TestPassphraseUnderCredentialNames(t *testing.T) {
	secrets := map[string]string{
		"/h/.gemini/settings.json": `{"FN_ANTHROPIC_PASSWORD": "correct-horse-battery-staple-orbit", "auth": "oauth-personal", "auth_mode": "oauth", "password_policy": "strict-mode", "secret_file": "/etc/app/secret-file-path.txt"}`,
		"/h/.hermes/.env":          "DB_PASSWORD=correct-horse-battery-staple\nAUTH_MODE=oauth-personal-device-flow\n",
		"/h/.hermes/config.yaml":   "db:\n  passphrase: lunar_tulip_quartz_meadow\n  password_policy: strict-mode\n  auth: oauth-personal\n",
		"/h/.codex/config.toml":    "client_secret = \"correct horse battery staple\"\nsecret_backend = \"hashicorp-vault-kv\"\n",
		"/h/.claude/CLAUDE.md":     "The DB password: lunar-tulip-quartz-meadow\npassword: see the vault\n",
	}
	hidden := []string{"horse-battery-staple", "tulip_quartz", "horse battery staple", "tulip-quartz"}
	kept := []string{`"auth": "oauth-personal"`, `"auth_mode": "oauth"`, `"password_policy": "strict-mode"`, "/etc/app/secret-file-path.txt",
		"AUTH_MODE=oauth-personal-device-flow", "password_policy: strict-mode", "auth: oauth-personal", `secret_backend = "hashicorp-vault-kv"`,
		"password: see the vault"}
	for i := 0; i < 20; i++ {
		c := &collector{}
		all := ""
		for path, content := range secrets {
			all += scrubFile(t, c, path, content)
		}
		for _, h := range hidden {
			if strings.Contains(all, h) {
				t.Fatalf("passphrase %q shipped:\n%s", h, all)
			}
		}
		for _, k := range kept {
			if !strings.Contains(all, k) {
				t.Fatalf("setting %q changed:\n%s", k, all)
			}
		}
	}
	// verdicts hold: weak stays weak, a profile name stays a reference
	for _, v := range []string{"changeme123", "correct-horse-battery-staple", "admin-password-reset", "production-us-east-2"} {
		c := &collector{}
		if d := c.disguiseKeyed("password", v); verdictsOf(d) != verdictsOf(v) {
			t.Fatalf("disguiseKeyed(%q) = %q changed verdicts %+v → %+v", v, d, verdictsOf(v), verdictsOf(d))
		}
	}
	if out := redactSecretValues("DB_PASSWORD=correct-horse-battery-staple auth=oauth-personal"); strings.Contains(out, "horse") || !strings.Contains(out, "oauth-personal") {
		t.Fatalf("command output: %s", out)
	}
}

// g1-N1: key=\"value\" and key: \"value\" inside a JSON string (custom
// instructions, a command string) are disguised up to the escaped closing
// quote; the file stays valid JSON of the same length.
func TestEscapedQuotedPairInJSONString(t *testing.T) {
	const pw, tok = "Kq7QUOTEPW2zXw9mNbVc", "Kq7ESCTOKEN3zXw9mNbVcLpOiUy"
	in := `{"mcpCustomInstructions": {"p2": "password=\"` + pw + `\"", "p4": "{\"api_key\": \"` + tok + `\"}", "p5": "label=\"plain words\""}}`
	for i := 0; i < 20; i++ {
		c := &collector{}
		out := scrubFile(t, c, "/h/.grokbot/settings.json", in)
		if strings.Contains(out, secretMiddle(pw)) || strings.Contains(out, secretMiddle(tok)) {
			t.Fatalf("escaped-quoted secret shipped: %s", out)
		}
		var v map[string]map[string]string
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("invalid JSON after scrub: %v\n%s", err, out)
		}
		if p2 := v["mcpCustomInstructions"]["p2"]; !strings.HasPrefix(p2, `password="Kq7Q`) || !strings.HasSuffix(p2, `"`) || len(p2) != len(`password="`+pw+`"`) {
			t.Fatalf("p2 = %q", p2)
		}
		if !strings.Contains(out, `label=\"plain words\"`) {
			t.Fatalf("a non-secret pair changed: %s", out)
		}
	}
	if out := redactSecretValues(`password=\"` + pw + `\"`); strings.Contains(out, secretMiddle(pw)) {
		t.Fatalf("command output: %s", out)
	}
}

// g8: Telegram bot tokens in URL paths, signature and session parameters,
// Zapier catch hooks and hex/dotted path tokens never ship.
func TestURLSecretsTelegramSignaturesSessions(t *testing.T) {
	secrets := []string{
		"1234567890:AAH7xk2Lm9Qp4Rs6Tu8Vw0Xy2Za4Bc6De8F",
		"Sg4Hj6Kl8Zx0Cv2Bn4Mq6Wr8Ty0Ui2Op", "Js4Hj6Kl8Zx0Cv2Bn4Mq6Wr8Ty0Ui2Op", "Sn4Hj6Kl8Zx0Cv2Bn4Mq6Wr8Ty0Ui2Op",
		"4f2b8c1e9a4d4e6fb1c27d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90123",
		"q7w2e9r4t6y1u8i3", "9c1e5b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e",
		"Rk4.Tz8~Wq2%2FMn6Xb1Lp9Vd3Hs5",
	}
	cfg := `{"a": "https://api.telegram.org/bot` + secrets[0] + `/sendMessage",` +
		` "b": "https://x.example.com/api?sig=` + secrets[1] + `",` +
		` "c": "https://x.example.com/p;jsessionid=` + secrets[2] + `",` +
		` "d": "https://x.example.com/p?signature=` + secrets[3] + `",` +
		` "e": "https://x.example.com/p?X-Amz-Signature=` + secrets[4] + `",` +
		` "f": "https://hooks.zapier.com/hooks/catch/123456/` + secrets[5] + `/",` +
		` "g": "https://hooks.example.com/mcp/` + secrets[6] + `",` +
		` "h": "https://x.example.com/s/` + secrets[7] + `/sse"}`
	keep := []string{"https://api.telegram.org/bot", "/sendMessage", "?sig=", ";jsessionid=", "?X-Amz-Signature=", "https://hooks.zapier.com/hooks/catch/123456/"}
	for i := 0; i < 20; i++ {
		c := &collector{}
		out := scrubFile(t, c, "/h/.claude/settings.json", cfg)
		for _, s := range secrets {
			if strings.Contains(out, secretMiddle(s)) {
				t.Fatalf("%s shipped: %s", s, out)
			}
		}
		for _, k := range keep {
			if !strings.Contains(out, k) {
				t.Fatalf("structure %q lost: %s", k, out)
			}
		}
		// the bot token keeps its shape (findUrlSecrets' bot<id>:<secret>)
		if !regexp.MustCompile(`/bot[0-9]{10}:[A-Za-z0-9_-]{35}/sendMessage`).MatchString(out) {
			t.Fatalf("bot token shape lost: %s", out)
		}
	}
	out := redactSecretValues(cfg)
	for _, s := range secrets {
		if strings.Contains(out, secretMiddle(s)) {
			t.Fatalf("%s in command output: %s", s, out)
		}
	}
	// a catch key of lowercase letters only is still the secret
	c := &collector{}
	if out := scrubFile(t, c, "/h/x.json", `{"u": "https://hooks.zapier.com/hooks/catch/123456/otibknhcgnewvlhw/"}`); strings.Contains(out, "otibknhcgnewvlhw") {
		t.Fatalf("lowercase catch key shipped: %s", out)
	}
}

// Path tokens with %XX escapes keep them valid (the TS rule reads them as
// escapes); ;session= and ;token= matrix parameters are disguised.
func TestURLPathTokenEscapesAndMatrixParams(t *testing.T) {
	tok := "Rk4Tz8Wq2%2FMn6Xb1Lp9Vd3Hs5Fq7%3DAb"
	cfg := `{"u": "https://mcp.example.com/s/` + tok + `/sse", "v": "https://x.example.com/p;session=Se4Hj6Kl8Zx0Cv2Bn4Mq;token=Tk4Hj6Kl8Zx0Cv2Bn4Mq/x"}`
	for i := 0; i < 50; i++ {
		c := &collector{}
		out := scrubFile(t, c, "/h/.claude/settings.json", cfg)
		for _, s := range []string{tok, "Se4Hj6Kl8Zx0Cv2Bn4Mq", "Tk4Hj6Kl8Zx0Cv2Bn4Mq"} {
			if strings.Contains(out, secretMiddle(s)) {
				t.Fatalf("%s shipped: %s", s, out)
			}
		}
		m := regexp.MustCompile(`/s/([^/]+)/sse`).FindStringSubmatch(out)
		if m == nil || !sameEscapes(tok, m[1]) || randomPathSegment(m[1]) != randomPathSegment(tok) {
			t.Fatalf("escape or verdict lost: %s", out)
		}
	}
}

// Escaped quotes at any depth: JSON embedded in a JSON string (a pasted curl
// -d body) writes its quotes as \\\" — still a quoted value under its key.
func TestNestedEscapedQuotedPairs(t *testing.T) {
	const a, b, c = "Zr5DBLESC9qWxYvTsRpOn", "Zr5LITBS5qWxYvTsRpOn", "Zr5DEEPER7qWxYvTsRpOnMk"
	in := `{"c1": "Run: curl -d \"{\\\"api_key\\\":\\\"` + a + `\\\"}\" https://api.x.com",` +
		` "e4": "token=\\\"` + b + `\\\"",` +
		` "d3": "x=\"{\\\"y\\\":\\\"{\\\\\\\"secret\\\\\\\":\\\\\\\"` + c + `\\\\\\\"}\\\"}\""}`
	var before map[string]string
	if err := json.Unmarshal([]byte(in), &before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		col := &collector{}
		out := scrubFile(t, col, "/h/.grokbot/settings.json", in)
		for _, s := range []string{a, b, c} {
			if strings.Contains(out, secretMiddle(s)) {
				t.Fatalf("%s shipped: %s", s, out)
			}
		}
		var after map[string]string
		if err := json.Unmarshal([]byte(out), &after); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, out)
		}
		for k, v := range before {
			if len(after[k]) != len(v) {
				t.Fatalf("%s length changed: %q", k, after[k])
			}
		}
	}
	if out := redactSecretValues(in); strings.Contains(out, secretMiddle(a)) || strings.Contains(out, secretMiddle(b)) {
		t.Fatalf("command output: %s", out)
	}
}
