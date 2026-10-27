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
