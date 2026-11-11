package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every random choice a stand-in makes is uniform over its class, the
// original character included. Excluding it gave the value away: across
// a few hundred snapshots of a PEM key, the one character a position never
// showed was the real one.
func TestStandInDrawsIncludeTheOriginal(t *testing.T) {
	const body = "MC4CAQAwBQYDK2VwBCIEIExg9fT9GlaxgDiKuzzD4HlfSpGnfqJTeKOCxXlvArkf"
	same, total := 0, 0
	for i := 0; i < 400; i++ {
		d := randomBase64(body)
		for j := range body {
			total++
			if d[j] == body[j] {
				same++
			}
		}
	}
	// chance is 1/64 a character
	if same*64 < total/2 || same*64 > total*2 {
		t.Errorf("PEM body: %d of %d characters kept, chance is %d", same, total, total/64)
	}
	// a hex key: every hidden position shows its own character sometimes,
	// the first and last hidden ones included
	const key = "9f86d081884c7d659a2feaa0c55ad015"
	seen := make([]int, len(key))
	for i := 0; i < 600; i++ {
		d := (&collector{}).disguise(key)
		for j := range key {
			if d[j] == key[j] {
				seen[j]++
			}
		}
	}
	for j := 8; j < len(key)-4; j++ {
		if seen[j] == 0 {
			t.Errorf("position %d never shows its own character: excluded", j)
		}
	}
	// a key in two files of one snapshot is one sample
	c := &collector{}
	pem := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
	a := string(c.scrubSecrets("/h/a/key.pem", []byte(pem)))
	b := string(c.scrubSecrets("/h/b/key.pem", []byte(pem)))
	if a != b || a == pem {
		t.Errorf("one key, two stand-ins:\n%s\n%s", a, b)
	}
}

// The class of each hidden position (digit or letter, a-f or g-z) is no
// longer kept in place: a hex key's layout alone was worth a bit a
// character. Separators and the value's counts stay.
func TestStandInShufflesClassLayout(t *testing.T) {
	const key = "9f86d081884c7d659a2feaa0c55ad015"
	digit := func(b byte) bool { return b >= '0' && b <= '9' }
	moved := 0
	for i := 0; i < 200; i++ {
		d := (&collector{}).disguise(key)
		for j := 8; j < len(key)-4; j++ {
			if digit(d[j]) != digit(key[j]) {
				moved++
				break
			}
		}
		if verdictsOf(d) != verdictsOf(key) {
			t.Fatalf("%q → %q: verdicts changed", key, d)
		}
	}
	if moved < 150 {
		t.Errorf("class layout kept in %d of 200 stand-ins", 200-moved)
	}
	const uuid = "3f9a1c7e-2b8d-4f6a-9c5e-9b1d7f3a8c2e"
	for i := 0; i < 50; i++ {
		d := (&collector{}).disguise(uuid)
		if d[8] != '-' || d[13] != '-' || d[18] != '-' || d[23] != '-' || verdictsOf(d) != verdictsOf(uuid) {
			t.Fatalf("%q → %q: structure or verdicts changed", uuid, d)
		}
	}
}

// Shapes the second round found shipping: YAML anchored/tagged lists and
// items, explicit keys, a grandchild of a secrets map, TOML [secrets.x] and
// dotted quoted keys, -p<password> as an argv element, <token>:@host, a
// token that is a URL's fragment, PINs and short passwords, an
// all-lowercase API key, a quoted --password value, a value starting with
// a literal \u.
func TestScrubRoundTwoShapes(t *testing.T) {
	s := []string{
		"YbmG1ylvuhfJXqIEnomef2mSJ5CMTIeg", "Yd11XzWL8MHpoKEzViXZya8cdFOcVwWB", "YehqG5KSFdPE0SPgjtHfb1F6w70WAKad",
		"YlRHUNL9yf4StfxDPNV2adCV1jFzYI20", "YoSgnYNPPtPQvv9PBmGGwYPnqwYo8kwQ", "Zd8mG1ylvuhfJXqIEnomef2mSJ5CMTIeg",
		"Ta8mG1ylvuhfJXqIEnomef2mSJ5CMTIeg", "Te8mG1ylvuhfJXqIEnomef2mSJ5CMTIeg", "Qa1Bb2Cc3Dd4Ee5Ff6Gg", "Qc1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0",
		"Qe1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0", "qzmxkvbtplwrhgdsnfyceaujoi4k7d2m", "two words Secret99 here", "abcDEF12345678xyzQq9Ww",
	}
	files := map[string]string{
		"/h/.hermes/config.yaml": "api_keys: &keys\n  - " + s[0] + "\n  - &k3 " + s[1] + "\n  - !!str " + s[2] + "\n" +
			"mcp:\n  headers:\n    ? X-Other\n    : " + s[3] + "\n" +
			"secrets:\n  nested:\n    deeper: " + s[4] + "\n  name: Readable-Name\n" +
			"api_keys3: !!seq\n  - " + s[5] + "\nplain:   # a comment\n  - x\n",
		"/h/.zeroclaw/config.toml": "[secrets.nested]\ngithub = \"" + s[6] + "\"\n[providers.x]\napi_key.\"main\" = \"" + s[7] + "\"\nmodel = \"gpt-5\"\n",
		"/h/.claude.json": `{"mcpServers":{"db":{"command":"mysql-mcp","args":["-u","root","-p` + s[8] + `","--host","db"]},` +
			`"u":{"url":"https://` + s[9] + `:@x.example/sse"},"f":{"url":"https://x.example/sse#` + s[10] + `"},` +
			`"p":{"args":["docker","run","-p127.0.0.1:8080:80","-pthread"]}},` +
			`"apiKey":"` + s[11] + `","notes":"run with --password \"` + s[12] + `\"","x":"token: \\` + `\u0041` + s[13] + `"}`,
		"/h/.hermes/.env": "DB_PASSWORD=84736251\nPIN=4821\nPASSWORD2=correcthorse\nPASSWORD=hunter2x\nADMIN_PASSWORD=admin\nDB_PASSWORD_MODE=disabled\n",
	}
	_, out := scrubAll(t, files, s)
	expectKept(t, out, map[string][]string{
		"/h/.hermes/config.yaml":   {"api_keys: &keys\n", "? X-Other\n", "name: Readable-Name", "plain:   # a comment\n"},
		"/h/.zeroclaw/config.toml": {`model = "gpt-5"`, `api_key."main" = "`},
		"/h/.claude.json":          {`"-u","root","-p`, "-p127.0.0.1:8080:80", `"-pthread"`, ":@x.example/sse", "x.example/sse#"},
		"/h/.hermes/.env":          {"ADMIN_PASSWORD=admin\n", "DB_PASSWORD_MODE=disabled\n"},
	})
	for _, leak := range []string{"84736251", "PIN=4821", "correcthorse", "hunter2x"} {
		if strings.Contains(out["/h/.hermes/.env"], leak) {
			t.Errorf(".env ships %q:\n%s", leak, out["/h/.hermes/.env"])
		}
	}
}

// UTF-16 written without a BOM (every other byte NUL) is read as UTF-16,
// in either byte order.
func TestScrubUTF16WithoutBOM(t *testing.T) {
	const key = "Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl"
	plain := "{\"apiKey\": \"" + key + "\"}\n"
	for _, little := range []bool{true, false} {
		var b []byte
		for _, r := range plain {
			if little {
				b = append(b, byte(r), 0)
			} else {
				b = append(b, 0, byte(r))
			}
		}
		out := (&collector{}).scrubSecrets("/h/.gemini/settings.json", b)
		var text []byte
		for i := 0; i+1 < len(out); i += 2 {
			if little {
				text = append(text, out[i])
			} else {
				text = append(text, out[i+1])
			}
		}
		if len(out) != len(b) || strings.Contains(string(text), secretMiddle(key)) || !strings.Contains(string(text), `{"apiKey": "`) {
			t.Errorf("little=%v: %q", little, text)
		}
	}
}

// A flag's value never starts with "-": after a secret-named switch
// (--no-auth, --oauth, --token) the next flag's value is the secret, and no
// flag name is disguised. -k takes a key only when what follows is random.
func TestScrubFlagAfterSecretNamedSwitch(t *testing.T) {
	s := []string{"CmdStrTok3nAlphaBravo7788CharlieDelta", "CmdStrTok3nAlphaBravo7788CharlieDelta2", "CmdStrTok3nAlphaBravo7788CharlieDelta3",
		"CmdStrTok3nAlphaBravo7788CharlieDelta4", "ZuluAlpha0987654321BravoCharlie12", "Pw9Secret8Zz7Yy6Xx5"}
	files := map[string]string{
		"/h/.nanobot/config.json": `{"a":["acme","--no-auth","--api-key","` + s[0] + `"],"b":["--oauth","--client-secret","` + s[1] + `"],` +
			`"c":["--token","--api-key","` + s[2] + `"],"d":"npx acme --use-oauth-token --api-key ` + s[3] + `","e":["-k","` + s[4] + `"],` +
			`"f":["--skip-token-check","--password","` + s[5] + `"],"g":["curl","-k","https://x.example"]}`,
		"/h/.hermes/config.yaml": "args:\n  - --no-auth\n  - --api-key\n  - " + s[0] + "\n",
	}
	_, out := scrubAll(t, files, s)
	expectKept(t, out, map[string][]string{
		"/h/.nanobot/config.json": {`"--no-auth","--api-key","`, `"--oauth","--client-secret","`, `"--token","--api-key","`, "--use-oauth-token --api-key ", `"-k","https://x.example"`, `"--skip-token-check","--password","`},
		"/h/.hermes/config.yaml":  {"- --no-auth\n  - --api-key\n"},
	})
	for key, val := range map[string]string{
		"HERMES_EXTRA_ARGS": `--password "two words Secret99 here"`,
		"GITHUB_MCP_URL":    "https://x.example/mcp#Qe1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0",
	} {
		if got := redactEnvValue(key, val); strings.Contains(got, "Secret99") || strings.Contains(got, "Ee5Ff6Gg") {
			t.Errorf("%s=%q kept the secret: %q", key, val, got)
		}
	}
}

// Skill trees are known by their directory, whatever it is called
// (skills-cursor, custom_skills, open-skills…); an interpolated reference
// (${process.env.X}) in a config is kept, as the CLI reads it.
func TestSkillTreesByDirectoryAndInterpolations(t *testing.T) {
	for _, p := range []string{"~/.cursor/skills-cursor/**", "~/.openclaw/custom_skills/**", "~/.ironclaw/installed_skills/**",
		"~/open-skills/**", "${HERMES_HOME}/optional-skills/**", "~/.claude/skills/**"} {
		if !isSkillPattern(p) {
			t.Errorf("%s is a skill tree", p)
		}
	}
	for _, p := range []string{"~/.claude/settings.json", "~/.codex/**", "~/.skillsrc/x/**"} {
		if isSkillPattern(p) {
			t.Errorf("%s is no skill tree", p)
		}
	}
	// collected: a skills-cursor glob ships as it is, a config relocated
	// under a directory named skill-lab is scrubbed
	root := t.TempDir()
	skill := filepath.Join(root, ".cursor", "skills-cursor", "s3", "h1.js")
	conf := filepath.Join(root, "work", "skill-lab", "claude", "settings.json")
	for p, content := range map[string]string{skill: "const k = '" + anthropicKey + "'\n", conf: `{"env":{"ANTHROPIC_API_KEY":"` + anthropicKey + `"}}`} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snap := Collect(ProbeManifest{FilePaths: []string{conf}, GlobPatterns: []string{filepath.Join(root, ".cursor", "skills-cursor", "**")}}, false)
	if !strings.Contains(snap.Files[skill].Content, anthropicKey) {
		t.Errorf("skill file changed: %q", snap.Files[skill].Content)
	}
	if strings.Contains(snap.Files[conf].Content, secretMiddle(anthropicKey)) {
		t.Errorf("config under skill-lab shipped its key: %q", snap.Files[conf].Content)
	}
	c := &collector{}
	in := `{"headers": {"Authorization": "Bearer ${process.env.OPENAI_API_KEY}"}, "env": {"API_KEY": "${Zx8f3kqLm29PqSecret}"}}`
	out := string(c.scrubSecrets("/h/.cursor/mcp.json", []byte(in)))
	if !strings.Contains(out, "${process.env.OPENAI_API_KEY}") || strings.Contains(out, "Zx8f3kqLm29PqSecret") {
		t.Errorf("interpolation: %s", out)
	}
}

// A skill-tree PE too large to ship carries its header: the head runs to
// e_lfanew, so IOC-007 judges it remotely as it does locally.
func TestOmittedSkillPEShipsItsHeader(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "helper.exe")
	content := make([]byte, 0x2000+64)
	content[0], content[1] = 'M', 'Z'
	content[0x3c], content[0x3d] = 0x00, 0x20 // e_lfanew = 0x2000
	copy(content[0x2000:], "PE\x00\x00")
	if err := os.WriteFile(bin, content, 0o755); err != nil {
		t.Fatal(err)
	}
	c := &collector{budget: 1 << 20, inSkillTree: true}
	e := c.collectFileLimit(bin, bin, false, 1024)
	head, _ := base64.StdEncoding.DecodeString(e.Head)
	if len(head) != 0x2004 || string(head[0x2000:]) != "PE\x00\x00" {
		t.Fatalf("head of %d bytes, no PE header", len(head))
	}
}

// The head is charged to the content budget and stops when it is spent; it
// runs past 4 KiB only to a PE header that is there.
func TestSkillHeadsWithinBudgetAndOnlyToARealPEHeader(t *testing.T) {
	root := t.TempDir()
	mz := func(name string, sig bool) string {
		content := make([]byte, 0x80000+64)
		content[0], content[1] = 'M', 'Z'
		content[0x3c], content[0x3e] = 0x00, 0x08 // e_lfanew = 0x80000
		if sig {
			copy(content[0x80000:], "PE\x00\x00")
		}
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, content, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	headLen := func(e FileEntry) int {
		b, _ := base64.StdEncoding.DecodeString(e.Head)
		return len(b)
	}
	c := &collector{budget: 1 << 22, inSkillTree: true}
	if n := headLen(c.collectFileLimit(mz("script.js", false), "", false, 1024)); n != headBytes {
		t.Errorf("MZ without a PE header: head of %d bytes", n)
	}
	if n := headLen(c.collectFileLimit(mz("real.dll", true), "", false, 1024)); n != 0x80004 {
		t.Errorf("PE: head of %d bytes", n)
	}
	before := c.budget
	c.collectFileLimit(mz("again.dll", true), "", false, 1024)
	if c.budget >= before {
		t.Error("head not charged to the budget")
	}
	c.budget = 100
	if e := c.collectFileLimit(mz("late.dll", true), "", false, 1024); e.Head != "" {
		t.Errorf("head shipped with the budget spent (%d bytes)", headLen(e))
	}
}

// UTF-16 without a BOM holding non-ASCII text (a Cyrillic comment), or with
// an odd trailing byte, is still read as UTF-16.
func TestScrubUTF16NonASCIIAndOddLength(t *testing.T) {
	const key = "Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl"
	plain := "# Настройки сервера, ключи доступа\nOPENROUTER_API_KEY=" + key + "\n"
	var b []byte
	for _, r := range plain {
		b = append(b, byte(r), byte(r>>8))
	}
	for _, in := range [][]byte{b, append(append([]byte(nil), b...), 0x0a)} {
		out := (&collector{}).scrubSecrets("/h/.hermes/.env", in)
		var text []byte
		for i := 0; i+1 < len(out); i += 2 {
			text = append(text, out[i])
		}
		if len(out) != len(in) || strings.Contains(string(text), secretMiddle(key)) || out[len(out)-1] != in[len(in)-1] {
			t.Errorf("UTF-16 (%d bytes) shipped its key: %q", len(in), text)
		}
	}
}

// Half a disguised token pasted elsewhere in the same file is disguised too:
// with the stand-in's characters, so it still reads as part of the same key.
func TestScrubCopiesOfADisguisedValue(t *testing.T) {
	tok := "Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5RiQ7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri+/Zq8wX3mK9pL2vB7nR4tY6uI1oP5aS0dF"
	md := "# Notes\nTOKEN=\"" + tok + "\"\nThe first half: `" + tok[:60] + "`\n"
	c := &collector{}
	out := string(c.scrubSecrets("/h/.config/devin/AGENTS.md", []byte(md)))
	if strings.Contains(out, tok[8:40]) || strings.Contains(out, tok[20:60]) {
		t.Errorf("a copy shipped:\n%s", out)
	}
	d := c.disguised[tok]
	if !strings.Contains(out, "`"+d[:60]+"`") {
		t.Errorf("the copy is not the stand-in's own characters:\n%s", out)
	}
}
