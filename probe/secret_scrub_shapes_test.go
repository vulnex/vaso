package main

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// scrubAll scrubs each file with one collector and fails when a secret's
// hidden part ships, the length changes or a disguise changes a verdict.
func scrubAll(t *testing.T, files map[string]string, secrets []string) (*collector, map[string]string) {
	t.Helper()
	c := &collector{}
	out := map[string]string{}
	for name, content := range files {
		got := string(c.scrubSecrets(name, []byte(content)))
		if len(got) != len(content) {
			t.Fatalf("%s: length changed %d → %d", name, len(content), len(got))
		}
		out[name] = got
		for _, s := range secrets {
			if strings.Contains(got, secretMiddle(s)) {
				t.Errorf("%s ships %q:\n%s", name, s, got)
			}
		}
	}
	for v, d := range c.disguised {
		if verdictsOf(d) != verdictsOf(v) {
			t.Errorf("%q → %q: verdicts %+v → %+v", v, d, verdictsOf(v), verdictsOf(d))
		}
	}
	return c, out
}

func expectKept(t *testing.T, out map[string]string, keep map[string][]string) {
	t.Helper()
	for name, ks := range keep {
		for _, k := range ks {
			if !strings.Contains(out[name], k) {
				t.Errorf("%s lost %q:\n%s", name, k, out[name])
			}
		}
	}
}

// One byte that isn't UTF-8 (a Latin-1 comment saved by a Windows editor,
// "José" in ~/.claude.json) or a UTF-16 file used to ship the file whole.
// The scrub runs on a copy of the same length; every other byte goes back
// as it was.
func TestScrubNonUTF8Files(t *testing.T) {
	const (
		k1 = "sk-ant-api03-Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxEa5Ri"
		k2 = "Xq7Lk2Pz9Rt4Vw8YbN3mHc6J"
		k3 = "Zr8Ty3Uw6Qa1Sx4Dc7Fv9Gb2Hn5Jm0Kl"
	)
	latin := "{\"userName\": \"Jos\xe9\", \"primaryApiKey\": \"" + k1 + "\",\n \"env\": {\"GITHUB_TOKEN\": \"" + k2 + "\"}}\n"
	env := "# Configuraci\xf3n\nOPENROUTER_API_KEY=" + k3 + "\n"
	utf16 := func(s string, little bool) string {
		b := []byte{0xFF, 0xFE}
		if !little {
			b = []byte{0xFE, 0xFF}
		}
		for _, r := range s {
			if little {
				b = append(b, byte(r), byte(r>>8))
			} else {
				b = append(b, byte(r>>8), byte(r))
			}
		}
		return string(b)
	}
	plain := "API_KEY=" + k3 + "\n# caf\u00e9\n"
	files := map[string]string{
		"/h/.claude.json":     latin,
		"/h/.hermes/.env":     env,
		"/h/a/.env":           utf16(plain, true),
		"/h/b/.env":           utf16(plain, false),
		"/h/.cursor/mcp.json": "{\"x\": \"\xff\xfe broken\", \"api_key\": \"" + k2 + "\"}",
	}
	_, out := scrubAll(t, files, nil)
	for name, got := range out {
		in := files[name]
		for _, k := range []string{k1, k2, k3} {
			if strings.Contains(got, secretMiddle(k)) || strings.Contains(got, utf16(secretMiddle(k), true)[2:]) || strings.Contains(got, utf16(secretMiddle(k), false)[2:]) {
				t.Errorf("%s ships %q", name, k)
			}
		}
		// only ASCII letters and digits changed
		for i := 0; i < len(in); i++ {
			if got[i] != in[i] && !(isASCIIAlnum(in[i]) && isASCIIAlnum(got[i])) {
				t.Fatalf("%s: byte %d changed %q → %q", name, i, in[i], got[i])
			}
		}
	}
	if !strings.Contains(out["/h/.claude.json"], "Jos\xe9") || !strings.Contains(out["/h/.hermes/.env"], "Configuraci\xf3n") {
		t.Errorf("non-UTF-8 text changed: %q", out["/h/.claude.json"])
	}
}

// CRLF line endings and a BOM disabled the line rules, so short passwords
// with symbols and no digit shipped.
func TestScrubCRLFAndBOM(t *testing.T) {
	files := map[string]string{
		"/h/.hermes/.env":        "\uFEFFDB_PASSWORD=Xk#mPq!wRz\r\nexport OTHER_TOKEN=Pq!wRz#Xkm\r\nMODE=fast\r\n",
		"/h/.hermes/config.yaml": "\uFEFFpassword: Bq!zT#kWm\r\napi:\r\n  token: Tk!zQ#wWm\r\nmodel: gpt\r\n? api_key\r\n: Ex!pL#cTv\r\n",
		"/h/.atomic/.env":        "\uFEFFATOMIC_WEBHOOK_SECRET=Xq#wE!rTy\r\n",
	}
	_, out := scrubAll(t, files, []string{"Xk#mPq!wRz", "Pq!wRz#Xkm", "Bq!zT#kWm", "Tk!zQ#wWm", "Ex!pL#cTv", "Xq#wE!rTy"})
	expectKept(t, out, map[string][]string{
		"/h/.hermes/.env":        {"\uFEFFDB_PASSWORD=", "\r\nMODE=fast\r\n"},
		"/h/.hermes/config.yaml": {"\r\nmodel: gpt\r\n"},
	})
}

// Credentials as list items, map children and parent tables: PicoClaw's
// .security.yml block lists, JSON and TOML arrays, ZeroClaw's
// [http_request.secrets] table and api_keys arrays, inline tables, Hermes
// argv block sequences, a YAML value on the line after its key.
func TestScrubSecretLists(t *testing.T) {
	s := []string{
		"Mq3Zx8Lp2Vn7Rk4Tw9Yb6Hd1Fs5Gj0Ab", "b8e4d0f2c6a35791bb8e4d0f2c6a3579", "e1b2c3d4f5a6b7c8.Zx8Lp2Vn7Rk4Tw9Y",
		"BSAq7Wz2Lk9Xv4Rt8Ns3Jm6Hb1", "Hm4rgBl0ck9Secret77Value", "N3xtL1ne7SecretValue99Zz",
		"Gh5SecretMapValue88Yyx1", "J5onArr1Key9Zz8Yy7Xx6Ww", "J5onArr2Key9Zz8Yy7Xx6Ww",
		"Rel1ab1eKey9Zz8Yy7Xx6Ww", "HttpSecret9Github8Zz7Ww", "InlinePrimary9Tok8Zz7Ww",
		"FlowMap9Primary8Zz7Yy6W", "J5onMap9Github8Zz7Yy6Ww", "SeqSameIndent9Key8Zz7Yy",
		"nzPYqSgPGpDd!EFloHOCtYSkSjj#qYOOpRgpWn", "03nbqnsGpWLuqIA1id6Vw5DQL05HA0", "Yq8wX3mK9pL2vB7nR4tY6uI1",
	}
	files := map[string]string{
		"/h/.picoclaw/.security.yml": "model_list:\n  mistral:\n    api_keys:\n      - " + s[0] + "\n      - \"" + s[1] + "\"\n  zhipu:\n    api_keys:\n    - " + s[2] + "  # key\n" +
			"tools:\n  brave:\n    api_keys: [x]\n    keys:\n      - " + s[3] + "\n",
		"/h/.hermes/config.yaml": "mcp_servers:\n  svc:\n    args:\n      - -y\n      - svc-mcp@1.2.3\n      - --verbose\n      - --api-key\n      - " + s[4] + "\n      - --port\n      - \"8080\"\n" +
			"auxiliary:\n  web_extract:\n    api_key:\n      " + s[5] + "\n    model: x\n" +
			"secrets:\n  github: " + s[6] + "\n  name: Readable-Name\n" +
			"tokens: {primary: " + s[12] + ", note: x}\n" +
			"svc: {command: npx, env: {SVC_API_TOKEN: " + s[15] + "}}\n" +
			"api_keys:\n- " + s[14] + "\n" +
			"max_tokens:\n  - 4096\ndescription:\n  This line names the API token\n" +
			"remote:\n  headers:\n    X-Custom: " + s[17] + "\n    Accept: application/json\n",
		"/h/.picoclaw/config.json": "{\n  \"api_keys\": [\n    \"" + s[7] + "\",\n    \"" + s[8] + "\"\n  ],\n  \"secrets\": {\"github\": \"" + s[13] + "\", \"enabled\": true},\n" +
			"  \"headers\": {\"Content-Type\": \"application/json\", \"X-Custom\": \"03nbqnsGpWLuqIA1id6Vw5DQL05HA0\"},\n  \"stop\": [\"Human:\", \"Assistant:\"]\n}\n",
		"/h/.zeroclaw/config.toml": "[reliability]\napi_keys = [\"" + s[9] + "\"]\n[http_request.secrets]\ngithub = \"" + s[10] + "\"\n" +
			"[x]\ntokens = { primary = \"" + s[11] + "\" }\n[gateway.auth]\nmode = \"Pairing-Code\"\n",
	}
	_, out := scrubAll(t, files, s)
	expectKept(t, out, map[string][]string{
		"/h/.hermes/config.yaml":   {"- --verbose\n", "- --api-key\n", "- --port\n      - \"8080\"", "name: Readable-Name", "max_tokens:\n  - 4096", "This line names the API token", "Accept: application/json"},
		"/h/.picoclaw/config.json": {`"enabled": true`, `"Content-Type": "application/json"`, `["Human:", "Assistant:"]`},
		"/h/.zeroclaw/config.toml": {`mode = "Pairing-Code"`},
	})
	var parsed interface{}
	if err := json.Unmarshal([]byte(out["/h/.picoclaw/config.json"]), &parsed); err != nil {
		t.Errorf("JSON no longer parses: %v", err)
	}
}

// "--verbose", "--token", "<value>": a boolean flag right before the
// credential flag consumed it, and the value shipped.
func TestScrubArgvSecretAfterBooleanFlag(t *testing.T) {
	const v1, v2, v3 = "OpaqueCutTok3nAlphaBravo7788CharlieDeltaEchoFox", "ZuluAlpha0987654321BravoCharlie12", "Hunter2HotelIndiaJuliet5566Kilo"
	files := map[string]string{
		"/h/.nanobot/config.json": `{"a": {"args": ["-y","acme-mcp","--verbose","--token","` + v1 + `"]}, "b": {"args": ["acme","-v","--api-key","` + v2 + `"]}}`,
		"/h/.openclaw/x.json5":    `{b: {args: ['acme', '--stdio', '--password', '` + v3 + `']}}`,
	}
	_, out := scrubAll(t, files, []string{v1, v2, v3})
	expectKept(t, out, map[string][]string{"/h/.nanobot/config.json": {`"--verbose","--token","`, `"-v","--api-key","`}})
}

// Command lines inside configs: a header flag with its value after "=", a
// password in a URL with an empty user name, a token as the URL user name,
// mysql -p<password>, sshpass -p <password>, --pwd.
func TestScrubCommandLineCredentialShapes(t *testing.T) {
	s := []string{"HdrTok9Secret8Zz7Yy6Xx", "RedisPw9Secret8Zz7Yy", "MongoPw9Secret8Zz7Yy", "MyPw9Secret8Zz7",
		"SshPw9Secret8Zz7", "SentryTok9Secret8Zz7Yy6Xx", "PwdFlag9Secret8Zz7", "XApiKey9Secret8Zz7Yy",
		// no digit, entropy under 4.5: a header value still, by its name
		"nzPYqSgPGpDd!EFloHOCtYSkSjj#qYOOpRgpWn", "qYOOpRgpWn!nzPYqSgPGpDd#EFloHOCtYSkSjj"}
	files := map[string]string{
		"/h/Library/Application Support/Claude/claude_desktop_config.json": `{"mcpServers": {"a": {"command": "npx", "args": ["supergateway", "--header=Authorization: Bearer ` + s[0] + `", "--header=X-Api-Key:` + s[7] + `", "redis://:` + s[1] + `@cache:6379"],` +
			` "env": {"MDB_MCP_CONNECTION_STRING": "mongodb+srv://:` + s[2] + `@c.example.net/db"}},` +
			` "b": {"command": "sh", "args": ["-c", "mysql -uroot -p` + s[3] + ` app && sshpass -p ` + s[4] + ` ssh host"]},` +
			` "c": {"url": "https://` + s[5] + `@o1.ingest.sentry.io/1"}, "d": {"args": ["--pwd", "` + s[6] + `"]},` +
			` "e": {"args": ["mysql", "-p", "appdb", "-h", "db"]}, "f": {"command": "docker run -p127.0.0.1:8080:80 img"},` +
			` "g": {"args": ["--header=Authorization: Bearer ` + s[8] + `", "--header", "Authorization: Bearer ` + s[9] + `", "--header", "Cookie: session=Ck9Secret8Zz7Yy6Ww"]}}}`,
	}
	_, out := scrubAll(t, files, s)
	name := "/h/Library/Application Support/Claude/claude_desktop_config.json"
	expectKept(t, out, map[string][]string{name: {"--header=Authorization: Bearer ", "--header=X-Api-Key:", "redis://:", "@cache:6379", "-p127.0.0.1:8080:80", "@o1.ingest.sentry.io/1", `"Cookie: session=`}})
}

// Variables and command output (redacted, not disguised): argv inside a
// value, a credential in a JSON argv array, a variable named …_PW.
func TestRedactEnvArgvAndShortNames(t *testing.T) {
	const v = "EnvArg9Secret8Zz7Yy"
	for key, val := range map[string]string{
		"HERMES_EXTRA_ARGS":       "--model x --api-key " + v,
		"GITHUB_MCP_ARGS":         "--gh-pat=" + v,
		"OPENCODE_CONFIG_CONTENT": `{"mcp":{"x":{"command":["npx","x-mcp","--verbose","--api-key","` + v + `"]}}}`,
		"CLAUDE_PW":               v,
		"DB_PWD":                  v,
	} {
		if got := redactEnvValue(key, val); strings.Contains(got, v[4:]) {
			t.Errorf("%s=%q kept the secret: %q", key, val, got)
		}
	}
	if got := redactEnvValue("OPENCODE_CONFIG_CONTENT", `{"command":["npx","--verbose","x"]}`); !strings.Contains(got, `"--verbose","x"`) {
		t.Errorf("argv without a credential changed: %s", got)
	}
	if isSecretEnvName("PWD") || !isSecretEnvName("DB_PWD") {
		t.Error("PWD is the working directory, DB_PWD a password")
	}
	out := redactSecretValues("pw: CmdOut9Secret8Zz7\nrun: mysql -uroot -pCmd9Secret8Zz db\n--token Cmd7Token9Secret8\n")
	for _, leak := range []string{"CmdOut9Secret8Zz7", "Cmd9Secret8Zz", "Cmd7Token9Secret8"} {
		if strings.Contains(out, leak) {
			t.Errorf("command output kept %q: %s", leak, out)
		}
	}
}

// A value under a credential name the CLI reads as a reference stays only
// when it is one: "//registry/:_authToken=…" is searched inside, a base64
// secret that starts with "/" is no path (isPathValue, on both sides),
// "\u0041…" is no Windows path.
func TestScrubValuesThatOnlyLookLikeReferences(t *testing.T) {
	s := []string{"Bb2Xv3Npm9Secret8Zz7Yy6", "/q7Wz2Lk9Xv4Rt8Ns3Jm6Hb1Pq", "\\u0041bcSecret9Zz8Yy7Xx6Ww"}
	files := map[string]string{
		"/h/.claude/settings.json": `{"env": {"NPM_CONFIG__AUTH": "//registry.npmjs.org/:_authToken=` + s[0] + `", "DB_PASSWORD": "` + s[1] + `", "API_KEY": "` + s[2] + `",` +
			` "KEY_FILE_TOKEN": "/Users/me/.config/app/token.json", "CERT_KEY": "~/certs/client.key"}}`,
	}
	c, out := scrubAll(t, files, s)
	expectKept(t, out, map[string][]string{"/h/.claude/settings.json": {"//registry.npmjs.org/:_authToken=", "/Users/me/.config/app/token.json", "~/certs/client.key", `"\u0041bc`}})
	// not a file reference here or in the CLI (isPathValue), nor its stand-in
	if d := c.disguised[s[1]]; !strings.HasPrefix(d, "/") || isSecretReference(s[1]) || isSecretReference(d) {
		t.Errorf("%q → %q: judged a file reference", s[1], d)
	}
	for _, path := range []string{"/Users/me/.config/app/token.json", "~/certs/client.key", "/Users/me/.keys/Xq7Lk2Pz9Rt4Vw8Y.pem", "./secrets/prod.env"} {
		if !isSecretReference(path) {
			t.Errorf("%q is a file reference", path)
		}
	}
}

// Memory and instruction files: a value whose line goes on with a URL, a
// placeholder word or "..." is still disguised (the CLI judges the first
// word); pwd, names of several words, 12–15 character table and bold
// values, values starting with "@"; escapes inside a value.
func TestScrubProseValuesWithATail(t *testing.T) {
	s := []string{"Pr0seKey9Secret8Zz7Yy", "Pr0seBearer9Secret8Zz7", "Pr0seTok9Secret8Zz7Yy6", "Pr0sePw9Secret8Zz7",
		"Pr0seDots9Secret8Zz7", "Pr0sePwd9Secret8Zz", "Pr0seMulti9Secret8Zz", "c47b1ba961ae6", "NYA82UO22PAW",
		"@Pr0seAt9Secret8Zz7", "Pr0seXApi9Secret8Zz7", "Pr0sePsql9Secret8Zz7"}
	md := "# Notes\n" +
		"API_KEY=" + s[0] + " for https://x.example.com\n" +
		"curl -H 'Authorization: Bearer " + s[1] + "' https://api.x.example.com\n" +
		"token: " + s[2] + " (see the example in the wiki)\n" +
		"password: " + s[3] + ", replace monthly\n" +
		"API_KEY=" + s[4] + " and so on...\n" +
		"DB_PWD=" + s[5] + "\n" +
		"Token del servidor: " + s[6] + "\n" +
		"**password**: " + s[7] + "\n" +
		"| DB_PASSWORD | " + s[8] + " |\n" +
		"token: " + s[9] + "\n" +
		"curl -H 'X-Api-Key: " + s[10] + "' https://api.x.example.com\n" +
		"DB_PASSWORD=" + s[11] + " psql postgres://db.example.com/app\n" +
		"Token: Required. The password: see the team vault.\n"
	_, out := scrubAll(t, map[string]string{"/h/.claude/CLAUDE.md": md}, s)
	expectKept(t, out, map[string][]string{"/h/.claude/CLAUDE.md": {" for https://x.example.com\n", "(see the example in the wiki)", ", replace monthly", " and so on...", "Token: Required. The password: see the team vault.", "psql postgres://db.example.com/app"}})

	// escapes inside a value in a JSON string: \/, \u00e9, an escaped quote
	const e1, e2, e3 = `Xk9Lm2Pq\/Rt7Vb1Nc6Hj3Wd5Fs0GaQw`, `Ab9Cd8Ef\u00e9Gh7Ij6Kl5Mn4Op3`, `Ab12\\\"Cd34Ef56Gh78`
	settings := `{"x": "export API_KEY=` + e1 + ` now", "y": "token=` + e2 + ` end", "z": "password=\"` + e3 + `\" end"}`
	_, out = scrubAll(t, map[string]string{"/h/.grokbot/settings.json": settings}, nil)
	got := out["/h/.grokbot/settings.json"]
	for _, leak := range []string{`Rt7Vb1Nc6Hj3Wd5Fs0`, `Gh7Ij6Kl5Mn4`, `Cd34Ef56Gh78`} {
		if strings.Contains(got, leak) {
			t.Errorf("escaped value shipped %q: %s", leak, got)
		}
	}
	var parsed interface{}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Errorf("JSON no longer parses: %v\n%s", err, got)
	}
}

// Token formats no check names still never ship; a YAML ” escape doesn't
// end a value early.
func TestScrubMoreTokenShapes(t *testing.T) {
	s := []string{"sk_live_q7Wz2Lk9Xv4Rt8Ns3Jm6Hb1Pq", "SG.q7Wz2Lk9Xv4Rt8Ns3Jm6H.b1Pq7Wz2Lk9Xv4Rt8Ns3Jm6Hb1Pq",
		"dop_v1_" + strings.Repeat("a7f3c9e1b5d24680", 4), "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",
		"lin_api_q7Wz2Lk9Xv4Rt8Ns3Jm6Hb1Pq7Wz2Lk9Xv4R", "ntn_q7Wz2Lk9Xv4Rt8Ns3Jm6Hb1Pq7Wz2Lk9Xv4Rt8",
		"pplx-q7Wz2Lk9Xv4Rt8Ns3Jm6Hb1Pq7Wz2Lk9Xv4Rt8", "Rest9SecretZzzQq77",
		"npm_KKhVz4NiaBfuRMFFw8Px6diSsjKORGs68JJN", "figd_1ACtOd4c8mlSGOzmIof7uYgfI6kMe2UnNbCIwFBK", "dckr_pat_akLN0kUgrHMkOTjCW8BYBhvuC6o",
		"ya29.wZp0Q162dNFzwjj1pFycgkzgWTs56mYZWuERE3INfZmySagGMLNl0ybuRbNt"}
	files := map[string]string{
		"/h/.config/app/settings.json": `{"a": "` + s[0] + `", "b": "` + s[1] + `", "c": "` + s[2] + `", "d": "` + s[3] + `", "e": "` + s[4] + `", "f": "` + s[5] + `", "g": "` + s[6] + `",` +
			` "h": "` + s[8] + `", "i": "` + s[9] + `", "j": "` + s[10] + `", "k": "` + s[11] + `"}`,
		"/h/.hermes/config.yaml": "password: 'abc''" + s[7] + "'\n",
	}
	scrubAll(t, files, append(append([]string(nil), s[:7]...), s[8:]...))
	_, out := scrubAll(t, map[string]string{"/h/.hermes/config.yaml": files["/h/.hermes/config.yaml"]}, nil)
	if strings.Contains(out["/h/.hermes/config.yaml"], "SecretZzzQq") {
		t.Errorf("YAML '' escape ended the value: %s", out["/h/.hermes/config.yaml"])
	}
}

// Whether a file is scrubbed: off only for skills globs (inSkillTree) and
// installed packages, judged below the user's home — a home under some
// ".../skills/" or ".../node_modules/" turned scrubbing off for all, and no
// directory name decides it otherwise (~/work/skill-lab/ is scrubbed).
func TestScrubbableJudgedBelowHome(t *testing.T) {
	c := &collector{homes: []string{"/srv/skills/h", "/opt/node_modules/u"}}
	for path, want := range map[string]bool{
		"/srv/skills/h/.claude/settings.json":                  true,
		"/opt/node_modules/u/.hermes/.env":                     true,
		"/srv/skills/h/work/skill-lab/claude/settings.json":    true,
		"/opt/node_modules/u/.npm-global/lib/node_modules/x/a": false,
		"/usr/local/lib/node_modules/x/package.json":           false,
	} {
		if got := c.scrubbable(path); got != want {
			t.Errorf("scrubbable(%q) = %v, want %v", path, got, want)
		}
	}
	for _, ext := range []string{".icns", ".tiff", ".tif", ".heic", ".avif", ".bz2", ".xz", ".zst", ".lz4", ".dmg", ".iso"} {
		if !metadataOnlyExtensions[ext] {
			t.Errorf("%s content is collected", ext)
		}
	}
}

// The reference rules are TS's (src/core/patterns.ts) verbatim: a looser
// copy kept stored passwords ("$Zx8f…", "${DB_PASSWORD:-<secret>}") as
// references, a narrower one disguised SOPS and Key Vault references.
func TestReferencePatternsMatchTS(t *testing.T) {
	var forms []string
	for _, m := range tsList(t, "src/core/patterns.ts", "const ENV_REFERENCE_FORMS: Array<[EnvReferenceForm, RegExp]>", regexp.MustCompile(`\['([a-z-]+)', /(.*)/([a-z]*)\]`)) {
		p := m[2]
		if m[3] == "i" {
			p = "(?i)" + p
		}
		forms = append(forms, m[1]+" "+p)
	}
	var probe []string
	for i, p := range envReferenceForms {
		probe = append(probe, envReferenceFormNames[i]+" "+p)
	}
	if strings.Join(forms, "\n") != strings.Join(probe, "\n") {
		t.Errorf("env reference forms differ:\nTS:    %q\nprobe: %q", forms, probe)
	}
	src := readTS(t, "src/core/patterns.ts")
	block := src[strings.Index(src, "const SECRET_MANAGER_REFERENCE = new RegExp(["):]
	block = block[:strings.Index(block, "].join('|'), 'i');")]
	var parts []string
	for _, m := range regexp.MustCompile("String\\.raw`([^`]*)`").FindAllStringSubmatch(block, -1) {
		parts = append(parts, m[1])
	}
	if strings.Join(parts, "\n") != strings.Join(managerReferenceParts, "\n") {
		t.Errorf("secret manager references differ:\nTS:    %q\nprobe: %q", parts, managerReferenceParts)
	}
	for name, probeSrc := range map[string]string{"VARIABLE_NAME": variableName.String(), "FILE_REFERENCE": "(?i)" + fileReferenceSrc, "PATH_PREFIX": pathPrefix.String(), "WORD_SEGMENT": wordSegment.String()} {
		m := regexp.MustCompile(`const ` + name + ` = /(.*)/([a-z]*);`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s not found", name)
		}
		ts := m[1]
		if m[2] == "i" {
			ts = "(?i)" + ts
		}
		if ts != probeSrc {
			t.Errorf("%s differs:\nTS:    %s\nprobe: %s", name, ts, probeSrc)
		}
	}
}

func readTS(t *testing.T, file string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", file))
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

// HASHED_VALUE and PUBLIC_VALUE are TS's verbatim.
func TestValueShapesMatchTS(t *testing.T) {
	src := readTS(t, "src/analyzers/secret-values.ts")
	m := regexp.MustCompile(`const HASHED_VALUE = /(.*)/i;`).FindStringSubmatch(src)
	if m == nil || m[1] != hashedValueSrc {
		t.Errorf("HASHED_VALUE differs:\nTS:    %v\nprobe: %s", m, hashedValueSrc)
	}
	block := src[strings.Index(src, "const PUBLIC_VALUE = new RegExp(["):]
	block = block[:strings.Index(block, "].join('|'));")]
	var parts []string
	for _, p := range regexp.MustCompile("String\\.raw`([^`]*)`").FindAllStringSubmatch(block, -1) {
		parts = append(parts, p[1])
	}
	if strings.Join(parts, "\n") != strings.Join(publicValueParts, "\n") {
		t.Errorf("PUBLIC_VALUE differs:\nTS:    %q\nprobe: %q", parts, publicValueParts)
	}
}

// Stand-ins found by a fuzz round that the CLI judged unlike the value:
// one whose entropy is exactly log2(20) - 0.7, where the order of the sum
// decides (judged now on the CLI's own sum, drawn again until it agrees,
// nothing kept beyond the head), and one that came out as "Y$…", a
// yescrypt hash to the CLI.
func TestDisguiseKeepsThresholdVerdictAndHashShape(t *testing.T) {
	const atThreshold = "srPypQ_zNfywQyy2oPIw"
	want := looksRandom(atThreshold, 12)
	for i := 0; i < 50; i++ {
		d := (&collector{}).disguiseKeyed("passphrase", atThreshold)
		if d == atThreshold || looksRandom(d, 12) != want || verdictsOf(d) != verdictsOf(atThreshold) {
			t.Fatalf("%q → %q: looksRandom %v → %v", atThreshold, d, want, looksRandom(d, 12))
		}
		if d := (&collector{}).disguise("O$Zs0Z1X@F%5rt"); hashedValue.MatchString(d) {
			t.Fatalf("stand-in %q reads as a password hash", d)
		}
	}
	// the CLI's sum: 3.621928094887362 for the value, …624 for a stand-in
	// with the same counts in another order (TS looksRandom false / true)
	if shannonEntropy(atThreshold) != 3.621928094887362 || shannonEntropy("srPymL_mLfimPmu3ySVz") != 3.6219280948873624 {
		t.Errorf("entropy differs from the CLI's: %v %v", shannonEntropy(atThreshold), shannonEntropy("srPymL_mLfimPmu3ySVz"))
	}
}

// log2JS is V8's Math.log2 bit for bit on every p = c/n the entropy sums
// (n ≤ 512), and so is the product the sum takes.
func TestLog2MatchesV8(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "-e", `const b=Buffer.alloc(8),o=[];for(let n=1;n<=512;n++)for(let c=1;c<=n;c++){const p=c/n;b.writeDoubleLE(p*Math.log2(p));o.push(b.readBigUInt64LE().toString(16))}process.stdout.write(o.join("\n"))`).Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(out), "\n")
	k, bad := 0, 0
	for n := 1; n <= 512; n++ {
		for c := 1; c <= n; c++ {
			p := float64(c) / float64(n)
			if strconv.FormatUint(math.Float64bits(float64(p*log2JS(p))), 16) != lines[k] {
				bad++
			}
			k++
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d products differ from V8", bad, k)
	}
}
