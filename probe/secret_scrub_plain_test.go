package main

import (
	"strings"
	"testing"
)

// Values in a credential position are the credential however plain: a
// lowercase word after --password or --token, a URL's userinfo password,
// a short value under a key or token name. References, placeholders and
// setting words stay.
func TestScrubPlainCredentialPositions(t *testing.T) {
	claude := `{"mcpServers": {"db": {"command": "npx", "args": [` +
		`"--password", "correcthorse", "--db", "postgres://admin:batterystaple@db.internal/x", ` +
		`"--api-key=lowercasekeyvalue", "--token", "tokenvaluelower", "--token=argtoklow", ` +
		`"--auth", "authflaglow", "--secret", "secretflaglow", "https://u:urlpwlow@x.example/y", ` +
		`"--password", "${DB_PW}", "--token", "$TOKEN", "--api-key", "<your-key>", "--auth", "none", ` +
		`"--token-file", "/home/u/.config/tok", "--api-key-env", "OPENAI_API_KEY"], ` +
		`"env": {"DATABASE_URL": "mysql://root:monkeymonkey@localhost/db", "PRIVATE_KEY": "privlow", "AUTH": "authlow", ` +
		`"ACCESS_KEY": "accesslow", "SESSION": "sesslow", "PAT": "patlow", "TELEGRAM_BOT_TOKEN": "tglow", "API_KEY": "abcde", ` +
		`"X_TOKEN": "none", "Y_TOKEN": "true", "Z_PASSWORD": "changeme", "PATH": "/usr/bin", "AUTHOR": "bobsmith", ` +
		`"SESSION_TIMEOUT": "30m", "AUTH_MODE": "oauth", "PAT_COUNT": "12", "auth": "oauth-personal"}}}}`
	env := "DB_URL=postgres://admin:batterystaple@db/x\nPRIVATE_KEY=privlow\nGITHUB_PAT=patlow\nAPI_KEY=abcde\nAUTH=off\n"
	hook := "#!/bin/sh\nexec server --password correcthorse --api-key=lowercasekeyvalue -u bob:hunterpw\n"
	secrets := []string{
		"correcthorse", "batterystaple", "lowercasekeyvalue", "tokenvaluelower", "argtoklow", "authflaglow",
		"secretflaglow", "urlpwlow", "monkeymonkey", "privlow", "authlow", "accesslow", "sesslow", "patlow",
		"tglow", "abcde", "hunterpw",
	}
	files := map[string]string{"/h/.claude.json": claude, "/h/.hermes/.env": env, "/h/.claude/hooks/start.sh.md": hook}
	c := &collector{}
	for name, content := range files {
		out := string(c.scrubSecrets(name, []byte(content)))
		if len(out) != len(content) {
			t.Fatalf("%s: length changed", name)
		}
		for _, s := range secrets {
			if strings.Contains(content, s) && strings.Contains(out, s) {
				t.Errorf("%s ships %q:\n%s", name, s, out)
			}
		}
		files[name] = out
	}
	for _, keep := range []string{
		`"${DB_PW}"`, `"$TOKEN"`, `"<your-key>"`, `"--auth", "none"`, `"/home/u/.config/tok"`, `"OPENAI_API_KEY"`,
		`"X_TOKEN": "none"`, `"Y_TOKEN": "true"`, `"Z_PASSWORD": "changeme"`, `"PATH": "/usr/bin"`, `"AUTHOR": "bobsmith"`,
		`"SESSION_TIMEOUT": "30m"`, `"AUTH_MODE": "oauth"`, `"PAT_COUNT": "12"`, `"auth": "oauth-personal"`, "postgres://admin:", "@db.internal/x",
	} {
		if !strings.Contains(files["/h/.claude.json"], keep) {
			t.Errorf("lost %q:\n%s", keep, files["/h/.claude.json"])
		}
	}
	if !strings.Contains(files["/h/.hermes/.env"], "AUTH=off") {
		t.Errorf("lost AUTH=off:\n%s", files["/h/.hermes/.env"])
	}
	for v, d := range c.disguised {
		if verdictsOf(d) != verdictsOf(v) {
			t.Errorf("%q → %q: verdicts %+v → %+v", v, d, verdictsOf(v), verdictsOf(d))
		}
	}
}

func TestStrongCredentialNames(t *testing.T) {
	strong := []string{"PRIVATE_KEY", "privateKey", "AUTH", "basic_auth", "ACCESS_KEY", "aws_secret_access_key", "SESSION", "GITHUB_PAT", "PAT", "credentials", "API_KEY"}
	about := []string{"PATH", "AUTHOR", "SESSION_TIMEOUT", "session_id", "auth_mode", "PRIVATE_KEY_PATH", "access_key_id", "PAT_COUNT", "oauth", "sessions", "auth_enabled", "token_refresh_interval"}
	for _, k := range strong {
		if !strongCredentialKey(k) {
			t.Errorf("%s: not a credential name", k)
		}
	}
	for _, k := range about {
		if strongCredentialKey(k) {
			t.Errorf("%s: taken for a credential name", k)
		}
	}
}

func TestShortSecret(t *testing.T) {
	for _, v := range []string{"tglow", "abcde", "x9", "Pw1!", "hunt"} {
		if !shortSecret(v) {
			t.Errorf("%q: not taken for a short credential", v)
		}
	}
	for _, v := range []string{"none", "true", "off", "xxx", "XXXXX", "null", "12", "0", "a", "$X", "${X}", "<k>", "too long", "sixsix"} {
		if shortSecret(v) {
			t.Errorf("%q: taken for a short credential", v)
		}
	}
}

// An account's email address keeps its first character, its length and its
// domain (what CG-002 reports: j…@example.com); a URL's user, a git remote
// and a package version are no address.
func TestScrubEmailAddresses(t *testing.T) {
	doc := `{"oauthAccount": {"emailAddress": "jane.doe+ai@example.com"}, "userEmail": "jane.doe+ai@example.com",` +
		` "remote": "git@github.com:org/repo.git", "url": "https://bob@host.example.com/x", "pkg": "server@1.2.3",` +
		` "mail": "mailto:ops@example.org", "scoped": "@scope/pkg@latest"}`
	c := &collector{}
	out := string(c.scrubSecrets("/h/.claude.json", []byte(doc)))
	if len(out) != len(doc) {
		t.Fatalf("length changed")
	}
	if strings.Contains(out, "jane.doe+ai@") {
		t.Fatalf("ships the address:\n%s", out)
	}
	i := strings.Index(out, `"emailAddress": "`) + len(`"emailAddress": "`)
	addr := out[i : i+len("jane.doe+ai@example.com")]
	if addr[0] != 'j' || !strings.HasSuffix(addr, "@example.com") || addr[4] != '.' || addr[8] != '+' {
		t.Errorf("stand-in %q lost its shape", addr)
	}
	if !strings.Contains(out, `"userEmail": "`+addr+`"`) {
		t.Errorf("one address, two stand-ins:\n%s", out)
	}
	for _, keep := range []string{"git@github.com:org/repo.git", "https://bob@host.example.com/x", "server@1.2.3", "mailto:ops@example.org", "@scope/pkg@latest"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q:\n%s", keep, out)
		}
	}
}

// --pw/--pass take a password like --password, and curl's -u/--user
// user:password as separate argv elements is disguised in every config format.
func TestScrubPasswordFlagsAndCurlUser(t *testing.T) {
	files := map[string]string{
		"/h/.claude.json": `{"mcpServers": {"b": {"command": "curl", "args": ["-u", "carol:curlpw2low", "--user", "dave:userpwlow", "https://x.example"]}, ` +
			`"f": {"command": "acme", "args": ["--pw", "pwflaglow", "--pass", "passflaglow", "--db-pw", "dbpwflaglow"]}, ` +
			`"d": {"command": "docker", "args": ["run", "--user", "app:appgroup", "img"]}}}`,
		"/h/.hermes/config.yaml": "mcp_servers:\n  b:\n    command: curl\n    args:\n      - -u\n      - carol:curlpw2low\n      - --user\n      - dave:userpwlow\n" +
			"  f:\n    command: acme\n    args: [--pw, pwflaglow, --pass, passflaglow]\n" +
			"  g:\n    command: acme\n    args:\n      - --pw\n      - dbpwflaglow\n      - --password\n      - correcthorse\n",
		"/h/.codex/config.toml": "[mcp_servers.b]\ncommand = \"curl\"\nargs = [\"-u\", \"carol:curlpw2low\", \"--user=dave:userpwlow\"]\n" +
			"[mcp_servers.f]\ncommand = \"acme\"\nargs = [\"--pw\", \"pwflaglow\", \"--pass\", \"passflaglow\"]\n",
	}
	c := &collector{}
	for name, content := range files {
		out := string(c.scrubSecrets(name, []byte(content)))
		for _, s := range []string{"curlpw2low", "userpwlow", "pwflaglow", "passflaglow", "dbpwflaglow", "correcthorse"} {
			if strings.Contains(content, s) && strings.Contains(out, s) {
				t.Errorf("%s ships %q:\n%s", name, s, out)
			}
		}
		for _, keep := range []string{"carol:", "dave:", "--pw", "--pass"} {
			if strings.Contains(content, keep) && !strings.Contains(out, keep) {
				t.Errorf("%s lost %q:\n%s", name, keep, out)
			}
		}
		if strings.Contains(content, "app:appgroup") && !strings.Contains(out, "app:appgroup") {
			t.Errorf("%s: docker --user disguised:\n%s", name, out)
		}
	}
}
