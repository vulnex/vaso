package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shell word assembly the TypeScript twin (src/mcp/argv-rules.ts) shares:
// testdata/argv-verdicts.json "segments".
func TestCommandSegmentsShared(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "argv-verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Segments []struct {
			Line  string
			Words [][]string
			Pipes []bool
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Segments) == 0 {
		t.Fatal("no segments")
	}
	for _, c := range corpus.Segments {
		var got [][]string
		var pipes []bool
		for _, seg := range commandSegments(c.Line) {
			got = append(got, tokenWords(seg.tokens))
			pipes = append(pipes, seg.pipe)
		}
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(c.Words)
		if string(g) != string(w) {
			t.Errorf("%s: words %s, want %s", c.Line, g, w)
		}
		if c.Pipes != nil {
			gp, _ := json.Marshal(pipes)
			wp, _ := json.Marshal(c.Pipes)
			if string(gp) != string(wp) {
				t.Errorf("%s: pipes %s, want %s", c.Line, gp, wp)
			}
		}
	}
}

func TestCommandCredentialsAssembledWords(t *testing.T) {
	same := func(v string) string { return strings.Repeat("Z", len(v)) }
	cases := []struct{ line, want string }{
		// the whole value is disguised; the space and the quotes around it stay
		{`mysql -p"pass Phr4se9x" app`, `mysql -p"ZZZZZZZZZZZZZ" app`},
		{`"command": "mysql -p\"pass Phr4se9x\" app"`, `"command": "mysql -p\"ZZZZZZZZZZZZZ\" app"`},
		{`mysql '-p'"Cc4Nc4tQ9x" app`, `mysql '-p'"ZZZZZZZZZZ" app`},
		{`mysql "-pQt3Wh0leQ9" app`, `mysql "-pZZZZZZZZZZ" app`},
		{`mysql -p$'Ans1Cq7Wx' app`, `mysql -p$'ZZZZZZZZZ' app`},
		// a $'…' escape inside: what is written is disguised, the escape too
		{`mysql -p$'Esc\x41pe9q' app`, `mysql -p$'ZZZZZZZZZZZ' app`},
		{`sshpass -p "spaced P4ss9z" ssh h`, `sshpass -p "ZZZZZZZZZZZZZ" ssh h`},
		{`echo Su1Pw9xQ | sudo -S true`, `echo ZZZZZZZZ | sudo -S true`},
	}
	parts := []string{"Phr4se9x", "Cc4Nc4tQ9x", "Qt3Wh0leQ9", "Ans1Cq7Wx", "x41pe9q", "P4ss9z", "Su1Pw9xQ"}
	for _, c := range cases {
		if got := commandCredentials(c.line, same); got != c.want {
			t.Errorf("%s: got %s, want %s", c.line, got, c.want)
		}
		redacted := commandCredentials(c.line, func(string) string { return "[REDACTED]" })
		for _, part := range parts {
			if strings.Contains(redacted, part) {
				t.Errorf("%s: redacted as %s", c.line, redacted)
			}
		}
	}
}

func TestClientPasswordsInSnapshots(t *testing.T) {
	commands := map[string]string{
		`mysql -u root "-pQt3Wh0leQ9" app`:                             "Qt3Wh0leQ9",
		`mysql -u root '-p'"Cc4Nc4tQ9x" app`:                           "Cc4Nc4tQ9x",
		`mysql -u root -p"pass Phr4se9x" app`:                          "Phr4se9x",
		`mysql -p$'Ans1Cq7Wx' app`:                                     "Ans1Cq7Wx",
		`sqlcmd -S h -U sa -P Sq1Pw9xLm`:                               "Sq1Pw9xLm",
		`docker login -u u -p Dk1Pw9xQ reg.example`:                    "Dk1Pw9xQ",
		`docker login --username u --password "Dk2 Pw9xQ" reg.example`: "Dk2 Pw9xQ",
		`smbclient //h/s -U u%Sm1Pw9xQ`:                                "Sm1Pw9xQ",
		`lftp -u u,Lf1Pw9xQ ftp.example`:                               "Lf1Pw9xQ",
		`ldapsearch -x -D cn=a -w Ld1Pw9xQ`:                            "Ld1Pw9xQ",
		`mongo -u u -p Mg1Pw9xQ h/db`:                                  "Mg1Pw9xQ",
		`htpasswd -b .htpasswd u Ht1Pw9xQ`:                             "Ht1Pw9xQ",
		`echo Su1Pw9xQ | sudo -S true`:                                 "Su1Pw9xQ",
		`echo Dk3Pw9xQ | docker login -u u --password-stdin reg`:       "Dk3Pw9xQ",
		`xfreerdp /u:admin /p:Rd1Pw9xQ /v:h`:                           "Rd1Pw9xQ",
		`ssh h "smbclient //h/s -U 'u%Sm3 Pw9xQ'"`:                     "Sm3 Pw9xQ",
		`bash -c "echo 'Su4Pw9xQ' | sudo -S id"`:                       "Su4Pw9xQ",
	}
	var hooks []map[string]string
	var yml strings.Builder
	for c := range commands {
		hooks = append(hooks, map[string]string{"type": "command", "command": c})
		q, _ := json.Marshal(c)
		yml.WriteString("  - command: " + string(q) + "\n")
	}
	doc := map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{"matcher": "Bash", "hooks": hooks}}}}
	in, _ := json.MarshalIndent(doc, "", " ")
	for name, content := range map[string]string{
		"/h/.claude/settings.json": string(in),
		"/h/.hermes/config.yaml":   "hooks:\n" + yml.String(),
	} {
		out := string((&collector{}).scrubSecrets(name, []byte(content)))
		for c, pw := range commands {
			for _, part := range strings.Fields(pw) {
				if strings.Contains(out, part) {
					t.Errorf("%s: %s: %q shipped", name, c, part)
				}
			}
		}
	}
}
