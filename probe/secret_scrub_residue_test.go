package main

import (
	"strings"
	"testing"
)

func scrubbedHides(t *testing.T, path, doc string, secrets []string) string {
	t.Helper()
	c := &collector{}
	got := string(c.scrubSecrets(path, []byte(doc)))
	if len(got) != len(doc) {
		t.Fatalf("%s: layout changed:\n%s", path, got)
	}
	for _, s := range secrets {
		// every run of 8 characters of the hidden part (all but first 8 / last 4)
		hidden := s[8 : len(s)-4]
		for i := 0; i+6 <= len(hidden); i++ {
			if strings.Contains(got, hidden[i:i+6]) {
				t.Fatalf("%s: %q shipped (run %q):\n%s", path, s, hidden[i:i+6], got)
			}
		}
	}
	return got
}

// Node's dotenv (OpenClaw, Lyrie) reads a backtick-quoted value, over lines too.
func TestScrubBacktickDotenvValues(t *testing.T) {
	one := "Qw7rTzP3xK9mVb2NcLd8Hs4Yf6Gj1Ak5"
	two := "Zu4pWq8eRt2yUi6oPa1sDf3gHj7kLm9N"
	multi := "Xc5vBn2mQw8eRt4yUi7oPl1kJh3gFd6S"
	doc := "OPENAI_API_KEY=`" + one + "`\n" +
		"TOKEN = `" + two + "` # note\n" +
		"SECRET_BLOB=`first-line\n" + multi + "\n`\n" +
		"PLAIN=value\n"
	for _, p := range []string{"/h/.openclaw/.env", "/h/.lyrie/.env", "/h/.hermes/.env"} {
		got := scrubbedHides(t, p, doc, []string{one, two, multi})
		if !strings.Contains(got, "PLAIN=value") || !strings.Contains(got, "SECRET_BLOB=`") {
			t.Fatalf("%s: layout or plain values changed:\n%s", p, got)
		}
	}
}

// Under a secrets container, random strings at any depth (creds arrays of
// objects, deep maps, arrays of arrays), compact and pretty.
func TestScrubDeepSecretContainers(t *testing.T) {
	a := "Rt5yUi8oPa2sDf4gHj6kLz1xCv3bNm7Q"
	b := "Lp9oKi8uJy7hGt6fRd5eSw4aQz3xCv2B"
	c := "Mn1bVc2xZa3sDf4gHj5kLp6oIu7yTr8E"
	docs := []string{
		`{"creds":[{"k":"` + a + `"}],"x":{"creds":{"x":{"y":"` + b + `"}}},"credentials":[["` + c + `"]]}`,
		"{\n  \"creds\": [\n    {\n      \"k\": \"" + a + "\"\n    }\n  ],\n  \"other\": {\n    \"creds\": {\n      \"x\": {\n        \"y\": \"" + b + "\"\n      }\n    }\n  },\n  \"credentials\": [\n    [\n      \"" + c + "\"\n    ]\n  ]\n}\n",
	}
	for _, doc := range docs {
		scrubbedHides(t, "/h/.openclaw/openclaw.json", doc, []string{a, b, c})
	}
	// a setting under the container that is no credential stays
	keep := `{"credentials":{"primary":{"provider":"openai","label":"main account"}}}`
	if got := string((&collector{}).scrubSecrets("/h/.openclaw/openclaw.json", []byte(keep))); got != keep {
		t.Fatalf("settings changed: %s", got)
	}
}

// More text in a container than one walk reads: the secret after it is
// still disguised (the rest of the file is judged without its structure).
func TestScrubContainerPastWalkLimits(t *testing.T) {
	secret := "Hy6tGr5fEd4wSq3aZx2cVb1nMk9jLp8O"
	note := strings.Repeat("lorem ipsum dolor ", 4000) // ~70 KiB string
	structure := strings.Repeat(`"k": 1, `, 9000)      // ~70 KiB of keys
	for _, doc := range []string{
		`{"credentials":{"note":"` + note + `","primary":"` + secret + `"}}`,
		`{"credentials":{` + structure + `"primary":"` + secret + `"}}`,
		`{"credentials":{"a":"` + strings.Repeat("x", 1<<20+10) + `","primary":"` + secret + `"}}`,
	} {
		scrubbedHides(t, "/h/.openclaw/openclaw.json", doc, []string{secret})
	}
}
