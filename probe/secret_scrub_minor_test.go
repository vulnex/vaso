package main

import (
	"bytes"
	"strings"
	"testing"
)

// dt24 g9: a quoted --header value kept its secret hidden but scrambled the
// header's name; a dotenv value written 'a\'b' shipped what follows the \'.
func TestScrubHeaderNamesAndDotenvEscapedQuote(t *testing.T) {
	const tok = "Qw7rTy2uIo9pAs4dFg6hJk10"
	for _, line := range []string{
		`{"command":"curl --header 'X-Auth-Token: ` + tok + `' x"}`,
		`{"command":"curl --header \"X-Api-Key: ` + tok + `\" x"}`,
	} {
		out := string((&collector{}).scrubSecrets("/h/.claude/settings.json", []byte(line)))
		if strings.Contains(out, hiddenPart(tok)) {
			t.Errorf("secret shipped: %s", out)
		}
		name := "X-Auth-Token: "
		if strings.Contains(line, "X-Api-Key") {
			name = "X-Api-Key: "
		}
		if !strings.Contains(out, name) {
			t.Errorf("header name changed: %s", out)
		}
	}
	doc := "SECRET_KEY='Ab3dEf9hIj\\'Kl8mNo7pQr'\nOTHER_KEY='Zx8cVb3nMq1w\\'Er5tYu7iOp2a' # note\n"
	out := string((&collector{}).scrubSecrets("/h/.hermes/.env", []byte(doc)))
	for _, s := range []string{"Kl8mNo7pQr", "Er5tYu7iOp2a"} {
		if strings.Contains(out, s) {
			t.Errorf("%s shipped:\n%s", s, out)
		}
	}
	sameShape(t, doc, out)
}

func TestCommandOutputCapped(t *testing.T) {
	b := newCappedBuffer(10)
	for i := 0; i < 5; i++ {
		if n, err := b.Write(bytes.Repeat([]byte("x"), 4)); n != 4 || err != nil {
			t.Fatalf("write %d: %d, %v", i, n, err)
		}
	}
	if got := b.String(); got != strings.Repeat("x", 10)+commandOutputTruncated {
		t.Errorf("kept %q", got)
	}
	if got := newCappedBuffer(10); got.String() != "" {
		t.Error("empty buffer")
	}
}

// dt24 g9: a dotenv value the shell glues from several quoted pieces
// (an escaped quote between single-quoted pieces, "a"'b', 'a'b) shipped every
// piece after the first.
func TestScrubDotenvGluedPieces(t *testing.T) {
	doc := "OPENROUTER_API_KEY='sk-or-v1-Zq8Wv3Lm5Np2'\\''Rx7Tk4Hs9Jd6Fb1Gc0Ny'\n" +
		"DB_PASSWORD=\"Pq8Wo3\"'Ie7Ru2TyXc'\n" +
		"API_TOKEN='Hh4Jj5Kk'\"Ll6Mm7Nn8\"Oo9Pp0Qq # note Vv1\n" +
		"SECRET_KEY='Ab3dEf9hIj\\'Kl8mNo7pQr'\n" +
		"export AUTH_TOKEN=`Bb2Cc3Dd`'Ee4Ff5Gg6Hh'\n" +
		"PLAIN_NAME='hello'\"world\"\n" +
		"MODEL=\"gpt-4o\" # comment\n"
	out := string((&collector{}).scrubSecrets("/h/.hermes/.env", []byte(doc)))
	for _, s := range []string{"Rx7Tk4Hs9Jd6Fb1Gc0Ny", "Ie7Ru2TyXc", "Ll6Mm7Nn8", "Oo9Pp0Qq", "Kl8mNo7pQr", "Ee4Ff5Gg6Hh"} {
		if strings.Contains(out, s) {
			t.Errorf("%s shipped:\n%s", s, out)
		}
	}
	// not a secret: kept; comments and quotes kept
	for _, s := range []string{"PLAIN_NAME='hello'\"world\"", "MODEL=\"gpt-4o\" # comment", "# note Vv1", "'\\''"} {
		if !strings.Contains(out, s) {
			t.Errorf("%q changed:\n%s", s, out)
		}
	}
	sameShape(t, doc, out)
}

// 1.4.3 re-verify: the first piece of a glued dotenv value was judged on its
// own, so a short one ("S3cr3tP"'!') shipped as written and a 6-character
// one kept more than the joined value's stand-in keeps.
func TestScrubDotenvGluedShortFirstPiece(t *testing.T) {
	doc := "DB_PASSWORD=\"S3cr3tP\"'!'\n" +
		"DB_PASSWORD2=\"Pq8Wo3\"'Ie7Ru2TyXc'\n" +
		"API_TOKEN='Zx4Cv7'\"Bn2Mm5Qw9Er\"\n" +
		"AUTH_SECRET=\"Kd3Fg8\"Hj6Lp1Wq4\n" +
		"DB_PASS=\"Yt5Ui2\"\"Op7As3Df\"\n" +
		"SECRET_KEY='Gh9J\\'Kl8mNo7pQr'\n" +
		"PLAIN_NAME='hello'\"world\"\n"
	for i := 0; i < 20; i++ {
		out := string((&collector{}).scrubSecrets("/h/.hermes/.env", []byte(doc)))
		for _, s := range []string{"S3cr3tP", "Pq8Wo3", "Zx4Cv7", "Kd3Fg8", "Yt5Ui2", "Gh9J"} {
			if strings.Contains(out, s) {
				t.Fatalf("%s shipped:\n%s", s, out)
			}
		}
		if !strings.Contains(out, "PLAIN_NAME='hello'\"world\"") {
			t.Fatalf("non-secret changed:\n%s", out)
		}
		sameShape(t, doc, out)
	}
	// a joined value of 16+ characters keeps the stand-in's 4-character head
	long := "DB_PASSWORD=\"Pq8Wo3Ie\"'7Ru2TyXcAb'\n"
	out := string((&collector{}).scrubSecrets("/h/.hermes/.env", []byte(long)))
	if !strings.HasPrefix(out, "DB_PASSWORD=\"Pq8W") || strings.Contains(out, "Pq8Wo3Ie") {
		t.Errorf("head of a 16+ joined value:\n%s", out)
	}
}
