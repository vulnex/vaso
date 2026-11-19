package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// numberKeys are the credential-ish names a number may sit under (dt24 g9
// tools/numfuzz.py).
var numberKeys = []string{"token", "api_key", "apiKey", "secret", "password", "pin", "tokenLimit", "max_tokens", "session", "auth", "client_secret", "private_key", "pat", "credential", "access_token"}

// numberDigits is a digit string of n characters, no leading zero.
func numberDigits(n int) string {
	b := []byte{byte('1' + randIndex(9))}
	for len(b) < n {
		b = append(b, byte('0'+randIndex(10)))
	}
	return string(b)
}

func numberSamples() []string {
	var out []string
	for _, n := range []int{6, 9, 12, 16, 18} {
		r := func() string { return numberDigits(n) }
		out = append(out, r(), "-"+r(), r()+"."+numberDigits(6), r()+"e"+numberDigits(2), r()+"E+"+numberDigits(2),
			r()+"e-"+numberDigits(1), "0."+r(), "-0."+r()+"e5", numberDigits(3)+"."+r())
	}
	return out
}

// typeShape is v's parsed structure: each key with the Go type of its value.
func typeShape(v map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, x := range v {
		t := fmt.Sprintf("%T", x)
		if f, ok := x.(float64); ok && (math.IsInf(f, 0) || math.IsNaN(f)) {
			t += fmt.Sprint(f)
		}
		out[k] = t
	}
	return out
}

// dt24 g9-F2: a disguised config parses to the same shape — every number
// stays a number of its kind, every date a date, inf and nan as they were.
func TestDisguisedNumbersParseTheSame(t *testing.T) {
	for round := 0; round < 2; round++ {
		var js, tm []string
		i := 0
		for _, k := range numberKeys {
			for _, v := range numberSamples() {
				i++
				js = append(js, fmt.Sprintf("%q: %s", fmt.Sprintf("%s%d", k, i), v))
				tm = append(tm, fmt.Sprintf("%s%d = %s", k, i, v))
			}
		}
		tm = append(tm,
			"token_hex = 0x"+strings.Repeat("9f3a", 3)+"c1", "secret_oct = 0o7316254017", "secret_bin = 0b1011001110001011100101",
			"token_under = 1_234_567_890_123", "password_inf = inf", "password_nan = nan", "password_neg_inf = -inf",
			"api_key_date = 2026-11-19T07:32:00Z", "api_key_ld = 2026-11-19", "pin_time = 07:32:00.123456",
			"password_plus = +123456789012345", "token_float_under = 3_141.592_653_589e1_0", "secret_ldt = 2026-11-19 07:32:00")
		jdoc := "{\n  " + strings.Join(js, ",\n  ") + "\n}\n"
		tdoc := strings.Join(tm, "\n") + "\n"

		jout := string((&collector{}).scrubSecrets("/h/.claude/settings.json", []byte(jdoc)))
		var a, b map[string]interface{}
		da := json.NewDecoder(strings.NewReader(jdoc))
		da.UseNumber()
		if err := da.Decode(&a); err != nil {
			t.Fatal(err)
		}
		db := json.NewDecoder(bytes.NewReader([]byte(jout)))
		db.UseNumber()
		if err := db.Decode(&b); err != nil {
			t.Fatalf("disguised JSON no longer parses: %v\n%s", err, jout)
		}
		if !reflect.DeepEqual(typeShape(a), typeShape(b)) {
			t.Fatalf("JSON shape changed:\n%s", jout)
		}

		tout := string((&collector{}).scrubSecrets("/h/.codex/config.toml", []byte(tdoc)))
		var ta, tb map[string]interface{}
		if _, err := toml.Decode(tdoc, &ta); err != nil {
			t.Fatal(err)
		}
		if _, err := toml.Decode(tout, &tb); err != nil {
			t.Fatalf("disguised TOML no longer parses: %v\n%s", err, tout)
		}
		if !reflect.DeepEqual(typeShape(ta), typeShape(tb)) {
			sa, sb := typeShape(ta), typeShape(tb)
			for k := range sa {
				if sa[k] != sb[k] {
					t.Errorf("TOML %s: %s → %s", k, sa[k], sb[k])
				}
			}
			t.Fatalf("TOML shape changed:\n%s", tout)
		}
	}
}

func TestNumberStandInKeepsLiteralShape(t *testing.T) {
	cases := map[string]scalarType{
		"933336529534e11": scalarNumber, "0x9f3a9f3a9f3ac1": scalarNumber, "0o7316254017": scalarNumber, "0b10110011100010111": scalarNumber,
		"1_234_567_890_123": scalarNumber, "+123456789012345": scalarNumber, ".123456789012345": scalarNumber, "123456789012345.": scalarNumber,
		"3_141.592_653_589e1_0": scalarNumber, "0123456789012": scalarNumber,
		".inf": scalarKept, "-.Inf": scalarKept, "nan": scalarKept, "Infinity": scalarKept, "NaN": scalarKept,
		"2026-11-19T07:32:00Z": scalarKept, "2026-11-19": scalarKept, "07:32:00.123456": scalarKept, "~": scalarKept,
	}
	for v, kind := range cases {
		if got := scalarKind(v); got != kind {
			t.Errorf("scalarKind(%q) = %d, want %d", v, got, kind)
			continue
		}
		c := &collector{}
		out := c.disguiseKeyed("password", v)
		if kind == scalarKept {
			if out != v {
				t.Errorf("%q changed to %q", v, out)
			}
			continue
		}
		if len(out) != len(v) || scalarKind(out) != scalarNumber {
			t.Errorf("%q → %q: no longer a number", v, out)
		}
		for i := 0; i < len(v); i++ {
			digit := func(ch byte) bool { return ch >= '0' && ch <= '9' || strings.HasPrefix(v, "0x") && i > 1 && strings.ContainsRune("abcdefABCDEF", rune(ch)) }
			if digit(v[i]) != digit(out[i]) {
				t.Errorf("%q → %q: byte %d changed class", v, out, i)
			}
		}
		if leadingZero(v) != leadingZero(out) {
			t.Errorf("%q → %q: leading zero changed", v, out)
		}
	}
}
