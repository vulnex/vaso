package main

import (
	"crypto/rand"
	"math"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Secrets inside collected config files (a .env's ANTHROPIC_API_KEY, a
// credentials.json NVIDIA key, an apiKey in settings.json) never leave the
// host. Checks still have to reach the same verdict remotely as locally, so a
// secret isn't blanked but disguised: its first 8 and last 4 characters (what
// reports show), length, punctuation and the class of every other character
// (digit, a–f, g–z, A–F, G–Z) stay, the rest is random. Key formats, length
// and entropy rules, references, placeholders and weak defaults then judge
// the disguised value exactly as they judge the real one, and checked below.
// Placeholders, references and weak defaults are kept as they are: they are
// what the checks look for and protect nothing.

// apiKeyPatterns is API_KEY_PATTERNS from src/core/patterns.ts, verbatim
// (TestAPIKeyPatternsMatchTS): a disguised value matches the same formats.
var apiKeyPatterns = []string{
	`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}`,
	`sk-or-v1-[a-f0-9]{32,}`,
	`sk-[a-zA-Z0-9]{20,}`,
	`sk-ant-[a-zA-Z0-9-]{20,}`,
	`AKIA[0-9A-Z]{16,}`,
	`ghp_[a-zA-Z0-9]{36,}`,
	`gho_[a-zA-Z0-9]{36,}`,
	`glpat-[a-zA-Z0-9\-_]{20,}`,
	`xoxb-[0-9]+(?:-[0-9a-zA-Z]+)+`,
	`xoxp-[0-9]+(?:-[0-9a-zA-Z]+)+`,
	`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`,
	`\b[0-9]{10}:[A-Za-z0-9_-]{35,}\b`,
	`\bdevin-[A-Za-z0-9$._-]{60,}`,
	`\bcog_[a-zA-Z0-9]{16,}`,
	`\bapk_(?:user_)?[a-zA-Z0-9]{16,}`,
	`VELLUM_API_KEY\s*[=:]\s*['"]?[a-zA-Z0-9._-]{20,}`,
}

var apiKeyRes = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(apiKeyPatterns))
	for i, p := range apiKeyPatterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}()

// weakPatterns is CFG-009's WEAK_PATTERNS (src/checks/config/cfg-009-default-credentials.ts),
// verbatim (TestWeakPatternsMatchTS): a default credential is the finding.
var weakPatterns = []string{
	`(?i)\bpassword\b`,
	`(?i)\b(admin|root|test|demo|default|changeme|password123|12345|qwerty)\b`,
	`(?i)(?:^|[-_ .])(?:replace|change|your|insert|enter|example|placeholder|sample|dummy)(?:[-_ .]|$)`,
	`^<[^>]+>$`,
	`(?i)^x{4,}$`,
	`(?i)abcd1234|12345678|0123456789`,
}

var weakRes = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(weakPatterns))
	for i, p := range weakPatterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}()

// isPlaceholderSecret mirrors isPlaceholderSecret in src/core/patterns.ts
// (shared corpus: testdata/secret-verdicts.json).
var (
	placeholderEllipsis = regexp.MustCompile(`\.{3}|\x{2026}`)
	placeholderWrapped  = regexp.MustCompile(`^<[^>]*>$|^\{\{[^}]*\}\}$`)
	placeholderMasked   = regexp.MustCompile(`x{4,}|X{4,}|\*{3,}`)
	placeholderExample  = regexp.MustCompile(`EXAMPLE(?:KEY)?$`)
	// JS uses a lookahead for the closing delimiter; consuming it is the same test
	placeholderWord = regexp.MustCompile(`(?i)(?:^|[-_.\s<{:/])(?:your|example|sample|dummy|placeholder|changeme|change[-_]me|replace|insert|redacted|fake)(?:$|[-_.\s>}])`)
)

func isPlaceholderSecret(value string) bool {
	v := strings.TrimSpace(value)
	return v == "" || placeholderEllipsis.MatchString(v) || placeholderWrapped.MatchString(v) ||
		placeholderMasked.MatchString(v) || placeholderExample.MatchString(v) || placeholderWord.MatchString(v)
}

func isWeakCredential(v string) bool {
	for _, re := range weakRes {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// isSecretReference approximates isSecretReference in src/core/patterns.ts:
// env references, secret-manager and file references, profile names. They
// name where a secret lives, are what the checks read, and are kept.
var (
	authSchemePrefix = regexp.MustCompile(`(?i)^\s*(?:bearer|basic|token)\s+`)
	envReference     = regexp.MustCompile(`^\$\{(?:env|file):[^}]+\}$|^\{(?:env|file):[^}]+\}$|^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?[-=?+][^}]*)?\}$|^\$[A-Za-z_][A-Za-z0-9_]*$|(?i:^\$env:[A-Za-z_][A-Za-z0-9_]*$)|^%[A-Za-z_][A-Za-z0-9_]*%$|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	managerReference = regexp.MustCompile(`^(?:op|vault|keychain|keyring|secret|secrets|gopass|lpass|bw|bws|doppler|infisical|azkv|gcpsm|awssm|sm|ssm|kms|sops|age)(?::\/\/|:)[^\s]+$|^ref\+[a-z0-9]+:\/\/\S+$|^arn:aws[\w-]*:(?:secretsmanager|ssm|kms):[\w-]*:\d*:\S+$|^projects\/[\w.-]+\/secrets\/[\w.-]+(?:\/versions\/[\w.-]+)?$`)
	fileReference    = regexp.MustCompile(`(?i)^(?:~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]|^[\w.@-]+\.(?:json|pem|key|p8|p12|pfx|crt|cer|der|jks|keystore|txt|env|ya?ml|toml|ini|cfg|conf|gpg|asc|age|enc)$`)
	profileName      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)
)

func isSecretReference(value string) bool {
	v := strings.TrimSpace(authSchemePrefix.ReplaceAllString(value, ""))
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return false
	}
	if envReference.MatchString(v) {
		return true
	}
	if matchesAPIKey(v) {
		return false
	}
	return managerReference.MatchString(v) || fileReference.MatchString(v) || isProfileName(v)
}

// profileWords is PROFILE_WORDS from src/core/patterns.ts (TestProfileWordsMatchTS).
var profileWords = strings.Fields(`prod production staging stage stg dev development test testing qa uat
	sandbox default local main primary secondary preview demo personal work team org admin
	readonly ro rw profile region global us eu ap sa ca me af il cn gov
	east west north south central northeast southeast northwest southwest`)

var (
	profileWordSet = func() map[string]bool {
		m := map[string]bool{}
		for _, w := range profileWords {
			m[w] = true
		}
		return m
	}()
	profileWord   = regexp.MustCompile(`^[a-z]{1,16}$`)
	profileNumber = regexp.MustCompile(`^\d{1,4}$`)
	profileSplit  = regexp.MustCompile(`[-_.]`)
)

// isProfileName mirrors isProfileName in src/core/patterns.ts: production-us-east-2, default.
func isProfileName(v string) bool {
	if len(v) > 64 || !profileName.MatchString(v) {
		return false
	}
	parts := profileSplit.Split(v, -1)
	known := false
	for _, p := range parts {
		if !profileWord.MatchString(p) && !profileNumber.MatchString(p) {
			return false
		}
		known = known || profileWordSet[p]
	}
	return known
}

func matchesAPIKey(v string) bool {
	for _, re := range apiKeyRes {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// shannonEntropy matches src/analyzers/entropy.ts (per character).
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		freq[r]++
		n++
	}
	e := 0.0
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

// highEntropySecret is isSecretLikeValue's generic arm (a secret-named key
// holding something random): length ≥ 20, no whitespace, entropy > 4.5.
func highEntropySecret(value string) bool {
	v := authSchemePrefix.ReplaceAllString(strings.TrimSpace(value), "")
	return len(v) >= 20 && !strings.ContainsAny(v, " \t\r\n") && shannonEntropy(v) > 4.5
}

// The judgements the CLI makes of a value, which a disguise must preserve.
type secretVerdicts struct {
	placeholder, weak, reference, apiKey, highEntropy bool
}

func verdictsOf(v string) secretVerdicts {
	return secretVerdicts{isPlaceholderSecret(v), isWeakCredential(v), isSecretReference(v), matchesAPIKey(v), highEntropySecret(v)}
}

// enumLike values are settings, not secrets: oauth-personal, none, true.
var enumLike = regexp.MustCompile(`^[a-z][a-z._-]*$|^[0-9]{1,11}$`)

// worthDisguising: something a credential could be, that isn't already a
// placeholder, a reference, a URL or a PEM block.
func worthDisguising(core string) bool {
	if core == "" || enumLike.MatchString(core) || strings.Contains(core, "://") || strings.Contains(core, "-----BEGIN") {
		return false
	}
	if isPlaceholderSecret(core) || isSecretReference(core) {
		return false
	}
	for i := 0; i < len(core); i++ {
		if isASCIIAlnum(core[i]) {
			return true
		}
	}
	return false
}

func isASCIIAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// keepBounds: what reports show of a secret (8 leading, 4 trailing chars of
// a long one; checks print value.slice(0, 8) and slice(-4)) stays real.
func keepBounds(n int) (int, int) {
	switch {
	case n >= 24:
		return 8, 4
	case n >= 16:
		return 4, 0
	}
	return 0, 0
}

func randIndex(n int) int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return int(i.Int64())
}

// classRange is the run of characters a byte is replaced from.
func classRange(b byte) (byte, byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return '0', '9', true
	case b >= 'a' && b <= 'f':
		return 'a', 'f', true
	case b >= 'g' && b <= 'z':
		return 'g', 'z', true
	case b >= 'A' && b <= 'F':
		return 'A', 'F', true
	case b >= 'G' && b <= 'Z':
		return 'G', 'Z', true
	}
	return 0, 0, false
}

// randomLike replaces each ASCII letter and digit with a random one of its
// class. A backslash escape (\n, \", é inside a JSON/TOML/YAML string)
// is copied whole so the file stays valid.
func randomLike(s string, fixed []bool) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if fixed != nil && fixed[i] {
			continue
		}
		if b[i] == '\\' {
			if i+1 < len(b) && b[i+1] == 'u' {
				i += 5
			} else {
				i++
			}
			continue
		}
		if lo, hi, ok := classRange(b[i]); ok {
			b[i] = lo + byte(randIndex(int(hi-lo)+1))
		}
	}
	return string(b)
}

// shuffleLike permutes letters and digits within each class (escapes kept):
// the character counts, and so the entropy, stay exactly as they were.
func shuffleLike(s string, fixed []bool) string {
	b := []byte(s)
	var pos [5][]int
	idx := func(lo byte) int { return strings.IndexByte("0agAG", lo) }
	for i := 0; i < len(b); i++ {
		if fixed != nil && fixed[i] {
			continue
		}
		if b[i] == '\\' {
			if i+1 < len(b) && b[i+1] == 'u' {
				i += 5
			} else {
				i++
			}
			continue
		}
		if lo, _, ok := classRange(b[i]); ok {
			pos[idx(lo)] = append(pos[idx(lo)], i)
		}
	}
	for _, p := range pos {
		for i := len(p) - 1; i > 0; i-- {
			j := randIndex(i + 1)
			b[p[i]], b[p[j]] = b[p[j]], b[p[i]]
		}
	}
	return string(b)
}

// disguise returns a stand-in for a secret value that every check judges as
// it judges the value, or the value itself when it isn't worth hiding. The
// same value gets the same stand-in throughout one snapshot.
func (c *collector) disguise(v string) string {
	if d, ok := c.disguised[v]; ok {
		return d
	}
	lead, core := "", v
	if m := authSchemePrefix.FindStringIndex(v); m != nil {
		lead, core = v[:m[1]], v[m[1]:]
	}
	if !worthDisguising(core) {
		return v
	}
	pre, suf := keepBounds(len(core))
	head, mid, tail := core[:pre], core[pre:len(core)-suf], core[len(core)-suf:]
	// What CFG-009 matched (a "12345678" run, "password") stays as it is
	fixed := make([]bool, len(mid))
	for _, re := range weakRes {
		for _, loc := range re.FindAllStringIndex(core, -1) {
			for i := loc[0]; i < loc[1]; i++ {
				if i >= pre && i < pre+len(mid) {
					fixed[i-pre] = true
				}
			}
		}
	}
	want := verdictsOf(v)
	out := lead + head + shuffleLike(mid, fixed) + tail
	for try := 0; try < 64; try++ {
		if cand := lead + head + randomLike(mid, fixed) + tail; verdictsOf(cand) == want {
			out = cand
			break
		}
	}
	if c.disguised == nil {
		c.disguised = map[string]string{}
	}
	c.disguised[v] = out
	c.disguised[out] = out // idempotent: a later pass over the same text keeps it
	return out
}

// isSecretKeyName: a settings key whose value is a credential — the probe's
// env-name rule (apiKey → API_KEY) or CLI's SECRET_KEY_NAME (src/core/secret-values.ts).
var secretKeyName = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|secret|password|passwd|credential|private[_-]?key|auth(?:orization)?$)`)

// credentialLike: what a value under a credential-named key must look like
// to be disguised — 8+ characters with a digit, a capital or a symbol. A
// short setting under a token-ish key ("tokenizer": "cl100k") is left alone.
var credentialMarker = regexp.MustCompile(`[0-9A-Z!-/:-@\[-` + "`" + `{-~]`)

func credentialLike(v string) bool {
	core := authSchemePrefix.ReplaceAllString(v, "")
	return len(core) >= 8 && credentialMarker.MatchString(core)
}

// isSecretFlag: --token, --api-key, --password, -k … (not --keyboard)
func isSecretFlag(flag string) bool {
	return isSecretKeyName(strings.TrimLeft(flag, "-"))
}

func isSecretKeyName(key string) bool {
	return secretKeyName.MatchString(key) || isSecretJSONKey(key)
}

var (
	// KEY=value lines of a dotenv file (commented-out ones too: they leak alike)
	dotenvLine = regexp.MustCompile(`(?m)^([ \t]*#?[ \t]*(?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*=[ \t]*)([^\r\n]*)$`)
	// "key": "value" in JSON, JSONC, JSON5 and YAML/TOML flow mappings
	jsonPair = regexp.MustCompile(`"((?:[^"\\\r\n]|\\.)*)"(\s*:\s*)"((?:[^"\\\r\n]|\\.)*)"`)
	// key: value in YAML (block mappings, list items)
	yamlPair = regexp.MustCompile(`(?m)^([ \t]*(?:-[ \t]+)?)(["']?)([A-Za-z0-9_.-]+)(["']?)([ \t]*:[ \t]+)([^\r\n]*)$`)
	// key = "value" in TOML (and inline tables)
	tomlPair = regexp.MustCompile(`(^|[\s{,])([A-Za-z0-9_.-]+|"[^"\r\n]+")([ \t]*=[ \t]*)("(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*')`)
	// scheme://user:password@ in URLs anywhere
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s:"']+:)([^/?#@\s"']+)@`)
	// ?api_key=, &token= … in URLs anywhere
	urlCredParam = regexp.MustCompile(`([?&#;])([^=&#;\s"']+)=([^&#;\s"'<>]+)`)
	argPair      = regexp.MustCompile(`"(--?[A-Za-z][A-Za-z0-9_-]*)"(\s*,\s*)"((?:[^"\\\r\n]|\\.)*)"`)
	flagValue    = regexp.MustCompile(`(--?[A-Za-z][A-Za-z0-9_-]*)=([^\s"',;&|]+)`)
	// a PEM private key's body (header and footer stay: they are the finding)
	pemBody = regexp.MustCompile(`(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)`)
)

// scalarValue splits a raw dotenv/YAML value into the secret part and what
// surrounds it (quotes, a trailing comment), so only the secret changes.
func scalarValue(raw string) (string, string, string) {
	if raw == "" {
		return "", "", ""
	}
	if q := raw[0]; q == '"' || q == '\'' {
		for i := 1; i < len(raw); i++ {
			if raw[i] == '\\' && q == '"' {
				i++
				continue
			}
			if raw[i] == q {
				return raw[:1], raw[1:i], raw[i:]
			}
		}
		return "", raw, ""
	}
	if strings.ContainsAny(raw[:1], "{[|>&*!") {
		return raw, "", ""
	}
	end := len(raw)
	if i := strings.Index(raw, " #"); i >= 0 {
		end = i
	}
	value := strings.TrimRight(raw[:end], " \t")
	return "", value, raw[len(value):]
}

// scrubSecrets disguises the secrets in a collected file's text (see above).
// The length never changes, so the content budget charged stays right.
func (c *collector) scrubSecrets(path string, content []byte) []byte {
	if !utf8.Valid(content) {
		return content
	}
	s := string(content)
	name := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	dotenv := strings.HasPrefix(name, ".env") || ext == ".env"
	jsonish := ext == ".json" || ext == ".jsonc" || ext == ".json5"
	yaml := ext == ".yaml" || ext == ".yml"
	toml := ext == ".toml" || ext == ".ini" || ext == ".cfg" || ext == ".conf"

	s = pemBody.ReplaceAllStringFunc(s, func(m string) string {
		g := pemBody.FindStringSubmatch(m)
		return g[1] + randomLike(g[2], nil) + g[3]
	})
	keyed := func(key, raw string) string {
		if !isSecretKeyName(key) {
			return raw
		}
		open, value, rest := scalarValue(raw)
		if !credentialLike(value) {
			return raw
		}
		return open + c.disguise(value) + rest
	}
	if dotenv {
		s = dotenvLine.ReplaceAllStringFunc(s, func(m string) string {
			g := dotenvLine.FindStringSubmatch(m)
			return g[1] + g[2] + g[3] + keyed(g[2], g[4])
		})
	}
	if jsonish || yaml || toml || dotenv {
		s = jsonPair.ReplaceAllStringFunc(s, func(m string) string {
			g := jsonPair.FindStringSubmatch(m)
			if !isSecretKeyName(g[1]) || !credentialLike(g[3]) {
				return m
			}
			return `"` + g[1] + `"` + g[2] + `"` + c.disguise(g[3]) + `"`
		})
	}
	if yaml {
		s = yamlPair.ReplaceAllStringFunc(s, func(m string) string {
			g := yamlPair.FindStringSubmatch(m)
			if g[2] != g[4] {
				return m
			}
			return g[1] + g[2] + g[3] + g[4] + g[5] + keyed(g[3], g[6])
		})
	}
	if toml {
		s = tomlPair.ReplaceAllStringFunc(s, func(m string) string {
			g := tomlPair.FindStringSubmatch(m)
			key := strings.Trim(g[2], `"`)
			return g[1] + g[2] + g[3] + keyed(key, g[4])
		})
	}
	if jsonish || yaml || toml {
		// "--api-key", "<value>" in an argv array (MCP server args)
		s = argPair.ReplaceAllStringFunc(s, func(m string) string {
			g := argPair.FindStringSubmatch(m)
			if !isSecretFlag(g[1]) || !credentialLike(g[3]) {
				return m
			}
			return `"` + g[1] + `"` + g[2] + `"` + c.disguise(g[3]) + `"`
		})
	}
	// --api-key=<value> anywhere (a command line in a hook or an args string)
	s = flagValue.ReplaceAllStringFunc(s, func(m string) string {
		g := flagValue.FindStringSubmatch(m)
		if !isSecretFlag(g[1]) || !credentialLike(g[2]) {
			return m
		}
		return g[1] + "=" + c.disguise(g[2])
	})
	s = urlPassword.ReplaceAllStringFunc(s, func(m string) string {
		g := urlPassword.FindStringSubmatch(m)
		return g[1] + c.disguise(g[2]) + "@"
	})
	s = urlCredParam.ReplaceAllStringFunc(s, func(m string) string {
		g := urlCredParam.FindStringSubmatch(m)
		if !isSecretJSONKey(g[2]) {
			return m
		}
		return g[1] + g[2] + "=" + c.disguise(g[3])
	})
	s = tokenShaped.ReplaceAllStringFunc(s, c.disguise)
	return []byte(s)
}

// scrubbable: a file whose secrets are disguised. Skill trees and installed
// packages ship verbatim: IOC-003/008 hash skill files, and neither is where
// an agent keeps its credentials.
func (c *collector) scrubbable(path string) bool {
	slash := filepath.ToSlash(path)
	return !c.inSkillTree && !strings.Contains(slash, "/node_modules/") && !strings.Contains(slash, "/skills/")
}
