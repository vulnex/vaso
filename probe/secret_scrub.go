package main

import (
	"bytes"
	"crypto/rand"
	"math"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
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

// extraTokenPatterns is EXTRA_TOKEN_PATTERNS from src/analyzers/secret-values.ts
// (TestExtraTokenPatternsMatchTS): the formats the agent-settings checks
// recognise beyond API_KEY_PATTERNS. A stand-in matches the same ones.
var extraTokenPatterns = []string{
	`^github_pat_[A-Za-z0-9_]{20,}`,
	`^gh[ousr]_[A-Za-z0-9]{30,}`,
	`^sk-or-v1-[A-Za-z0-9]{32,}`,
	`^sk-ant-[A-Za-z0-9_-]{20,}`,
	`^sk-ak-[A-Za-z0-9]{20,}`,
	`(?i)^sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
	`^xox[abeprs]-[A-Za-z0-9-]{10,}`,
	`^AIza[0-9A-Za-z_-]{30,}`,
	`^ASIA[0-9A-Z]{16,}`,
	`^gsk_[A-Za-z0-9]{20,}`,
	`^hf_[A-Za-z0-9]{20,}`,
	`^xai-[A-Za-z0-9]{32,}`,
	`^nvapi-[A-Za-z0-9_-]{20,}`,
	`^glpat-[A-Za-z0-9_-]{20,}`,
	`^pat[A-Za-z0-9]{14}\.[0-9a-f]{64}`,
}

var tokenFormatRes = func() []*regexp.Regexp {
	out := append([]*regexp.Regexp(nil), apiKeyRes...)
	for _, p := range extraTokenPatterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}()

// tokenFormats is the set of known token formats v matches (one bit each).
func tokenFormats(v string) uint64 {
	var set uint64
	for i, re := range tokenFormatRes {
		if re.MatchString(v) {
			set |= 1 << uint(i)
		}
	}
	return set
}

// knownTokenPrefix is the fixed lead of a known token format. A stand-in
// keeps it whole even past the 8 characters reports show: github_pat_ whose
// "at_" was substituted (github_pct_…) matched no format any more.
var knownTokenPrefix = regexp.MustCompile(`^(?:github_pat_|sk-(?:proj|svcacct|admin)-|sk-ant-(?:api|admin)[0-9]{2}-|sk-ant-|sk-or-v1-|sk-lf-|sk-ak-|xox[abeprs]-|glpat-|gh[pousr]_|nvapi-|devin-|cog_|apk_user_|apk_|A[KS]IA|AIza|gsk_|hf_|xai-)`)

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
	// summed in a fixed order: values with the same frequency profile (a
	// value and its stand-in) get the very same number
	counts := make([]float64, 0, len(freq))
	for _, c := range freq {
		counts = append(counts, c)
	}
	sort.Float64s(counts)
	e := 0.0
	for _, c := range counts {
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
	// which known token formats it matches (API_KEY_PATTERNS and the extras)
	formats uint64
	// entropy against every threshold a check applies (3.5 ABA, 3.8 source
	// secrets, 4.5 GEM/QC/CC/HM/MCP — whitespace or not —, 5.5 memory files)
	entropyBand int
}

var entropyThresholds = []float64{3.5, 3.8, 4.5, 5.5}

func entropyBand(v string) int {
	e := shannonEntropy(authSchemePrefix.ReplaceAllString(strings.TrimSpace(v), ""))
	band := 0
	for _, t := range entropyThresholds {
		if e > t {
			band++
		}
	}
	return band
}

func verdictsOf(v string) secretVerdicts {
	return secretVerdicts{isPlaceholderSecret(v), isWeakCredential(v), isSecretReference(v), matchesAPIKey(v), highEntropySecret(v), tokenFormats(v), entropyBand(v)}
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
			// never the character itself: a stand-in shows none of the secret
			r := lo + byte(randIndex(int(hi-lo)))
			if r >= b[i] {
				r++
			}
			b[i] = r
		}
	}
	return string(b)
}

// substituteLike replaces the letters and digits of mid (shown: the rest of
// the value) through a random one-to-one mapping within each class, so the
// stand-in has the value's exact frequency profile — and so every entropy
// a check computes — and none of its hidden characters in place: a
// character the value shows anyway (in what reports keep, a kept CFG-009
// match, an escape) maps to itself, every other one to another character
// of its class. level picks how much of the layout stays when the value
// leaves few characters of a class unused:
//
//	0: classes 0-9 a-f g-z A-F G-Z (hex stays hex), unused characters only
//	1: the same classes, unused characters first, then the hidden
//	   characters themselves, permuted so none keeps its place
//	2, 3: as 0 and 1 over the classes 0-9 a-z A-Z
//
// ok is false when the level has no such mapping.
func substituteLike(shown, mid string, fixed []bool, level int) (string, bool) {
	keep := map[byte]bool{}
	for i := 0; i < len(mid); i++ {
		if fixed != nil && fixed[i] {
			keep[mid[i]] = true
		} else if mid[i] == '\\' {
			n := 1
			if i+1 < len(mid) && mid[i+1] == 'u' {
				n = 5
			}
			for j := i + 1; j <= i+n && j < len(mid); j++ {
				keep[mid[j]] = true
			}
			i += n
		}
	}
	// what lies outside mid (lead, the kept head and tail) is shown as is
	for i := 0; i < len(shown); i++ {
		keep[shown[i]] = true
	}
	used := map[byte]bool{}
	for _, part := range []string{shown, mid} {
		for i := 0; i < len(part); i++ {
			used[part[i]] = true
		}
	}
	classes := [][2]byte{{'0', '9'}, {'a', 'f'}, {'g', 'z'}, {'A', 'F'}, {'G', 'Z'}}
	if level >= 2 {
		classes = [][2]byte{{'0', '9'}, {'a', 'z'}, {'A', 'Z'}}
	}
	shuffle := func(b []byte) {
		for i := len(b) - 1; i > 0; i-- {
			j := randIndex(i + 1)
			b[i], b[j] = b[j], b[i]
		}
	}
	mapping := map[byte]byte{}
	for _, cl := range classes {
		var hidden, free []byte
		for ch := cl[0]; ch <= cl[1]; ch++ {
			if !used[ch] {
				free = append(free, ch)
			} else if !keep[ch] && strings.IndexByte(mid, ch) >= 0 {
				hidden = append(hidden, ch)
			}
		}
		if len(hidden) == 0 {
			continue
		}
		shuffle(free)
		shuffle(hidden)
		images := free
		if len(images) > len(hidden) {
			images = images[:len(hidden)]
		}
		if len(images) < len(hidden) {
			if level%2 == 0 {
				return "", false
			}
			// the rest of the images are hidden characters: a derangement
			// of them over what's left keeps the mapping one-to-one
			pool := append([]byte(nil), hidden...)
			shuffle(pool)
			images = append(append([]byte(nil), images...), pool[:len(hidden)-len(images)]...)
			for i := range hidden {
				if images[i] != hidden[i] {
					continue
				}
				swapped := false
				for j := range hidden {
					if j != i && images[j] != hidden[i] && images[i] != hidden[j] {
						images[i], images[j] = images[j], images[i]
						swapped = true
						break
					}
				}
				if !swapped {
					return "", false
				}
			}
		}
		for i, ch := range hidden {
			mapping[ch] = images[i]
		}
	}
	b := []byte(mid)
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
		if to, ok := mapping[b[i]]; ok {
			b[i] = to
		}
	}
	return string(b), true
}

// disguise returns a stand-in for a secret value that every check judges as
// it judges the value, or the value itself when it isn't worth hiding. The
// same value gets the same stand-in throughout one snapshot.
func (c *collector) disguise(v string) string {
	return c.disguiseAs(v, false)
}

// disguiseURLSecret disguises what a URL rule found in the place of a
// credential (a Zapier catch key, a webhook token): there, even all
// lowercase letters (a key enumLike would read as a setting) is the secret.
func (c *collector) disguiseURLSecret(v string) string {
	if c.disguised == nil {
		c.disguised = map[string]string{}
	}
	if _, ok := c.disguised[v]; !ok && enumLike.MatchString(v) && !isPlaceholderSecret(v) && !isSecretReference(v) {
		out := v
		for try := 0; try < 64 && out == v; try++ {
			if cand := randomLike(v, nil); verdictsOf(cand) == verdictsOf(v) {
				out = cand
			}
		}
		c.disguised[v] = out
		c.disguised[out] = out
	}
	out := c.disguise(v)
	// A %XX escape stays one (a level-2 substitution may map F to Q): the
	// TS rules read %XX as an escape, so a broken one changes their verdict
	if out != v && !sameEscapes(v, out) {
		for try := 0; try < 64; try++ {
			cand := randomLike(v, nil)
			if sameEscapes(v, cand) && verdictsOf(cand) == verdictsOf(v) && randomPathSegment(cand) == randomPathSegment(v) {
				out = cand
				break
			}
		}
		c.disguised[v] = out
		c.disguised[out] = out
	}
	return out
}

var percentEscape = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)

// sameEscapes: b has a %XX escape wherever a has one.
func sameEscapes(a, b string) bool {
	for _, loc := range percentEscape.FindAllStringIndex(a, -1) {
		if !percentEscape.MatchString(b[loc[0]:loc[1]]) {
			return false
		}
	}
	return true
}

// disguiseKeyed disguises a value found under key: under a password or
// secret name, a passphrase of lowercase words too (see passphraseLike).
func (c *collector) disguiseKeyed(key, v string) string {
	return c.disguiseAs(v, strongCredentialKey(key))
}

func (c *collector) disguiseAs(v string, passphrase bool) string {
	if d, ok := c.disguised[v]; ok {
		return d
	}
	lead, core := "", v
	if m := authSchemePrefix.FindStringIndex(v); m != nil {
		lead, core = v[:m[1]], v[m[1]:]
	}
	if !worthDisguising(core) && !(passphrase && passphraseLike(core)) {
		return v
	}
	pre, suf := keepBounds(len(core))
	if tokenFormats(core) != 0 {
		if p := len(knownTokenPrefix.FindString(core)); p > pre && p < len(core)-suf {
			pre = p
		}
	}
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
	// A one-to-one substitution keeps the character counts, so every entropy
	// any check computes — of the value, or of a string that holds it —
	// stays exactly as it was; each level keeps less of the class layout
	// and is tried only when the one before has no mapping or none that
	// keeps the other verdicts (a placeholder word, a key format).
	want := verdictsOf(v)
	out, first := "", ""
	for level := 0; level <= 3 && out == ""; level++ {
		for try := 0; try < 64 && out == ""; try++ {
			p, ok := substituteLike(lead+head+tail, mid, fixed, level)
			if !ok {
				break
			}
			cand := lead + head + p + tail
			if first == "" {
				first = cand
			}
			if verdictsOf(cand) == want {
				out = cand
			}
		}
	}
	// no mapping at all (one hidden character, nothing else free in its
	// class): random replacement, still judged like the value
	for try := 0; try < 64 && out == "" && first == ""; try++ {
		if cand := lead + head + randomLike(mid, fixed) + tail; verdictsOf(cand) == want {
			out = cand
		}
	}
	if out == "" {
		out = first
	}
	if out == "" {
		out = lead + head + randomLike(mid, fixed) + tail
	}
	if c.disguised == nil {
		c.disguised = map[string]string{}
	}
	c.disguised[v] = out
	c.disguised[out] = out // idempotent: a later pass over the same text keeps it
	return out
}

// strongCredentialKey: a key that names a password or secret itself
// (password, db_passwd, pwd, passphrase, client_secret, secretKey) — not one
// about it (password_policy, secret_file, auth_mode, token_type). Under such
// a key a lowercase passphrase is the credential, where elsewhere a
// lowercase-words value is a setting (auth: oauth-personal) and is kept.
var (
	strongCredentialWord = regexp.MustCompile(`(?:^|_)(?:password|passwd|pwd|passphrase|secret)(?:_|$)`)
	credentialAboutWord  = regexp.MustCompile(`_(?:mode|method|policy|url|uri|file|path|dir|id|arn|ref|name|type|hint|prompt|length|backend|store|provider|manager|source|format|algorithm|scheme|strategy|env|var)$`)
	passphraseWords      = regexp.MustCompile(`^[A-Za-z0-9]+(?:[-_ ][A-Za-z0-9]+){2,}$`)
)

func strongCredentialKey(key string) bool {
	k := strings.ToLower(camelBoundary.ReplaceAllString(key, "${1}_${2}"))
	k = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(strings.Trim(k, `"'`))
	return strongCredentialWord.MatchString(k) && !credentialAboutWord.MatchString(k)
}

// passphraseLike: a value under a strongCredentialKey that is a password even
// in lowercase words (correct-horse-battery-staple): 12+ characters or 3+
// words joined by - _ or space — never a reference, placeholder or URL.
func passphraseLike(v string) bool {
	if v == "" || strings.Contains(v, "://") || strings.ContainsAny(v, "\r\n") || strings.TrimSpace(v) != v {
		return false
	}
	if isPlaceholderSecret(v) || isSecretReference(v) || !strings.ContainsAny(strings.ToLower(v), "abcdefghijklmnopqrstuvwxyz0123456789") {
		return false
	}
	return len(v) >= 12 || passphraseWords.MatchString(v)
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
	// "key": "value" in JSON and JSONC; key: 'value', 'key': "value" in JSON5
	// (OpenClaw's openclaw.json) and YAML/TOML flow mappings. Groups: key
	// "…" (2), '…' (3) or bare (4); value "…" (6) or '…' (7).
	quotedPair = regexp.MustCompile(`(^|[\s{,\[])(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|([A-Za-z_$][A-Za-z0-9_$-]*))(\s*:\s*(?:/\*(?:[^*]|\*[^/])*\*/\s*)*)(?:"((?:[^"\\\r\n]|\\(?:.|\r?\n))*)"|'((?:[^'\\\r\n]|\\(?:.|\r?\n))*)')`)
	// key: | / key: >- with the value on the next, deeper-indented line (YAML block scalar)
	// a JSON(5) number value of 12+ digits, which a secret can be
	jsonNumber  = regexp.MustCompile(`(^|[\s{,])(["']?)([A-Za-z_$][A-Za-z0-9_$-]*)(["']?)(\s*:\s*)([0-9]{12,})`)
	yamlBlock   = regexp.MustCompile(`(?m)^([ \t]*)(?:-[ \t]+)?(["']?)([A-Za-z0-9_.-]+)(["']?)[ \t]*:[ \t]+[|>][-+0-9]*[ \t]*(?:#[^\r\n]*)?\r?\n([ \t]+)([^\s#][^\r\n]*?)[ \t]*(\r?\n|$)`)
	blockHeader = regexp.MustCompile(`:[ \t]+[|>]`)
	// ? key / : value (YAML explicit key)
	yamlExplicit = regexp.MustCompile(`(?m)^([ \t]*\?[ \t]+)(["']?)([A-Za-z0-9_.-]+)(["']?)([ \t]*\r?\n[ \t]*:[ \t]+)([^\r\n]*)$`)
	// key: value in YAML (block mappings, list items)
	yamlPair = regexp.MustCompile(`(?m)^([ \t]*(?:-[ \t]+)?)(["']?)([A-Za-z0-9_.-]+)(["']?)([ \t]*:[ \t]+)([^\r\n]*)$`)
	// one item of a YAML flow sequence
	flowItem = regexp.MustCompile(`([\[,][ \t]*)("(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^\s,\[\]{}"'#][^,\[\]{}\r\n]*)`)
	// &anchor and !tag properties ahead of a YAML scalar (token: &a v, secret: !!str v)
	yamlProps = regexp.MustCompile(`^(?:[&!][^\s]*[ \t]+)+`)
	// key = "value" in TOML (and inline tables), multi-line strings first
	tomlPair = regexp.MustCompile(`(^|[\s{,])([A-Za-z0-9_.-]+|"[^"\r\n]+")([ \t]*=[ \t]*)("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*')`)
	// scheme://user:password@ in URLs anywhere; the password runs to the
	// last @ before the host (WHATWG), never past what ends a URL in JSON/XML
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s:"']+:)([^/?#\s"'<>,{}]+)@`)
	// ?api_key=, &token= … in URLs anywhere
	urlCredParam = regexp.MustCompile(`([?&#;])([^=&#;\s"']+)=([^&#;\s"'<>]+)`)
	// "--api-key", "<value>" in an argv array; '…' in JSON5, plain in YAML.
	// Groups: flag (2); value "…" (5), '…' (6) or plain (7).
	argPair   = regexp.MustCompile(`(["']?)(--?[A-Za-z][A-Za-z0-9_-]*)(["']?)(\s*,\s*)(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|([^\s,\]}"'#][^\s,\]}"']*))`)
	flagValue = regexp.MustCompile(`(--?[A-Za-z][A-Za-z0-9_-]*)=([^\s"',;&|]+)`)
	// --api-key <value> in a command line (a hook, an MCP command string)
	flagSpace = regexp.MustCompile(`(^|[\s"'\[,(])(--?[A-Za-z][A-Za-z0-9_-]*)([ \t]+["']?)([^\s"'` + "`" + `,;&|<>\\]+)`)
	// curl -u user:password
	userFlag = regexp.MustCompile(`(^|[\s"'\[,])(-u|--user)([ \t]+["']?|=["']?)([^\s:"'@/]+:)([^\s"'` + "`" + `@,;&|<>\\]+)`)
	// KEY=value, key: value, Authorization: Bearer value anywhere in a line:
	// instruction and memory files (CLAUDE.md), command strings inside
	// configs ("OPENAI_API_KEY=… node x.js"), command output. A value ends
	// at whitespace, quotes and the punctuation that closes a structure. A
	// quote may be escaped, at any depth: password=\"…\" inside a JSON
	// string, \\\"api_key\\\":\\\"…\\\" in JSON embedded in one.
	inlinePair = regexp.MustCompile(`(^|[^A-Za-z0-9_.$-])([A-Za-z_][A-Za-z0-9_.-]*)(\\*["'` + "`" + `]?[ \t]*[:=][ \t]*)(\\+["']|["'` + "`" + `]?)((?i:bearer|basic|token)[ \t]+)?([^\s"'` + "`" + `<>{}\[\],;&@\\]+)`)
	// | API_KEY | <value> | in a markdown table, **API key**: <value>
	tableRow = regexp.MustCompile(`(?m)^([ \t]*\|[ \t]*(?:\*\*|` + "`" + `)?)([A-Za-z][A-Za-z0-9 _.-]{0,40}?)((?:\*\*|` + "`" + `)?[ \t]*\|[ \t]*` + "`" + `?)([^|` + "`" + `\s]+)(` + "`" + `?[ \t]*\|)`)
	boldKey  = regexp.MustCompile(`\*\*([A-Za-z][A-Za-z0-9 _.-]{0,40}?)(:?\*\*[ \t]*:?[ \t]*` + "`" + `?)([^\s` + "`" + `]+)`)
	// a Slack incoming-webhook URL's secret path segment
	slackWebhook = regexp.MustCompile(`(hooks\.slack\.com/(?:services|workflows|triggers)/(?:[A-Za-z0-9]+/)+)([A-Za-z0-9]{16,})`)
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
	if props := yamlProps.FindString(raw); props != "" && len(props) < len(raw) {
		open, value, rest := scalarValue(raw[len(props):])
		return props + open, value, rest
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

// tripleQuoted disguises a TOML multi-line string (triple-quoted) under
// a credential-named key when it holds one line: the secret.
func (c *collector) tripleQuoted(key, raw string) string {
	inner := raw[3 : len(raw)-3]
	lead := len(inner) - len(strings.TrimLeft(inner, "\r\n"))
	value := strings.TrimRight(inner[lead:], " \t\r\n")
	if !isSecretKeyName(key) || strings.ContainsAny(value, "\r\n") || !credentialLike(value) && !(strongCredentialKey(key) && passphraseLike(value)) {
		return raw
	}
	return raw[:3+lead] + c.disguiseKeyed(key, value) + raw[3+lead+len(value):]
}

// inlineSecret: what a value next to a credential-named key in free text
// must look like to be disguised — credentialLike and a digit in it, or
// random. Prose ("Token: Required", "password: see the vault") is left.
func inlineSecret(v string) bool {
	core := authSchemePrefix.ReplaceAllString(v, "")
	return credentialLike(core) && strings.ContainsAny(core, "0123456789") || highEntropySecret(core)
}

// nextLineDeeper: the line that follows continues a block indented by indent.
func nextLineDeeper(rest, indent string) bool {
	line := rest
	if i := strings.IndexByte(rest, '\n'); i >= 0 {
		line = rest[:i]
	}
	return strings.TrimSpace(line) != "" && strings.HasPrefix(line, indent)
}

// standaloneSecret: a table cell or a bold label's value that is a
// credential — one word, random, or 16+ characters with a digit in them.
func standaloneSecret(v string) bool {
	return highEntropySecret(v) || len(v) >= 16 && credentialLike(v) &&
		// a random 40-character key may have no digit, or fall under 4.5
		(strings.ContainsAny(v, "0123456789") || len(v) >= 20 && shannonEntropy(v) > 4.0)
}

// inlineSecrets finds KEY=value, key: value and "key": "value" in one line
// and hands each credential under a credential-named key to replace. A
// quoted value runs to its closing quote; an unquoted one, in free text
// (prose), to the end of the line (before a " #" comment or a closing
// quote), elsewhere to the end of the word. A pair that isn't one is
// searched again from its value ("command": "OPENAI_API_KEY=…").
func inlineSecrets(line string, prose bool, replace func(key, value string) (string, bool)) string {
	var b strings.Builder
	last, from := 0, 0
	for from < len(line) {
		loc := inlinePair.FindStringSubmatchIndex(line[from:])
		if loc == nil {
			break
		}
		g := make([]int, len(loc))
		for i, x := range loc {
			if x >= 0 {
				x += from
			}
			g[i] = x
		}
		m := submatch{line, g}
		key, _ := m.group(2)
		quote, _ := m.group(4)
		start, end := g[12], g[13]
		if g[10] >= 0 {
			start = g[10]
		}
		trigger := line[start:end]
		switch {
		case len(quote) >= 2:
			// \"…\" inside a JSON string (\\\"…\\\" a level deeper): up to
			// the same escaped quote
			if j := strings.Index(line[start:], quote); j >= 0 {
				end = start + j
				trigger = line[start:end]
			}
		case quote != "":
			if j := closingQuote(line, start, quote[0]); j >= 0 {
				end = j
				trigger = line[start:end]
			}
		case prose:
			rest := strings.TrimRight(line[start:], "\r\n")
			if i := strings.Index(rest, " #"); i >= 0 {
				rest = rest[:i]
			}
			if i := strings.IndexAny(rest, "\"`"); i >= 0 {
				rest = rest[:i]
			}
			end = start + len(strings.TrimRight(rest, " \t"))
			if end < g[13] {
				end = g[13]
			}
		}
		if isSecretKeyName(key) && (inlineSecret(trigger) ||
			// a quoted value is a literal, not prose: the structured rules' bar
			quote != "" && credentialLike(trigger) || strongCredentialKey(key) && passphraseLike(line[start:end]) &&
			// in free text a run of spaced words is a sentence (password: see the vault)
			!(prose && quote == "" && strings.Contains(line[start:end], " "))) {
			if out, ok := replace(key, line[start:end]); ok {
				b.WriteString(line[last:start])
				b.WriteString(out)
				last, from = end, end
				continue
			}
		}
		from = g[12]
	}
	b.WriteString(line[last:])
	return b.String()
}

// closingQuote returns the index of the quote closing a value that starts
// at start (a backslash escapes in double quotes), or -1 on this line.
func closingQuote(line string, start int, q byte) int {
	for i := start; i < len(line) && line[i] != '\n'; i++ {
		if line[i] == '\\' && q == '"' {
			i++
			continue
		}
		if line[i] == q {
			return i
		}
	}
	return -1
}

// secretHints: a key isSecretKeyName accepts holds one of these words.
var secretHints = []string{"key", "token", "secret", "pass", "credential", "auth", "cookie", "session", "jwt", "dsn", "bearer", "header", "signature", "pat"}

// onSecretLines applies f to the lines of s that hold one of the words
// (lower case; secretHints for the key patterns), leaving the rest as they
// are: the line patterns are slow, and most lines of a large file hold none.
func onSecretLines(s string, words []string, f func(string) string) string {
	var b strings.Builder
	lower := make([]byte, 0, 256)
	for len(s) > 0 {
		end := strings.IndexByte(s, '\n') + 1
		if end == 0 {
			end = len(s)
		}
		line := s[:end]
		s = s[end:]
		lower = lower[:0]
		for i := 0; i < len(line); i++ {
			ch := line[i]
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			lower = append(lower, ch)
		}
		hit := false
		for _, w := range words {
			if bytes.Contains(lower, []byte(w)) {
				hit = true
				break
			}
		}
		if hit {
			line = f(line)
		}
		b.WriteString(line)
	}
	return b.String()
}

// submatch is one regexp match with its submatch indexes into s.
type submatch struct {
	s string
	g []int
}

func (m submatch) text() string { return m.s[m.g[0]:m.g[1]] }

// group returns submatch n, and whether it took part in the match.
func (m submatch) group(n int) (string, bool) {
	if m.g[2*n] < 0 {
		return "", false
	}
	return m.s[m.g[2*n]:m.g[2*n+1]], true
}

// first returns the first of the alternative submatches that took part, and its number.
func (m submatch) first(ns ...int) (string, int) {
	for _, n := range ns {
		if v, ok := m.group(n); ok {
			return v, n
		}
	}
	return "", 0
}

// with returns the match with submatches from..to (adjacent, both taking
// part) replaced by repl.
func (m submatch) with(from, to int, repl string) string {
	return m.s[m.g[0]:m.g[2*from]] + repl + m.s[m.g[2*to+1]:m.g[1]]
}

// replaceMatches rewrites every match of re in s through f.
func replaceMatches(re *regexp.Regexp, s string, f func(submatch) string) string {
	var b strings.Builder
	last := 0
	for _, g := range re.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(s[last:g[0]])
		b.WriteString(f(submatch{s, g}))
		last = g[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// replacePairs is replaceMatches for key/value patterns whose value can hold
// the next pair ("command": "OPENAI_API_KEY=…", --verbose --api-key …): a
// match f declines (ok false) is searched again from its value, group v.
func replacePairs(re *regexp.Regexp, s string, v int, f func(submatch) (string, bool)) string {
	var b strings.Builder
	last, from := 0, 0
	for from <= len(s) {
		loc := re.FindStringSubmatchIndex(s[from:])
		if loc == nil {
			break
		}
		g := make([]int, len(loc))
		for i, x := range loc {
			if x >= 0 {
				x += from
			}
			g[i] = x
		}
		if out, ok := f(submatch{s, g}); ok {
			b.WriteString(s[last:g[0]])
			b.WriteString(out)
			last, from = g[1], g[1]
		} else if g[2*v] > g[0] {
			from = g[2*v]
		} else {
			from = g[1]
		}
		if g[1] == g[0] {
			from++
		}
	}
	b.WriteString(s[last:])
	return b.String()
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
	// free text (CLAUDE.md, notes): an unquoted keyed value runs to the end of its line
	prose := !dotenv && (ext == ".md" || ext == ".mdc" || ext == ".markdown" || ext == ".txt" || strings.HasSuffix(ext, "rules"))

	s = pemBody.ReplaceAllStringFunc(s, func(m string) string {
		g := pemBody.FindStringSubmatch(m)
		return g[1] + randomLike(g[2], nil) + g[3]
	})
	keyed := func(key, raw string) string {
		if !isSecretKeyName(key) {
			return raw
		}
		open, value, rest := scalarValue(raw)
		if !credentialLike(value) && !(strongCredentialKey(key) && passphraseLike(value)) {
			return raw
		}
		return open + c.disguiseKeyed(key, value) + rest
	}
	if dotenv {
		s = dotenvLine.ReplaceAllStringFunc(s, func(m string) string {
			g := dotenvLine.FindStringSubmatch(m)
			return g[1] + g[2] + g[3] + keyed(g[2], g[4])
		})
	}
	if jsonish || yaml || toml || dotenv {
		s = replaceMatches(quotedPair, s, func(m submatch) string {
			key, _ := m.first(2, 3, 4)
			vi := 6
			if _, ok := m.group(6); !ok {
				vi = 7
			}
			value, _ := m.group(vi)
			if !isSecretKeyName(key) || !credentialLike(value) && !(strongCredentialKey(key) && passphraseLike(value)) {
				return m.text()
			}
			return m.with(vi, vi, c.disguiseKeyed(key, value))
		})
	}
	if jsonish {
		// "client_secret": 1234…: an unquoted number under a secret name
		s = jsonNumber.ReplaceAllStringFunc(s, func(m string) string {
			g := jsonNumber.FindStringSubmatch(m)
			if g[2] != g[4] {
				return m
			}
			return g[1] + g[2] + g[3] + g[4] + g[5] + keyed(g[3], g[6])
		})
	}
	if yaml {
		s = yamlPair.ReplaceAllStringFunc(s, func(m string) string {
			g := yamlPair.FindStringSubmatch(m)
			if g[2] != g[4] {
				return m
			}
			if strings.HasPrefix(g[6], "[") && isSecretKeyName(g[3]) {
				// tokens: [a, "b"], a flow sequence of secrets
				return g[1] + g[2] + g[3] + g[4] + g[5] + replaceMatches(flowItem, g[6], func(m submatch) string {
					item, _ := m.group(2)
					return m.with(2, 2, keyed(g[3], item))
				})
			}
			return g[1] + g[2] + g[3] + g[4] + g[5] + keyed(g[3], g[6])
		})
		if strings.Contains(s, "? ") {
			s = yamlExplicit.ReplaceAllStringFunc(s, func(m string) string {
				g := yamlExplicit.FindStringSubmatch(m)
				if g[2] != g[4] {
					return m
				}
				return g[1] + g[2] + g[3] + g[4] + g[5] + keyed(g[3], g[6])
			})
		}
		if blockHeader.MatchString(s) {
			s = replaceMatches(yamlBlock, s, func(m submatch) string {
				indent, _ := m.group(1)
				deeper, _ := m.group(5)
				key, _ := m.group(3)
				value, _ := m.group(6)
				open, _ := m.group(2)
				closing, _ := m.group(4)
				// one line only: the block is the secret, not a multi-line document
				if open != closing || len(deeper) <= len(indent) || !strings.HasPrefix(deeper, indent) ||
					!isSecretKeyName(key) || !credentialLike(value) && !(strongCredentialKey(key) && passphraseLike(value)) || nextLineDeeper(m.s[m.g[1]:], deeper) {
					return m.text()
				}
				return m.with(6, 6, c.disguiseKeyed(key, value))
			})
		}
	}
	if toml {
		s = tomlPair.ReplaceAllStringFunc(s, func(m string) string {
			g := tomlPair.FindStringSubmatch(m)
			key := strings.Trim(g[2], `"`)
			if q := g[4][:1]; len(g[4]) >= 6 && strings.HasPrefix(g[4], strings.Repeat(q, 3)) {
				return g[1] + g[2] + g[3] + c.tripleQuoted(key, g[4])
			}
			return g[1] + g[2] + g[3] + keyed(key, g[4])
		})
	}
	if jsonish || yaml || toml {
		// "--api-key", "<value>" in an argv array (MCP server args)
		s = replaceMatches(argPair, s, func(m submatch) string {
			open, _ := m.group(1)
			closing, _ := m.group(3)
			flag, _ := m.group(2)
			value, vi := m.first(5, 6, 7)
			if open != closing || !isSecretFlag(flag) || !credentialLike(value) {
				return m.text()
			}
			return m.with(vi, vi, c.disguise(value))
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
	// --api-key <value>, -u user:<password>
	s = onSecretLines(s, secretHints, func(line string) string {
		return replacePairs(flagSpace, line, 4, func(m submatch) (string, bool) {
			flag, _ := m.group(2)
			value, _ := m.group(4)
			if !isSecretFlag(flag) || !credentialLike(value) {
				return "", false
			}
			return m.with(4, 4, c.disguise(value)), true
		})
	})
	s = onSecretLines(s, []string{"-u", "--user"}, func(line string) string {
		return replaceMatches(userFlag, line, func(m submatch) string {
			password, _ := m.group(5)
			if !credentialLike(password) {
				return m.text()
			}
			return m.with(5, 5, c.disguise(password))
		})
	})
	s = urlPassword.ReplaceAllStringFunc(s, func(m string) string {
		g := urlPassword.FindStringSubmatch(m)
		return g[1] + c.disguise(g[2]) + "@"
	})
	s = urlCredParam.ReplaceAllStringFunc(s, func(m string) string {
		g := urlCredParam.FindStringSubmatch(m)
		if !urlSecretParam(g[2]) {
			return m
		}
		return g[1] + g[2] + "=" + c.disguise(g[3])
	})
	s = slackWebhook.ReplaceAllStringFunc(s, func(m string) string {
		g := slackWebhook.FindStringSubmatch(m)
		return g[1] + c.disguise(g[2])
	})
	// capability URLs: Zapier/Discord path secrets, random path tokens
	s = replaceURLPathSecrets(s, c.disguiseURLSecret)
	// KEY=value and key: value in any text (CLAUDE.md, a command string in
	// a config): last, so what a structured rule disguised is kept as is
	s = onSecretLines(s, secretHints, func(line string) string {
		return inlineSecrets(line, prose, func(key, value string) (string, bool) {
			return c.disguiseKeyed(key, value), true
		})
	})
	if prose {
		s = onSecretLines(s, secretHints, func(line string) string {
			line = replaceMatches(tableRow, line, func(m submatch) string {
				key, _ := m.group(2)
				value, _ := m.group(4)
				if !isSecretKeyName(strings.TrimSpace(key)) || !standaloneSecret(value) {
					return m.text()
				}
				return m.with(4, 4, c.disguise(value))
			})
			return replaceMatches(boldKey, line, func(m submatch) string {
				key, _ := m.group(1)
				sep, _ := m.group(2)
				value, _ := m.group(3)
				if !strings.Contains(sep, ":") || !isSecretKeyName(key) || !standaloneSecret(value) {
					return m.text()
				}
				return m.with(3, 3, c.disguise(value))
			})
		})
	}
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

// URL path credentials, mirroring findUrlSecrets in src/mcp/config-secrets.ts:
// hosts whose path is the credential (Zapier MCP and catch hooks, Slack and
// Discord webhooks), Telegram bot tokens, and random or 32+ hex path tokens in any URL (a capability URL: whoever has
// it can use the server). Only the secret segment changes; scheme, host and
// the rest of the path stay for the checks.
var (
	urlText          = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>\\]+`)
	zapierSecretPath = regexp.MustCompile(`^/api/mcp/s/([^/?#]{8,})|^/mcp/([^/?#]{8,})/(?:sse|mcp)(?:$|[^A-Za-z0-9_])|^/hooks/catch/[^/?#]+/([^/?#]+)`)
	slackSecretPath  = regexp.MustCompile(`^/(?:services|workflows|triggers)/(?:[^/?#]+/)*([A-Za-z0-9]{16,})`)
	discordToken     = regexp.MustCompile(`^/api/webhooks/[^/?#]+/([^/?#]+)`)
	pathTokenRun     = regexp.MustCompile(`^[A-Za-z0-9_+=.~%-]+`)
	hexPathToken     = regexp.MustCompile(`^(?:[0-9a-f]{32,}|[0-9A-F]{32,})$`)
	telegramBotPath  = regexp.MustCompile(`^bot([0-9]{6,12}:[A-Za-z0-9_-]{30,})`)
	zapierHost       = regexp.MustCompile(`(?i)(?:^|\.)zapier\.com$`)
	slackHost        = regexp.MustCompile(`(?i)(?:^|\.)hooks\.slack\.com$`)
	discordHost      = regexp.MustCompile(`(?i)(?:^|\.)(?:discord|discordapp)\.com$`)
)

// randomPathSegment mirrors randomPathSegment in src/mcp/config-secrets.ts:
// 24+ letters and digits in both cases with near-maximal entropy (here also
// with . ~ and %-escapes in it: over-hiding keeps verdicts, the stand-in has
// the same classes and entropy).
func randomPathSegment(seg string) bool {
	if len(seg) < 24 {
		return false
	}
	// Wider than the TS detection (which also needs a digit): a random token
	// can lack one class, and a stand-in keeps its classes and entropy, so
	// disguising a segment the checks wouldn't flag changes no verdict.
	classes := 0
	for _, set := range []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789"} {
		if strings.ContainsAny(seg, set) {
			classes++
		}
	}
	if classes < 2 {
		return false
	}
	// and a lower entropy bar (TS: 4.5): a random 48-character token falls
	// under 4.5 now and then, and is still a token
	return shannonEntropy(seg) >= math.Min(4.0, math.Log2(float64(len(seg)))-0.8)
}

// replaceURLPathSecrets replaces each credential in a URL path through
// replace (disguise for files, redaction for command output).
func replaceURLPathSecrets(s string, replace func(string) string) string {
	return urlText.ReplaceAllStringFunc(s, func(u string) string {
		scheme := strings.Index(u, "://") + 3
		end := len(u)
		if i := strings.IndexAny(u[scheme:], "?#"); i >= 0 {
			end = scheme + i
		}
		slash := strings.IndexByte(u[scheme:end], '/')
		if slash < 0 {
			return u
		}
		pathStart := scheme + slash
		host := u[scheme:pathStart]
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			host = host[at+1:]
		}
		if colon := strings.IndexByte(host, ':'); colon >= 0 {
			host = host[:colon]
		}
		path := u[pathStart:end]
		b := []byte(u)
		var spans [][2]int // offsets within path
		var hostRe *regexp.Regexp
		switch {
		case zapierHost.MatchString(host):
			hostRe = zapierSecretPath
		case slackHost.MatchString(host):
			hostRe = slackSecretPath
		case discordHost.MatchString(host):
			hostRe = discordToken
		}
		if hostRe != nil {
			if g := hostRe.FindStringSubmatchIndex(path); g != nil {
				for i := 2; i+1 < len(g); i += 2 {
					if g[i] >= 0 {
						spans = append(spans, [2]int{g[i], g[i+1]})
					}
				}
			}
		}
		for off := 0; off < len(path); {
			next := strings.IndexByte(path[off+1:], '/')
			segEnd := len(path)
			if next >= 0 {
				segEnd = off + 1 + next
			}
			raw := path[off+1 : segEnd]
			seg := pathTokenRun.FindString(raw)
			covered := false
			for _, sp := range spans {
				covered = covered || (off+1 >= sp[0] && off+1 < sp[1])
			}
			switch {
			case covered:
			case telegramBotPath.MatchString(raw):
				// api.telegram.org/bot<id>:<secret>/sendMessage
				g := telegramBotPath.FindStringSubmatchIndex(raw)
				spans = append(spans, [2]int{off + 1 + g[2], off + 1 + g[3]})
			case randomPathSegment(seg) || hexPathToken.MatchString(seg):
				// the probe errs towards hiding: a 32+ hex token (a webhook
				// key, a commit hash) keeps its class, so verdicts hold
				spans = append(spans, [2]int{off + 1, off + 1 + len(seg)})
			}
			off = segEnd
		}
		// right to left: a replacement keeps the length, but stay safe
		sort.Slice(spans, func(i, j int) bool { return spans[i][0] > spans[j][0] })
		out := string(b)
		for _, sp := range spans {
			from, to := pathStart+sp[0], pathStart+sp[1]
			out = out[:from] + replace(out[from:to]) + out[to:]
		}
		return out
	})
}

// secretURLParamName: URL parameters that carry a credential though the
// env-name rule doesn't call them one (SECRET_PARAM in
// src/mcp/config-secrets.ts, plus signatures and session IDs).
var secretURLParamName = regexp.MustCompile(`(?i)^(?:auth|api[_-]?key|sig|signature|x-(?:amz|goog)-(?:signature|credential|security-token)|jsessionid|phpsessid|asp\.net_sessionid|sessionid|session_id|session|sid|key|pass|pwd|jwt|bearer|code|access_token|id_token|refresh_token)$`)

// urlSecretParam: a URL query, fragment or ;matrix parameter holding a credential.
func urlSecretParam(name string) bool {
	return isSecretJSONKey(name) || secretURLParamName.MatchString(name)
}
