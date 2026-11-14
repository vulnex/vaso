package main

import (
	"bytes"
	"crypto/rand"
	"math"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// isSecretReference mirrors isSecretReference in src/core/patterns.ts:
// env references, secret-manager and file references, profile names. They
// name where a secret lives, are what the checks read, and are kept. The
// pattern lists are TS's verbatim (TestReferencePatternsMatchTS).
var (
	authSchemePrefix = regexp.MustCompile(`(?i)^\s*(?:bearer|basic|token)\s+`)
	// ENV_REFERENCE_FORMS, in order; the form names drive envReferenceForm
	envReferenceForms = []string{
		`^\$\{(?:env|file):[^}]+\}$`,
		`^\{(?:env|file):[^}]+\}$`,
		`^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?[-=?+][^}]*)?\}$`,
		`^\$[A-Za-z_][A-Za-z0-9_]*$`,
		`(?i)^\$env:[A-Za-z_][A-Za-z0-9_]*$`,
		`^%[A-Za-z_][A-Za-z0-9_]*%$`,
		`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`,
	}
	envReferenceFormNames = []string{"env-colon", "brace-env", "dollar-brace", "dollar", "powershell", "percent", "name"}
	envReferenceFormRes   = func() []*regexp.Regexp {
		out := make([]*regexp.Regexp, len(envReferenceForms))
		for i, p := range envReferenceForms {
			out[i] = regexp.MustCompile(p)
		}
		return out
	}()
	// VARIABLE_NAME: how variables are named (UPPER_SNAKE, lower_snake, camel words)
	variableName      = regexp.MustCompile(`^(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*|[A-Za-z]?[a-z]+(?:[A-Z][a-z]+)*\d*)$`)
	firstIdentifier   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	powershellPrefix  = regexp.MustCompile(`(?i)^\$env:`)
	dollarBraceFallbk = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=?+](.*)\}$`)
	// SECRET_MANAGER_REFERENCE's alternatives (case-insensitive, as in TS)
	managerReferenceParts = []string{
		`^(?:op|vault|keychain|keyring|secret|secrets|gopass|lpass|bw|bws|doppler|infisical|azkv|gcpsm|awssm|sm|ssm|kms|sops|age)(?::\/\/|:)[^\s]+$`,
		`^ref\+[a-z0-9]+:\/\/\S+$`,
		`^arn:aws[\w-]*:(?:secretsmanager|ssm|kms):[\w-]*:\d*:\S+$`,
		`^projects\/[\w.-]+\/secrets\/[\w.-]+(?:\/versions\/[\w.-]+)?$`,
		`^https:\/\/[\w-]+\.vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net)\/secrets\/[\w-]+(?:\/\w+)?\/?$`,
		`^@Microsoft\.KeyVault\(.+\)$`,
		`^ENC\[[A-Z0-9_]+,data:.*\]$`,
	}
	managerReference = regexp.MustCompile(`(?i)` + strings.Join(managerReferenceParts, "|"))
	fileReferenceSrc = `^(?:~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]|^[\w.@-]+\.(?:json|pem|key|p8|p12|pfx|crt|cer|der|jks|keystore|txt|env|ya?ml|toml|ini|cfg|conf|gpg|asc|age|enc)$`
	fileReference    = regexp.MustCompile(`(?i)` + fileReferenceSrc)
	profileName      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)
	// a fallback written into ${VAR:-…} that is a credential all the same
	fallbackCredential = regexp.MustCompile(`^[^\s/]{16,}$`)
)

// envReferenceForm mirrors envReference in src/core/patterns.ts: the form
// when a value is wholly a reference to a variable or file, "" otherwise —
// `$Zx8f3kq…` is a password starting with `$`, and `${VAR:-<secret>}`
// stores the secret all the same.
func envReferenceForm(value string) string {
	v := strings.TrimSpace(authSchemePrefix.ReplaceAllString(value, ""))
	if v == "" || utf16Len(v) > 256 {
		return ""
	}
	form := ""
	for i, re := range envReferenceFormRes {
		if re.MatchString(v) {
			form = envReferenceFormNames[i]
			break
		}
	}
	if form == "name" && (utf16Len(v) > 64 || matchesAPIKey(v)) {
		return ""
	}
	if form != "" && form != "name" && form != "env-colon" && form != "brace-env" {
		if name := firstIdentifier.FindString(powershellPrefix.ReplaceAllString(v, "")); name != "" && !variableName.MatchString(name) {
			return ""
		}
	}
	if form == "dollar-brace" {
		if m := dollarBraceFallbk.FindStringSubmatch(v); m != nil && m[1] != "" && !isPlaceholderSecret(m[1]) &&
			(matchesAPIKey(m[1]) || fallbackCredential.MatchString(m[1]) && strings.ContainsAny(m[1], "0123456789") && containsASCIILetter(m[1])) {
			return ""
		}
	}
	return form
}

// utf16Len is a string's JavaScript length.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}

func containsASCIILetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

func isSecretReference(value string) bool {
	v := strings.TrimSpace(authSchemePrefix.ReplaceAllString(value, ""))
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return false
	}
	if envReferenceForm(v) != "" {
		return true
	}
	if matchesAPIKey(v) {
		return false
	}
	// a value that only starts like a path (a base64 secret starts with "/"
	// one time in 64) is judged by its shape, as in TS
	return managerReference.MatchString(v) || fileReference.MatchString(v) && (!pathPrefix.MatchString(v) || isPathValue(v)) || isProfileName(v)
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

// shannonEntropy is shannonEntropy in src/analyzers/entropy.ts to the last
// bit: characters counted by code point and summed in the order they first
// appear, over the string's JavaScript length, with V8's log2 (log2JS). A
// stand-in keeps the value's counts, so its entropy is the same number up to
// the order of the sum — which decides a verdict when the entropy sits on a
// threshold (log2(20) - 0.7 is the entropy of some 20-character values), so
// verdicts are judged on exactly what the CLI computes.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	index := map[rune]int{}
	var counts []float64
	for _, r := range s {
		if i, ok := index[r]; ok {
			counts[i]++
			continue
		}
		index[r] = len(counts)
		counts = append(counts, 1)
	}
	n := float64(utf16Len(s))
	e := 0.0
	for _, c := range counts {
		p := c / n
		e = e - float64(p*log2JS(p))
	}
	return e
}

// log2JS is V8's Math.log2 (fdlibm's e_log2.c, as in src/base/ieee754.cc),
// with no fused multiply-add, so the probe and the CLI get the same bits
// (TestLog2MatchesV8; Go's math.Log2 differs in the last bit for about one
// value in six).
func log2JS(x float64) float64 {
	const (
		two54   = 1.80143985094819840000e+16
		ivln2hi = 1.44269504072144627571e+00
		ivln2lo = 1.67517131648865118353e-10
		lg1     = 6.666666666666735130e-01
		lg2     = 3.999999999940941908e-01
		lg3     = 2.857142874366239149e-01
		lg4     = 2.222219843214978396e-01
		lg5     = 1.818357216161805012e-01
		lg6     = 1.531383769920937332e-01
		lg7     = 1.479819860511658591e-01
	)
	bits := math.Float64bits(x)
	hx, lx := int32(bits>>32), uint32(bits)
	k := int32(0)
	if hx < 0x00100000 {
		if (hx&0x7fffffff)|int32(lx) == 0 {
			return math.Inf(-1)
		}
		if hx < 0 {
			return math.NaN()
		}
		k -= 54
		x = float64(x * two54)
		bits = math.Float64bits(x)
		hx, lx = int32(bits>>32), uint32(bits)
	}
	if hx >= 0x7ff00000 {
		return x + x
	}
	if hx == 0x3ff00000 && lx == 0 {
		return 0
	}
	k += (hx >> 20) - 1023
	hx &= 0x000fffff
	i := (hx + 0x95f64) & 0x100000
	x = math.Float64frombits(uint64(uint32(hx|(i^0x3ff00000)))<<32 | uint64(lx))
	k += i >> 20
	y := float64(k)
	f := x - 1.0
	hfsq := float64(float64(0.5*f) * f)
	// k_log1p(f)
	sv := f / (2.0 + f)
	z := float64(sv * sv)
	w := float64(z * z)
	t1 := float64(w * float64(lg2+float64(w*float64(lg4+float64(w*lg6)))))
	t2 := float64(z * float64(lg1+float64(w*float64(lg3+float64(w*float64(lg5+float64(w*lg7)))))))
	r := float64(sv * float64(hfsq+float64(t2+t1)))
	hi := math.Float64frombits(math.Float64bits(f-hfsq) &^ 0xffffffff)
	lo := float64(f-hi) - hfsq + r
	valHi := float64(hi * ivln2hi)
	valLo := float64(float64(lo+hi)*ivln2lo) + float64(lo*ivln2hi)
	wv := y + valHi
	valLo += float64(y-wv) + valHi
	return valLo + wv
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
	// looksRandom (src/analyzers/secret-values.ts) at the lengths the checks
	// ask for, and its hex-key and UUID arms on their own
	random12, random16, hexKey, uuidTail bool
	// isPathValue: what isCredentialReference reads a "/…" value as
	pathValue bool
	// a password hash or digest ("Y$…" reads as yescrypt), a public value
	hashed, public bool
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
	core := strings.TrimSpace(authSchemePrefix.ReplaceAllString(v, ""))
	return secretVerdicts{isPlaceholderSecret(v), isWeakCredential(v), isSecretReference(v), matchesAPIKey(v), highEntropySecret(v), tokenFormats(v), entropyBand(v),
		looksRandom(core, 12), looksRandom(core, 16), hexKey.MatchString(core), uuidTail.MatchString(core), isPathValue(core),
		hashedValue.MatchString(core), publicValue.MatchString(core)}
}

// HASHED_VALUE and PUBLIC_VALUE in src/analyzers/secret-values.ts
// (TestValueShapesMatchTS): never a stored secret there, so a stand-in
// must not turn into one.
var (
	hashedValueSrc   = `^(?:[a-z][\w-]*\$)?\$?(?:2[abxy]?|argon2(?:id|i|d)?|scrypt|pbkdf2[\w-]*|[156y]|sha(?:256|512)-?crypt)\$|^(?:sha(?:1|224|256|384|512)|md5|blake2b?)[:=-][0-9a-f]{32,}$`
	hashedValue      = regexp.MustCompile(`(?i)` + hashedValueSrc)
	publicValueParts = []string{
		`^(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+AAAA`,
		`^-----BEGIN (?:(?:RSA |EC )?PUBLIC KEY|CERTIFICATE)-----`,
		`\.apps\.googleusercontent\.com$`,
		`^age1[0-9a-z]{50,}$`,
		`^pk_(?:live|test)_`,
		`^pk-lf-`,
	}
	publicValue = regexp.MustCompile(strings.Join(publicValueParts, "|"))
)

var (
	hexKey   = regexp.MustCompile(`^[0-9a-f]*[a-f][0-9a-f]*$|^[0-9A-F]*[A-F][0-9A-F]*$`)
	uuidTail = regexp.MustCompile(`(?i)(?:^|[-_])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	base36   = regexp.MustCompile(`(?i)^[a-z0-9]+$`)
)

// looksRandom mirrors looksRandom in src/analyzers/secret-values.ts (hex
// keys of 32+ there; any length here, which only tracks more).
func looksRandom(v string, minLength int) bool {
	if utf16Len(v) < minLength || strings.ContainsAny(v, " \t\r\n\v\f") {
		return false
	}
	if len(v) >= 32 && hexKey.MatchString(v) || uuidTail.MatchString(v) {
		return true
	}
	e := shannonEntropy(v)
	if utf16Len(v) >= 20 && e > 4.5 {
		return true
	}
	digits, upper, lower := 0, false, false
	for i := 0; i < len(v); i++ {
		switch b := v[i]; {
		case b >= '0' && b <= '9':
			digits++
		case b >= 'A' && b <= 'Z':
			upper = true
		case b >= 'a' && b <= 'z':
			lower = true
		}
	}
	if digits == 0 || !(upper || lower) {
		return false
	}
	if !(upper && lower) && (!base36.MatchString(v) || digits < 3 || len(v)-digits < 3) {
		return false
	}
	return e >= math.Min(4.5, math.Log2(float64(utf16Len(v)))-0.7)
}

// interpolation is a template reference to a dotted name (process.env.X).
var interpolation = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\}$`)

// enumLike values are settings, not secrets: oauth-personal, none, true.
var enumLike = regexp.MustCompile(`^[a-z][a-z._-]*$|^[0-9]{1,11}$`)

// worthDisguising: something a credential could be, that isn't already a
// placeholder, a reference, a URL or a PEM block.
func worthDisguising(core string) bool {
	if core == "" || enumLike.MatchString(core) || strings.Contains(core, "://") || strings.Contains(core, "-----BEGIN") {
		return false
	}
	// ${process.env.OPENAI_API_KEY}: an interpolation, which the CLI reads
	// as a reference (not ${Zx8f…}: no variable is named like a password)
	if m := interpolation.FindStringSubmatch(core); m != nil {
		named := true
		for _, part := range strings.Split(m[1], ".") {
			named = named && variableName.MatchString(part)
		}
		if named {
			return false
		}
	}
	// judged as the CLI reads it: "\u0041…" in a JSON string is "A…", no path
	judged := unescapeValue(core)
	if isPlaceholderSecret(judged) || isSecretReference(judged) {
		return false
	}
	for i := 0; i < len(core); i++ {
		if isASCIIAlnum(core[i]) {
			return true
		}
	}
	return false
}

// pathPrefix is PATH_PREFIX in src/core/patterns.ts.
var (
	pathPrefix    = regexp.MustCompile(`^(?:~|\.{1,2})?[/\\]|^[A-Za-z]:[/\\]`)
	pathSplit     = regexp.MustCompile(`[/\\]+`)
	segmentExt    = regexp.MustCompile(`\.[A-Za-z0-9]{1,8}$`)
	segmentChars  = regexp.MustCompile(`^[A-Za-z0-9+=_-]+$`)
	wordSegment   = regexp.MustCompile(`^\.?(?:[a-z]{2,}|[A-Z][a-z]+|[A-Z]{2,})(?:[._-][A-Za-z0-9]+)*$`)
	segmentDashes = regexp.MustCompile(`[-_]`)
)

// isPathValue mirrors isPathValue in src/core/patterns.ts: a value that
// starts like a path and is one by its shape — a base64 secret starts with
// "/" one time in 64. Such a secret keeps its leading "/" in the stand-in,
// so it is disguised and still judged a file reference where the CLI does.
func isPathValue(value string) bool {
	v := strings.TrimSpace(value)
	if !pathPrefix.MatchString(v) {
		return false
	}
	var segments []string
	for _, seg := range pathSplit.Split(pathPrefix.ReplaceAllString(v, ""), -1) {
		if seg != "" {
			segments = append(segments, seg)
		}
	}
	random := false
	for _, seg := range segments {
		random = random || randomSegment(seg)
	}
	if !random {
		return true
	}
	if len(segments) < 3 {
		return false
	}
	for _, seg := range segments {
		if wordSegment.MatchString(seg) {
			return true
		}
	}
	return false
}

// randomSegment mirrors randomSegment in src/core/patterns.ts.
func randomSegment(segment string) bool {
	s := segmentExt.ReplaceAllString(segment, "")
	if len(s) < 12 || !segmentChars.MatchString(s) {
		return false
	}
	if !strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz") || !strings.ContainsAny(s, "0123456789") {
		return false
	}
	words := true
	for _, p := range segmentDashes.Split(s, -1) {
		words = words && splitsIntoWords(p)
	}
	if words {
		return false
	}
	return shannonEntropy(s) >= math.Min(4, math.Log2(float64(len(s)))-0.8)
}

// splitsIntoWords is /^(?:[A-Z]?[a-z]{2,}|[A-Z]{2,}(?![a-z])|\d+)*$/ (RE2
// has no lookahead): which prefixes of p a run of such words can cover.
func splitsIntoWords(p string) bool {
	isUpper := func(i int) bool { return i < len(p) && p[i] >= 'A' && p[i] <= 'Z' }
	isLower := func(i int) bool { return i < len(p) && p[i] >= 'a' && p[i] <= 'z' }
	isDigit := func(i int) bool { return i < len(p) && p[i] >= '0' && p[i] <= '9' }
	reach := make([]bool, len(p)+1)
	reach[0] = true
	for i := 0; i < len(p); i++ {
		if !reach[i] {
			continue
		}
		// [A-Z]?[a-z]{2,}
		for _, s := range []int{i, i + 1} {
			if s == i+1 && !isUpper(i) {
				continue
			}
			for j := s; isLower(j); j++ {
				if j-s+1 >= 2 {
					reach[j+1] = true
				}
			}
		}
		// [A-Z]{2,} not followed by a lowercase letter
		for j := i; isUpper(j); j++ {
			if j-i+1 >= 2 && !isLower(j+1) {
				reach[j+1] = true
			}
		}
		// \d+
		for j := i; isDigit(j); j++ {
			reach[j+1] = true
		}
	}
	return reach[len(p)]
}

// unescapeValue decodes the backslash escapes of a JSON/TOML/YAML
// double-quoted string (\uXXXX, \/, \", \n …) for judging; a value without
// a backslash is returned as is.
func unescapeValue(v string) string {
	if !strings.Contains(v, "\\") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '\\' || i+1 >= len(v) {
			b.WriteByte(v[i])
			continue
		}
		i++
		switch v[i] {
		case 'u':
			if i+4 < len(v) {
				if n, err := strconv.ParseUint(v[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(n))
					i += 4
					continue
				}
			}
			b.WriteString("\\u")
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b', 'f':
			b.WriteByte(' ')
		default:
			b.WriteByte(v[i])
		}
	}
	return b.String()
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

// standInLayout returns, for each byte of s, the class it is drawn from in
// a stand-in (lo..hi; ok false where the byte stays: punctuation, kept
// positions, the bytes of a backslash escape). Within each run of free
// letters and digits between separators (- . _ : / and the like, which stay
// in place and keep a format's structure) the classes of the run are
// shuffled: a stand-in shows how many characters of each class the value
// had, never which position held which (a hex key's digit/letter layout was
// worth about one bit a character).
func standInLayout(s string, fixed []bool, classes [][2]byte) [][2]byte {
	layout := make([][2]byte, len(s))
	classOf := func(b byte) ([2]byte, bool) {
		for _, cl := range classes {
			if b >= cl[0] && b <= cl[1] {
				return cl, true
			}
		}
		return [2]byte{}, false
	}
	var run []int
	flush := func() {
		var cls [][2]byte
		for _, i := range run {
			cls = append(cls, layout[i])
		}
		for i := len(cls) - 1; i > 0; i-- {
			j := randIndex(i + 1)
			cls[i], cls[j] = cls[j], cls[i]
		}
		for k, i := range run {
			layout[i] = cls[k]
		}
		run = run[:0]
	}
	for i := 0; i < len(s); i++ {
		if fixed != nil && fixed[i] {
			flush()
			continue
		}
		if s[i] == '\\' {
			flush()
			if i+1 < len(s) && s[i+1] == 'u' {
				i += 5
			} else {
				i++
			}
			continue
		}
		cl, ok := classOf(s[i])
		if !ok {
			flush()
			continue
		}
		layout[i] = cl
		run = append(run, i)
	}
	flush()
	return layout
}

var (
	fineClasses   = [][2]byte{{'0', '9'}, {'a', 'f'}, {'g', 'z'}, {'A', 'F'}, {'G', 'Z'}}
	coarseClasses = [][2]byte{{'0', '9'}, {'a', 'z'}, {'A', 'Z'}}
)

// randomLike replaces each ASCII letter and digit with a character drawn
// uniformly from a class of standInLayout — the original character as
// likely as any other: excluding it gave it away over a few snapshots. A
// backslash escape (\n, \", é inside a JSON/TOML/YAML string) is copied
// whole so the file stays valid.
func randomLike(s string, fixed []bool) string {
	layout := standInLayout(s, fixed, fineClasses)
	b := []byte(s)
	for i, cl := range layout {
		if cl[1] != 0 {
			b[i] = cl[0] + byte(randIndex(int(cl[1]-cl[0])+1))
		}
	}
	return string(b)
}

// base64Alphabet is what a PEM body is written in.
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// randomBase64 replaces every base64 character of a PEM body with one drawn
// uniformly from the whole alphabet (no check reads the body; the header and
// footer are the finding). Escapes and line breaks stay.
func randomBase64(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' {
			if i+1 < len(b) && b[i+1] == 'u' {
				i += 5
			} else {
				i++
			}
			continue
		}
		if strings.IndexByte(base64Alphabet, b[i]) >= 0 {
			b[i] = base64Alphabet[randIndex(len(base64Alphabet))]
		}
	}
	return string(b)
}

// arrangeLike draws a stand-in for mid (the hidden part of a value; shown:
// what stays of it — the kept head and tail, kept CFG-009 matches, escapes —
// and lead, an auth scheme before it). Each free letter or digit gets a
// class from standInLayout (0-9 a-f g-z A-F G-Z: a hex key stays hex; coarse:
// 0-9 a-z A-Z) and a character of that class, with the counts the whole
// value had: a random bijection of each class's characters keeps each total
// — a character shown k times takes the total of one shown at most that
// often — and the hidden copies are then laid out at random. So every
// entropy a check computes stays the same number, while no character's
// place, which character it was, or its class at that place survives.
func arrangeLike(lead, shown, mid string, fixed []bool, coarse bool) string {
	classes := fineClasses
	if coarse {
		classes = coarseClasses
	}
	layout := standInLayout(mid, fixed, classes)
	shownCount := map[byte]int{}
	for i := 0; i < len(shown); i++ {
		shownCount[shown[i]]++
	}
	hidden := map[byte]int{}
	for i := 0; i < len(mid); i++ {
		if layout[i][1] != 0 {
			hidden[mid[i]]++
		} else {
			shownCount[mid[i]]++
		}
	}
	leadCount := map[byte]int{}
	for i := 0; i < len(lead); i++ {
		leadCount[lead[i]]++
	}
	out := []byte(mid)
	for _, cl := range classes {
		var positions []int
		for i := range layout {
			if layout[i] == cl {
				positions = append(positions, i)
			}
		}
		if len(positions) == 0 {
			continue
		}
		// a bijection within each lead-count group: t takes the total of s
		// when t is shown no more often than s's total
		groups := map[int][]byte{}
		for ch := cl[0]; ch <= cl[1]; ch++ {
			groups[leadCount[ch]] = append(groups[leadCount[ch]], ch)
		}
		var pool []byte
		for _, syms := range groups {
			targets := append([]byte(nil), syms...)
			// most-shown first: the eligible sources of each are a subset of
			// the next one's, so a random pick never runs out
			shuffleBytes(targets)
			sort.SliceStable(targets, func(i, j int) bool { return shownCount[targets[i]] > shownCount[targets[j]] })
			sources := append([]byte(nil), syms...)
			for _, t := range targets {
				var eligible []int
				for k, src := range sources {
					if shownCount[src]+hidden[src] >= shownCount[t] {
						eligible = append(eligible, k)
					}
				}
				k := eligible[randIndex(len(eligible))]
				src := sources[k]
				sources = append(sources[:k], sources[k+1:]...)
				for n := shownCount[src] + hidden[src] - shownCount[t]; n > 0; n-- {
					pool = append(pool, t)
				}
			}
		}
		shuffleBytes(pool)
		for k, i := range positions {
			out[i] = pool[k]
		}
	}
	return string(out)
}

func shuffleBytes(b []byte) {
	for i := len(b) - 1; i > 0; i-- {
		j := randIndex(i + 1)
		b[i], b[j] = b[j], b[i]
	}
}

// relocateWeak returns mid with the CFG-009 match sp (core offsets; -1: none)
// moved to a random start inside its run of letters and digits, never
// touching the kept head or tail, and which positions of the result hold it.
// A match the kept head already shows part of (xoxb-123|4567890…), or one
// whose run leaves no room, stays where it is; ok is false when it lies
// wholly outside mid.
func relocateWeak(core, mid string, pre, suf int, sp [2]int) (string, []bool, bool) {
	fixed := make([]bool, len(mid))
	if sp[0] < 0 {
		return mid, fixed, true
	}
	end := len(core) - suf
	inPlace := func() (string, []bool, bool) {
		any := false
		for i := sp[0]; i < sp[1]; i++ {
			if i >= pre && i < end {
				fixed[i-pre] = true
				any = true
			}
		}
		return mid, fixed, any
	}
	if sp[0] < pre || sp[1] > end {
		return inPlace()
	}
	ra, rb := sp[0], sp[1]
	for ra > pre && isASCIIAlnum(core[ra-1]) {
		ra--
	}
	for rb < end && isASCIIAlnum(core[rb]) {
		rb++
	}
	// at least two characters from the head and tail: one drawn character
	// between them may match by chance, and the run would then extend it
	n := sp[1] - sp[0]
	lo, hi := ra, rb-n
	if lo < pre+2 {
		lo = pre + 2
	}
	if hi > end-n-2 {
		hi = end - n - 2
	}
	if lo > hi {
		return inPlace()
	}
	t := lo + randIndex(hi-lo+1)
	// the run without the match, the match put back at t
	rest := core[ra:sp[0]] + core[sp[1]:rb]
	run := rest[:t-ra] + core[sp[0]:sp[1]] + rest[t-ra:]
	b := []byte(mid)
	copy(b[ra-pre:], run)
	for i := t; i < t+n; i++ {
		fixed[i-pre] = true
	}
	return string(b), fixed, true
}

// weakSpans are the CFG-009 matches in core that may stay in place to keep
// the weak verdict, the ones clear of the kept head and tail and the
// shortest first: one is enough, and a run next to the head ("LimaMike" +
// "0123456789") would show more of the value than reports do.
func weakSpans(core string, pre, suf int) [][2]int {
	seen := map[[2]int]bool{}
	var spans [][2]int
	add := func(a, b int) {
		if a < b && !seen[[2]int{a, b}] {
			seen[[2]int{a, b}] = true
			spans = append(spans, [2]int{a, b})
		}
	}
	for _, re := range weakRes {
		for _, loc := range re.FindAllStringIndex(core, -1) {
			add(loc[0], loc[1])
		}
		// shorter matches inside a run ("12345678" in "0123456789")
		if len(core) <= 256 {
			for i := 1; i < len(core); i++ {
				if loc := re.FindStringIndex(core[i:]); loc != nil {
					add(i+loc[0], i+loc[1])
				}
			}
		}
	}
	end := len(core) - suf
	clear := func(sp [2]int) bool { return sp[0] > pre && sp[1] < end }
	sort.SliceStable(spans, func(i, j int) bool {
		if ci, cj := clear(spans[i]), clear(spans[j]); ci != cj {
			return ci
		}
		return spans[i][1]-spans[i][0] < spans[j][1]-spans[j][0]
	})
	return spans
}

// disguise returns a stand-in for a secret value that every check judges as
// it judges the value, or the value itself when it isn't worth hiding. The
// same value gets the same stand-in throughout one snapshot.
func (c *collector) disguise(v string) string {
	return c.disguiseAs(v, false, false)
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

// disguiseArgv disguises what a command-line rule found: a password after
// mysql -p or sshpass -p is one even as a lowercase word.
func (c *collector) disguiseArgv(v string) string {
	out := c.disguiseAs(v, true, true)
	if out != v || isPlaceholderSecret(v) || isSecretReference(v) {
		return out
	}
	// what the argv rules call a password is one, however plain (appdb,
	// 8-digit numbers): a random stand-in of its classes, judged like it
	for try := 0; try < 64 && out == v; try++ {
		if cand := randomLike(v, nil); cand != v && verdictsOf(cand) == verdictsOf(v) {
			out = cand
		}
	}
	if c.disguised == nil {
		c.disguised = map[string]string{}
	}
	c.disguised[v] = out
	c.disguised[out] = out
	return out
}

// disguiseKeyed disguises a value found under key: under a password or
// secret name, a passphrase of lowercase words too (see passphraseLike).
func (c *collector) disguiseKeyed(key, v string) string {
	return c.disguiseAs(v, strongCredentialKey(key), true)
}

// disguiseAs: passphrase — under a password name, where a passphrase, a PIN
// or a lowercase word is the credential; keyed — under any credential name,
// where an all-lowercase random key is one.
func (c *collector) disguiseAs(v string, passphrase, keyed bool) string {
	if d, ok := c.disguised[v]; ok {
		if c.inFile != nil && d != v {
			c.inFile[v] = d
		}
		return d
	}
	lead, core := "", v
	if m := authSchemePrefix.FindStringIndex(v); m != nil {
		lead, core = v[:m[1]], v[m[1]:]
	}
	if !worthDisguising(core) && !(passphrase && passphraseLike(core)) && !(keyed && lowercaseToken(core)) {
		return v
	}
	pre, suf := keepBounds(len(core))
	if tokenFormats(core) != 0 {
		if p := len(knownTokenPrefix.FindString(core)); p > pre && p < len(core)-suf {
			pre = p
		}
	}
	head, mid, tail := core[:pre], core[pre:len(core)-suf], core[len(core)-suf:]
	// Every verdict a check reaches must hold for the stand-in (drawn again
	// until it does, a bounded number of times); a CFG-009 match
	// ("12345678", "password") that makes the value weak stays, one match
	// only, moved to a random place of its run clear of the kept head and
	// tail — next to the head it would show more of the value than reports do.
	want := verdictsOf(v)
	spans := [][2]int{{-1, -1}}
	if want.weak {
		spans = append(weakSpans(core, pre, suf), spans...)
		if len(spans) > 6 {
			spans = append(spans[:5], [2]int{-1, -1})
		}
	}
	out := ""
	for _, coarse := range []bool{false, true} {
		for _, sp := range spans {
			for try := 0; try < 24 && out == ""; try++ {
				m, fixed, ok := relocateWeak(core, mid, pre, suf, sp)
				if !ok {
					break
				}
				if cand := lead + head + arrangeLike(lead, head+tail, m, fixed, coarse) + tail; verdictsOf(cand) == want {
					out = cand
				}
			}
			if out != "" {
				break
			}
		}
		if out != "" {
			break
		}
	}
	// no arrangement keeps every verdict: an independent random character of
	// each class, still judged like the value
	for try := 0; try < 64 && out == ""; try++ {
		if cand := lead + head + randomLike(mid, nil) + tail; verdictsOf(cand) == want {
			out = cand
		}
	}
	if out == "" {
		out = lead + head + randomLike(mid, nil) + tail
	}
	if c.disguised == nil {
		c.disguised = map[string]string{}
	}
	c.disguised[v] = out
	c.disguised[out] = out // idempotent: a later pass over the same text keeps it
	if c.inFile != nil {
		c.inFile[v] = out
	}
	return out
}

// strongCredentialKey: a key that names a password or secret itself
// (password, db_passwd, pwd, passphrase, client_secret, secretKey) — not one
// about it (password_policy, secret_file, auth_mode, token_type). Under such
// a key a lowercase passphrase is the credential, where elsewhere a
// lowercase-words value is a setting (auth: oauth-personal) and is kept.
var (
	strongCredentialWord = regexp.MustCompile(`(?:^|_)(?:password|passwd|pwd|passphrase|secret|pin|passcode)\d*(?:_|$)`)
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
	// a PIN or numeric password (4821, 84736251); a single lowercase word
	// that isn't a setting (hunter2abc, correcthorse)
	if pinLike.MatchString(v) || lowerWord.MatchString(v) && !passwordSetting.MatchString(v) {
		return true
	}
	return len(v) >= 12 || passphraseWords.MatchString(v)
}

var (
	pinLike         = regexp.MustCompile(`^[0-9]{4,}$`)
	lowerWord       = regexp.MustCompile(`^[a-z][a-z0-9]{5,}$`)
	passwordSetting = regexp.MustCompile(`^(?:none|null|disabled?|enabled?|required|optional|prompt|keychain|keyring|default|inherit|system|unset|empty|random|generated?|interactive|manual|automatic|auto)$`)
	lowercaseKey    = regexp.MustCompile(`^[a-z0-9]{24,}$`)
)

// lowercaseToken: an all-lowercase random key (24+ letters and digits)
// under a credential name, which credentialLike's marker misses.
func lowercaseToken(v string) bool {
	return lowercaseKey.MatchString(v) && !pinLike.MatchString(v) && shannonEntropy(v) > 3.5
}

// isSecretKeyName: a settings key whose value is a credential — the probe's
// env-name rule (apiKey → API_KEY) or CLI's SECRET_KEY_NAME (src/core/secret-values.ts).
var secretKeyName = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|credential|private[_-]?key|auth(?:orization)?$|(?:^|[_\s-])(?:pw|pin)$)`)

// credentialLike: what a value under a credential-named key must look like
// to be disguised — 8+ characters with a digit, a capital or a symbol. A
// short setting under a token-ish key ("tokenizer": "cl100k") is left alone.
var credentialMarker = regexp.MustCompile(`[0-9A-Z!-/:-@\[-` + "`" + `{-~]`)

func credentialLike(v string) bool {
	core := authSchemePrefix.ReplaceAllString(v, "")
	return len(core) >= 8 && credentialMarker.MatchString(core) || lowercaseToken(core)
}

// looksLikeSecret is looksLikeSecret in src/mcp/config-secrets.ts.
func looksLikeSecret(v string) bool {
	if utf16Len(v) < 12 || strings.ContainsAny(v, " \t\r\n\v\f") {
		return false
	}
	if !containsASCIILetter(v) || !strings.ContainsAny(v, "0123456789") {
		return utf16Len(v) >= 20 && shannonEntropy(v) > 3.5
	}
	return shannonEntropy(v) > 3
}

// flagTakesCredential: value, after flag, is a credential to disguise. A
// value never starts with "-" (that is the next flag: "--no-auth",
// "--api-key", X). -k is a key for some tools and "insecure" for curl: as in
// the report masker (randomKey in src/reporting/serialize.ts), only a
// random-looking value after it is one.
func flagTakesCredential(flag, value string) bool {
	if flagShaped(value) {
		return false
	}
	if flag == "-k" {
		return randomKey(value)
	}
	return isSecretFlag(flag) && credentialLike(value)
}

// isSecretFlag: --token, --api-key, --password … (not --keyboard)
func isSecretFlag(flag string) bool {
	return isSecretKeyName(strings.TrimLeft(flag, "-"))
}

func isSecretKeyName(key string) bool {
	return secretKeyName.MatchString(key) || isSecretJSONKey(key)
}

var (
	// KEY=value lines of a dotenv file (commented-out ones too: they leak alike)
	dotenvLine = regexp.MustCompile(`(?m)^(\x{FEFF}?[ \t]*#?[ \t]*(?:export[ \t]+)?)([A-Za-z_][A-Za-z0-9_.-]*)([ \t]*=[ \t]*)([^\r\n]*)(\r?)$`)
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
	yamlExplicit = regexp.MustCompile(`(?m)^([ \t]*\?[ \t]+)(["']?)([A-Za-z0-9_.-]+)(["']?)([ \t]*\r?\n[ \t]*:[ \t]+)([^\r\n]*)(\r?)$`)
	// key: value in YAML (block mappings, list items); a CRLF line's \r and a
	// BOM stay outside the value
	yamlPair = regexp.MustCompile(`(?m)^(\x{FEFF}?[ \t]*(?:-[ \t]+)?)(["']?)([A-Za-z0-9_.-]+)(["']?)([ \t]*:[ \t]+)([^\r\n]*)(\r?)$`)
	// key: value inside a YAML flow mapping (tokens: {primary: …})
	flowPair = regexp.MustCompile(`([{,][ \t]*)(["']?)([A-Za-z0-9_.-]+)(["']?)([ \t]*:[ \t]*)("(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^\s,\[\]{}"'#][^,\[\]{}\r\n]*)`)
	// one item of a YAML flow sequence
	flowItem = regexp.MustCompile(`([\[,][ \t]*)("(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^\s,\[\]{}"'#][^,\[\]{}\r\n]*)`)
	// &anchor and !tag properties ahead of a YAML scalar (token: &a v, secret: !!str v)
	yamlProps = regexp.MustCompile(`^(?:[&!][^\s]*[ \t]+)+`)
	// key = "value" in TOML (and inline tables), multi-line strings first
	tomlPair = regexp.MustCompile(`(^|[\s{,])((?:[A-Za-z0-9_-]+|"[^"\r\n]+"|'[^'\r\n]+')(?:[ \t]*\.[ \t]*(?:[A-Za-z0-9_-]+|"[^"\r\n]+"|'[^'\r\n]+'))*)([ \t]*=[ \t]*)("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*')`)
	// scheme://user:password@ in URLs anywhere; the password runs to the
	// last @ before the host (WHATWG), never past what ends a URL in JSON/XML
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s:"']*:)([^/?#\s"'<>,{}]+)@`)
	// scheme://<token>@ — a token as the user name, no password (Sentry DSNs)
	urlUserToken = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)([^/?#@\s:"'<>,{}]{16,})(:?)@`)
	// a port or port mapping (-p 8080:80), never a password
	portLike = regexp.MustCompile(`^\d+(?::\d+)*(?:/(?:tcp|udp))?$|^[\d.]+:\d+(?::\d+)?$`)
	// ?api_key=, &token= … in URLs anywhere
	urlCredParam = regexp.MustCompile(`([?&#;])([^=&#;\s"']+)=([^&#;\s"'<>]+)`)
	// "--api-key", "<value>" in an argv array; '…' in JSON5, plain in YAML.
	// Groups: flag (2); value "…" (5), '…' (6) or plain (7).
	argPair = regexp.MustCompile(`(["']?)(--?[A-Za-z][A-Za-z0-9_-]*)(["']?)(\s*,\s*)(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|([^\s,\]}"'#][^\s,\]}"']*))`)
	// --api-key=<value>; a header line as the value may have a space after
	// its colon (--header=Authorization: Bearer <value>)
	flagValue = regexp.MustCompile(`(--?[A-Za-z][A-Za-z0-9_-]*)=((?:[A-Za-z][A-Za-z0-9-]*:[ \t]+(?:(?i:bearer|basic|token)[ \t]+)?)?[^\s"',;&|]+)`)
	// --password "two words", --token='<value>'
	// (the quotes escaped inside a JSON string: --password \"two words\")
	flagQuoted = regexp.MustCompile(`(--?[A-Za-z][A-Za-z0-9_-]*)([ \t]+|=)(\\*["'])([^"'\\\r\n]+)(\\*["'])`)
	// a URL whose fragment is a bare token (…/mcp#<token>); #name=value
	// pairs are urlCredParam's, each value judged as a query parameter's
	urlFragment = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>#]*#)([A-Za-z0-9_.~%+/-]{16,}=*)($|[^A-Za-z0-9_.~%+/=&-])`)
	// a header line in a flag's value (--header=X-Api-Key:<value>)
	headerName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*:`)
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
	inlinePair = regexp.MustCompile(`(^|[^A-Za-z0-9_.$-])([A-Za-z_][A-Za-z0-9_.-]*)(\\*["'` + "`" + `]?[ \t]*[:=][ \t]*)(\\+["']|["'` + "`" + `]?)((?i:bearer|basic|token)[ \t]+)?((?:[^\s"'` + "`" + `<>{}\[\],;&\\]|\\/|\\u[0-9A-Fa-f]{4}|\\\\)+)`)
	// the same in free text, where a name may be up to three words
	// (Token del servidor: …, password for prod: …)
	inlinePairProse = regexp.MustCompile(`(^|[^A-Za-z0-9_.$-])([A-Za-z_][A-Za-z0-9_.-]*(?:[ \t][A-Za-z][A-Za-z0-9_.-]*){0,2})(\\*["'` + "`" + `]?[ \t]*[:=][ \t]*)(\\+["']|["'` + "`" + `]?)((?i:bearer|basic|token)[ \t]+)?((?:[^\s"'` + "`" + `<>{}\[\],;&\\]|\\/|\\u[0-9A-Fa-f]{4}|\\\\)+)`)
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
			// '' is a quote inside a YAML single-quoted scalar
			if q == '\'' && raw[i] == q && i+1 < len(raw) && raw[i+1] == q {
				i++
				continue
			}
			if raw[i] == q {
				return raw[:1], raw[1:i], raw[i:]
			}
		}
		return "", raw, ""
	}
	if raw[0] == '#' {
		// key:   # a comment, no value
		return raw, "", ""
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
// credential — one word, random, or 12+ characters with a digit in them
// (the CLI's looksRandom bar for keyed memory lines).
func standaloneSecret(v string) bool {
	return highEntropySecret(v) || len(v) >= 12 && credentialLike(v) &&
		// a random 40-character key may have no digit, or fall under 4.5
		(strings.ContainsAny(v, "0123456789") || len(v) >= 20 && shannonEntropy(v) > 4.0)
}

// inlineSecrets finds KEY=value, key: value and "key": "value" in one line
// and hands each credential under a credential-named key to replace. A
// quoted value runs to its closing quote; an unquoted one, in free text
// (prose), to the end of the line (before a " #" comment or a closing
// quote), elsewhere to the end of the word. Prose that follows a value (a
// URL, "see the example", "...") would make the run no credential: then
// the first word alone is the value, as the CLI judges it. A pair that
// isn't one, or whose value replace keeps, is searched again from its value
// ("command": "OPENAI_API_KEY=…", "//registry/:_authToken=…").
func inlineSecrets(line string, prose bool, replace func(key, value string) (string, bool)) string {
	re := inlinePair
	if prose {
		re = inlinePairProse
	}
	var b strings.Builder
	last, from := 0, 0
	for from < len(line) {
		loc := re.FindStringSubmatchIndex(line[from:])
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
		word := end
		trigger := line[start:end]
		switch {
		case len(quote) >= 2:
			// \"…\" inside a JSON string (\\\"…\\\" a level deeper): up to
			// the same escaped quote, past deeper-escaped ones inside it
			if j := closingEscapedQuote(line, start, quote); j >= 0 {
				end = j
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
		// Cookie: session=<value>: the value is a credential pair of its own,
		// read next (a base64 value's "=" padding is no pair)
		if np := nestedPair.FindStringSubmatch(trigger); np != nil && isSecretKeyName(np[1]) {
			from = g[12]
			continue
		}
		if isSecretKeyName(key) && (inlineSecret(trigger) ||
			// a quoted value is a literal, not prose: the structured rules' bar
			quote != "" && credentialLike(trigger) || strongCredentialKey(key) && passphraseLike(line[start:end]) &&
			// in free text a run of spaced words is a sentence (password: see the vault)
			!(prose && quote == "" && strings.Contains(line[start:end], " "))) {
			out, ok := replace(key, line[start:end])
			if !ok && prose && quote == "" && end > word {
				end = word
				out, ok = replace(key, line[start:end])
			}
			if ok {
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

var nestedPair = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.-]*)=[^=]`)

// closingEscapedQuote returns where the escaped quote (\" — n backslashes and
// a quote) closing a value that starts at start begins: a quote after
// exactly n backslashes; one after more (\\\") is a quote inside the value.
func closingEscapedQuote(line string, start int, quote string) int {
	n := len(quote) - 1
	q := quote[n]
	for j := start; j < len(line) && line[j] != '\n'; j++ {
		if line[j] != q {
			continue
		}
		k := j
		for k > start && line[k-1] == '\\' {
			k--
		}
		if j-k == n {
			return k
		}
	}
	return -1
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
var secretHints = []string{"key", "token", "secret", "pass", "pwd", "pw", "pin", "credential", "auth", "cookie", "session", "jwt", "dsn", "bearer", "header", "signature", "pat"}

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
// The length never changes, so the content budget charged stays right. A
// file that isn't valid UTF-8 (a Latin-1 comment, UTF-16) is scrubbed
// through a copy of the same length (scrubbableText) — one such byte used
// to ship the whole file as it was.
func (c *collector) scrubSecrets(path string, content []byte) []byte {
	text, restore := scrubbableText(content)
	return restore(c.scrubText(path, text))
}

// opaqueByte stands in for a character the rules can't read: not a letter,
// digit, space or quote, so it neither starts nor ends a value.
const opaqueByte = 0x1a

// scrubbableText returns valid UTF-8 text the rules can scrub, of the same
// length as content, and how to write a scrubbed copy back: as is for
// UTF-8; for UTF-16 (a BOM) one byte per code unit; otherwise each byte of
// an invalid sequence becomes opaqueByte. Stand-ins only change ASCII letters
// and digits, so everything else goes back exactly as it was.
func scrubbableText(content []byte) (string, func(string) []byte) {
	if little, ok := utf16Order(content); ok {
		unit := func(i int) uint16 {
			if little {
				return uint16(content[2*i]) | uint16(content[2*i+1])<<8
			}
			return uint16(content[2*i])<<8 | uint16(content[2*i+1])
		}
		text := make([]byte, len(content)/2)
		for i := range text {
			if u := unit(i); u > 0 && u < 0x80 {
				text[i] = byte(u)
			} else {
				text[i] = opaqueByte
			}
		}
		return string(text), func(s string) []byte {
			out := append([]byte(nil), content...)
			for i := 0; i < len(text) && i < len(s); i++ {
				if s[i] != text[i] {
					lo := 2 * i
					if !little {
						lo++
					}
					out[lo] = s[i]
				}
			}
			return out
		}
	}
	if utf8.Valid(content) {
		return string(content), func(s string) []byte { return []byte(s) }
	}
	text := make([]byte, 0, len(content))
	for i := 0; i < len(content); {
		r, n := utf8.DecodeRune(content[i:])
		if r == utf8.RuneError && n <= 1 {
			text = append(text, opaqueByte)
			i++
			continue
		}
		text = append(text, content[i:i+n]...)
		i += n
	}
	return string(text), func(s string) []byte {
		out := []byte(s)
		for i := 0; i < len(out) && i < len(content); i++ {
			if text[i] == opaqueByte && out[i] == opaqueByte {
				out[i] = content[i]
			}
		}
		return out
	}
}

// utf16Order reports whether content is UTF-16 and in which byte order: a
// BOM, or (none written) text whose every other byte is NUL — ASCII in
// UTF-16 is valid UTF-8 too, so this is asked first.
func utf16Order(content []byte) (little, ok bool) {
	// an odd trailing byte (a truncated or appended file) doesn't stop it
	if len(content) < 2 {
		return false, false
	}
	if content[0] == 0xFF && content[1] == 0xFE || content[0] == 0xFE && content[1] == 0xFF {
		return content[0] == 0xFF, true
	}
	units := len(content) / 2
	if units < 8 {
		return false, false
	}
	// ASCII in UTF-16 has a NUL in every unit, on one side; non-ASCII text
	// (Cyrillic, CJK comments) has none, but never on the other side either
	le, be := 0, 0
	text := func(b byte) bool { return b >= 0x20 && b < 0x7f || b == '\n' || b == '\r' || b == '\t' }
	for i := 0; i < units; i++ {
		lo, hi := content[2*i], content[2*i+1]
		if hi == 0 && text(lo) {
			le++
		}
		if lo == 0 && text(hi) {
			be++
		}
	}
	switch {
	case le*2 >= units && be*20 <= units:
		return true, true
	case be*2 >= units && le*20 <= units:
		return false, true
	}
	return false, false
}

// keyedValue disguises a raw dotenv/YAML/TOML value under key when it is a
// credential, keeping its quotes and a trailing comment.
func (c *collector) keyedValue(key, raw string) string {
	if !isSecretKeyName(key) {
		return raw
	}
	open, value, rest := scalarValue(raw)
	if !credentialLike(value) && !(strongCredentialKey(key) && passphraseLike(value)) {
		return raw
	}
	return open + c.disguiseKeyed(key, value) + rest
}

func (c *collector) scrubText(path, s string) string {
	// the values disguised in this file (disguiseCopies)
	c.inFile = map[string]string{}
	defer func() { c.inFile = nil }()
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
		// one stand-in per key in a snapshot: a key in two files is one sample
		if c.disguised == nil {
			c.disguised = map[string]string{}
		}
		body, ok := c.disguised[g[2]]
		if !ok {
			body = randomBase64(g[2])
			c.disguised[g[2]] = body
			c.disguised[body] = body
		}
		return g[1] + body + g[3]
	})
	if dotenv {
		s = dotenvLine.ReplaceAllStringFunc(s, func(m string) string {
			g := dotenvLine.FindStringSubmatch(m)
			return g[1] + g[2] + g[3] + c.keyedValue(g[2], g[4]) + g[5]
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
	if jsonish || toml {
		// "api_keys": ["…", "…"], tokens = { primary = "…" }
		s = c.secretContainers(s, toml)
	}
	if jsonish {
		// "client_secret": 1234…: an unquoted number under a secret name
		s = jsonNumber.ReplaceAllStringFunc(s, func(m string) string {
			g := jsonNumber.FindStringSubmatch(m)
			if g[2] != g[4] {
				return m
			}
			return g[1] + g[2] + g[3] + g[4] + g[5] + c.keyedValue(g[3], g[6])
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
					return m.with(2, 2, c.keyedValue(g[3], item))
				}) + g[7]
			}
			if strings.HasPrefix(g[6], "{") {
				// env: {SVC_API_TOKEN: a} judged as a block pair is; under
				// tokens: {primary: a}, a flow mapping of secrets, every child
				return g[1] + g[2] + g[3] + g[4] + g[5] + replaceMatches(flowPair, g[6], func(m submatch) string {
					child, _ := m.group(3)
					value, _ := m.group(6)
					if secretContainerKey(g[3]) {
						child = containerChildKey(g[3], child)
					}
					return m.with(6, 6, c.keyedValue(child, value))
				}) + g[7]
			}
			return g[1] + g[2] + g[3] + g[4] + g[5] + c.keyedValue(g[3], g[6]) + g[7]
		})
		if strings.Contains(s, "? ") {
			s = yamlExplicit.ReplaceAllStringFunc(s, func(m string) string {
				g := yamlExplicit.FindStringSubmatch(m)
				if g[2] != g[4] {
					return m
				}
				return g[1] + g[2] + g[3] + g[4] + g[5] + c.keyedValue(g[3], g[6]) + g[7]
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
		// values on the lines below their key: block sequences, a scalar on
		// the next line, children of a secrets mapping, argv items
		s = c.yamlNested(s)
	}
	if toml {
		headers := tomlHeader.FindAllStringSubmatchIndex(s, -1)
		s = replaceMatches(tomlPair, s, func(m submatch) string {
			lead, _ := m.group(1)
			rawKey, _ := m.group(2)
			sep, _ := m.group(3)
			raw, _ := m.group(4)
			// a dotted key (api_key."main", env.OPENAI_API_KEY) is named by its
			// last part, or by a part before it that names a credential;
			// [http_request.secrets] github = "…" by its table
			parts := tomlKeyParts(rawKey)
			key := parts[len(parts)-1]
			for i := len(parts) - 2; i >= 0 && !isSecretKeyName(key); i-- {
				if isSecretKeyName(parts[i]) {
					key = containerChildKey(parts[i], key)
				}
			}
			if table := tomlTableAt(s, headers, m.g[0]); !isSecretKeyName(key) && table != "" {
				key = containerChildKey(table, key)
			}
			if q := raw[:1]; len(raw) >= 6 && strings.HasPrefix(raw, strings.Repeat(q, 3)) {
				return lead + rawKey + sep + c.tripleQuoted(key, raw)
			}
			return lead + rawKey + sep + c.keyedValue(key, raw)
		})
	}
	if jsonish || yaml || toml {
		// "--api-key", "<value>" in an argv array (MCP server args); a flag
		// that takes no value before it ("--verbose", "--token", …) is
		// searched again from its own value
		s = replacePairs(argPair, s, 4, func(m submatch) (string, bool) {
			open, _ := m.group(1)
			closing, _ := m.group(3)
			flag, _ := m.group(2)
			value, vi := m.first(5, 6, 7)
			// a value never starts with "-": "--no-auth", "--api-key", X pairs
			// the second flag with X, and no flag name is disguised
			if open != closing || !flagTakesCredential(flag, value) {
				return "", false
			}
			out, ok := headerValue(value, c.disguise)
			return m.with(vi, vi, out), ok
		})
	}
	if jsonish || toml {
		// an args array: the shared argv rules, its server's command in front
		s = c.argvArrays(s, toml)
	}
	if yaml {
		s = c.yamlArgv(s)
		s = c.yamlFlowArgv(s)
	}
	s = flagCredentials(s, c.disguiseArgv)
	s = urlPassword.ReplaceAllStringFunc(s, func(m string) string {
		g := urlPassword.FindStringSubmatch(m)
		return g[1] + c.disguise(g[2]) + "@"
	})
	s = urlUserToken.ReplaceAllStringFunc(s, func(m string) string {
		g := urlUserToken.FindStringSubmatch(m)
		if !credentialLike(g[2]) {
			return m
		}
		return g[1] + c.disguise(g[2]) + g[3] + "@"
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
	s = replaceURLFragmentTokens(s, c.disguiseURLSecret)
	// capability URLs: Zapier/Discord path secrets, random path tokens
	s = replaceURLPathSecrets(s, c.disguiseURLSecret)
	// KEY=value and key: value in any text (CLAUDE.md, a command string in
	// a config): last, so what a structured rule disguised is kept as is
	s = onSecretLines(s, secretHints, func(line string) string {
		return inlineSecrets(line, prose, func(key, value string) (string, bool) {
			out := c.disguiseKeyed(key, value)
			return out, out != value
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
	return c.disguiseCopies(s)
}

// disguiseCopies replaces what is left in s of a value disguised in it: a
// copy of 16+ of its characters elsewhere in the file (half a token pasted
// into a note) gets the stand-in's characters at the same offsets.
func (c *collector) disguiseCopies(s string) string {
	for v, d := range c.inFile {
		if len(v) < 24 || v == d || len(d) != len(v) {
			continue
		}
		for from := 8; from+16 <= len(v); from += 8 {
			for n := 0; n < 64; n++ {
				i := strings.Index(s, v[from:from+16])
				if i < 0 || d[from:from+16] == v[from:from+16] {
					break
				}
				// the whole run of v around it
				a, b := from, from+16
				for a > 0 && i-(from-a) > 0 && s[i-(from-a)-1] == v[a-1] {
					a--
				}
				for b < len(v) && i+(b-from) < len(s) && s[i+(b-from)] == v[b] {
					b++
				}
				start := i - (from - a)
				s = s[:start] + d[a:b] + s[start+(b-a):]
			}
		}
	}
	return s
}

// flagCredentials applies replace to every credential value a command line
// passes by flag — --api-key=<value>, --api-key <value>, -u user:<password>,
// mysql -p<password> — in a file (disguise), a variable or command output
// (redaction). A value replace returns unchanged is kept.
func flagCredentials(s string, replace func(string) string) string {
	// --header=X-Api-Key:<value> keeps the header name; with a space after
	// the colon (--header=Authorization: Bearer <value>) the keyed rule reads it
	s = flagValue.ReplaceAllStringFunc(s, func(m string) string {
		g := flagValue.FindStringSubmatch(m)
		if !isSecretFlag(g[1]) || !credentialLike(g[2]) {
			return m
		}
		out, _ := headerValue(g[2], replace)
		return g[1] + "=" + out
	})
	// --password "two words" / --token='<value>': a quoted value may hold spaces
	s = onSecretLines(s, secretHints, func(line string) string {
		return replaceMatches(flagQuoted, line, func(m submatch) string {
			flag, _ := m.group(1)
			open, _ := m.group(3)
			closing, _ := m.group(5)
			value, _ := m.group(4)
			if open != closing || !isSecretFlag(flag) || strings.HasPrefix(value, "-") || !credentialLike(value) && !passphraseLike(value) {
				return m.text()
			}
			return m.with(4, 4, replace(value))
		})
	})
	s = onSecretLines(s, append([]string{"-k"}, secretHints...), func(line string) string {
		return replacePairs(flagSpace, line, 4, func(m submatch) (string, bool) {
			flag, _ := m.group(2)
			value, _ := m.group(4)
			if !flagTakesCredential(flag, value) {
				return "", false
			}
			out, ok := headerValue(value, replace)
			return m.with(4, 4, out), ok && out != value
		})
	})
	s = onSecretLines(s, []string{"-u", "--user"}, func(line string) string {
		return replaceMatches(userFlag, line, func(m submatch) string {
			password, _ := m.group(5)
			if !credentialLike(password) {
				return m.text()
			}
			return m.with(5, 5, replace(password))
		})
	})
	// mysql -p<password>, sshpass -p <password>, redis-cli -a, -k <key>:
	// the shared argv rules (argv_rules.go) on each command in a line
	return onSecretLines(s, argvHints, func(line string) string {
		return commandCredentials(line, replace)
	})
}

// headerValue applies replace to a credential flag's value; a header line
// in it (X-Api-Key:<value>, Authorization: Bearer <value>) keeps its name
// and scheme. "Cookie: session=<value>" holds a pair of its own, left to the
// keyed rule (ok false).
func headerValue(v string, replace func(string) string) (string, bool) {
	h := headerName.FindString(v)
	if h == "" {
		return replace(v), true
	}
	rest := v[len(h):]
	lead := len(rest) - len(strings.TrimLeft(rest, " \t"))
	lead += len(authSchemePrefix.FindString(rest[lead:]))
	value := rest[lead:]
	if np := nestedPair.FindStringSubmatch(value); np != nil && isSecretKeyName(np[1]) {
		return v, false
	}
	if !credentialLike(value) {
		return v, true
	}
	return h + rest[:lead] + replace(value), true
}

// secretContainerKey: a key holding several credentials — api_keys, tokens,
// [http_request.secrets], credentials — whose items and children are
// credentials whatever they are named. Not auth or headers, whose
// children are settings (mode, Content-Type) beside the credential.
var (
	secretContainerName = regexp.MustCompile(`(?i)(?:api[_-]?keys?|apikeys?|tokens?|secrets?|passwords?|passwd|pwds?|credentials?|private[_-]?keys?|(?:^|[_.-])keys)$`)
	tokenCountName      = regexp.MustCompile(`(?i)(?:max|min|num|total|count|limit|output|input|prompt|completion|context)[_-]?tokens$`)
)

// headerMapKey: a map of HTTP headers, whose random values are credentials
// whatever the header is called (X-Custom: <token>).
var headerMapKey = regexp.MustCompile(`(?i)^(?:http_?)?headers$`)

func secretContainerKey(key string) bool {
	k := strings.Trim(key, `"'`)
	return secretContainerName.MatchString(k) && !tokenCountName.MatchString(k)
}

// settingChildName: a child of a secrets container that describes the
// credential beside it (name, provider, enabled) rather than holding one.
var settingChildName = regexp.MustCompile(`(?i)^(?:name|label|description|type|kind|mode|provider|enabled|disabled|url|uri|endpoint|host|path|file|dir|id|env|scope|scopes|region|format|header|prefix|expires|expiry|ttl)$`)

// containerChildKey is the name a child of the container parent is judged
// under: its own when that names a credential, the parent's unless it names
// a setting ("" then: not a credential).
func containerChildKey(parent, child string) string {
	switch {
	case isSecretKeyName(child):
		return child
	case settingChildName.MatchString(child) || credentialAboutWord.MatchString("_"+strings.ToLower(child)):
		return ""
	}
	return parent
}

var (
	// key = [ / "key": { — the opening of an array or table under a key
	containerOpen = regexp.MustCompile(`(^|[\s{,\[])(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|([A-Za-z_$][A-Za-z0-9_$.-]*))(\s*[:=]\s*)([\[{])`)
	// [table] / [[array.of.tables]] in TOML
	tomlHeader = regexp.MustCompile(`(?m)^[ \t]*\[\[?[ \t]*([^\[\]\r\n]+?)[ \t]*\]\]?`)
)

// tomlTableAt is the secretContainerKey part of the name of the TOML table
// at pos, its deepest one ([secrets.nested] is under secrets), or "".
func tomlTableAt(s string, headers [][]int, pos int) string {
	name := ""
	for _, h := range headers {
		if h[0] > pos {
			break
		}
		name = s[h[2]:h[3]]
	}
	parts := tomlKeyParts(name)
	for i := len(parts) - 1; i >= 0; i-- {
		if secretContainerKey(parts[i]) {
			return parts[i]
		}
	}
	return ""
}

// tomlKeyParts splits a dotted TOML key (a."b.c".d) into its unquoted parts.
func tomlKeyParts(key string) []string {
	var parts []string
	var cur strings.Builder
	quote := byte(0)
	for i := 0; i < len(key); i++ {
		switch ch := key[i]; {
		case quote != 0 && ch == quote:
			quote = 0
		case quote != 0:
			cur.WriteByte(ch)
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '.':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	return append(parts, strings.TrimSpace(cur.String()))
}

// secretContainers disguises the strings of an array or inline table under
// a secretContainerKey (JSON, JSON5, TOML): array items, and table values
// whose own key names no credential. Nested containers are walked over.
func (c *collector) secretContainers(s string, toml bool) string {
	var b []byte
	for _, g := range containerOpen.FindAllStringSubmatchIndex(s, -1) {
		m := submatch{s, g}
		key, _ := m.first(2, 3, 4)
		if headerMapKey.MatchString(key) && s[g[12]] == '{' {
			// headers: {"X-Custom": "<random>"}: a header no rule names
			for _, sp := range containerStrings(s, g[12], toml) {
				if value := s[sp.from:sp.to]; !isSecretKeyName(sp.key) && looksRandom(value, 16) {
					if b == nil {
						b = []byte(s)
					}
					copy(b[sp.from:sp.to], c.disguise(value))
				}
			}
			continue
		}
		if !secretContainerKey(key) {
			continue
		}
		for _, sp := range containerStrings(s, g[12], toml) {
			name := key
			if s[g[12]] == '{' {
				name = containerChildKey(key, sp.key)
			}
			value := s[sp.from:sp.to]
			if name == "" {
				continue
			}
			if !credentialLike(value) && !(strongCredentialKey(name) && passphraseLike(value)) {
				continue
			}
			if b == nil {
				b = []byte(s)
			}
			copy(b[sp.from:sp.to], c.disguiseKeyed(name, value))
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

type containerString struct {
	from, to int
	key      string // the value's own key in a table, "" in an array
}

// containerStrings returns the string values directly inside the array or
// table opening at open: every string of an array, the values (after : or
// =) of a table. Comments are skipped; an unterminated string, a TOML
// multi-line string or more than 64 KiB of text ends the walk.
func containerStrings(s string, open int, toml bool) []containerString {
	var out []containerString
	array := s[open] == '['
	depth, afterSep, key := 0, false, ""
	limit := open + 64<<10
	for i := open; i < len(s) && i < limit; i++ {
		switch ch := s[i]; {
		case ch == '"' || ch == '\'':
			if strings.HasPrefix(s[i:], `"""`) || strings.HasPrefix(s[i:], "'''") {
				return out
			}
			end := i + 1
			for ; end < len(s) && s[end] != ch && s[end] != '\n'; end++ {
				if s[end] == '\\' && !(toml && ch == '\'') {
					end++
				}
			}
			if end >= len(s) || s[end] != ch {
				return out
			}
			if depth == 1 {
				if array || afterSep {
					out = append(out, containerString{i + 1, end, key})
				} else {
					key = s[i+1 : end]
				}
				afterSep = false
			}
			i = end
		case ch == '[' || ch == '{':
			depth++
			afterSep = false
		case ch == ']' || ch == '}':
			depth--
			if depth == 0 {
				return out
			}
		case ch == ':' || ch == '=':
			afterSep = depth == 1
		case ch == ',' || ch == '\n':
			afterSep = false
		case ch == '#' && toml, ch == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			i--
		case ch == '/' && i+1 < len(s) && s[i+1] == '*':
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return out
			}
			i += j + 3
		case depth == 1 && !array && !afterSep && (isASCIIAlnum(ch) || ch == '_' || ch == '$'):
			j := i
			for j < len(s) && (isASCIIAlnum(s[j]) || strings.IndexByte("_$-.", s[j]) >= 0) {
				j++
			}
			key = s[i:j]
			i = j - 1
		}
	}
	return out
}

var (
	yamlKeyLine  = regexp.MustCompile(`^(["']?)([A-Za-z0-9_.-]+)(["']?)[ \t]*:(?:[ \t]+(.*))?$`)
	yamlItemLine = regexp.MustCompile(`^-(?:[ \t]+(.*))?$`)
	yamlBareFlag = regexp.MustCompile(`^["']?(--?[A-Za-z][A-Za-z0-9_-]*)["']?[ \t]*(?:#.*)?$`)
	yamlMapValue = regexp.MustCompile(`^["']?[A-Za-z0-9_.-]+["']?[ \t]*:(?:[ \t]|$)`)
)

// yamlNested disguises YAML values written below their key, which the
// one-line rules can't see: the items of a block sequence under a
// credential name (api_keys: then "- <key>" lines, as PicoClaw saves
// .security.yml), a lone scalar on the deeper line after "api_key:", the
// children of a mapping under a secretContainerKey (secrets: then
// "github: <token>"), and the item after a credential flag in any sequence
// (args: then "- --api-key", "- <value>").
func (c *collector) yamlNested(s string) string {
	type frame struct {
		indent int
		key    string
		// the secretContainerKey this mapping sits in (secrets: nested:)
		secrets string
	}
	type item struct {
		indent int
		flag   string
	}
	b := []byte(s)
	var stack []frame
	var prevItem *item
	blockIndent := -1 // inside a | or > block scalar deeper than this
	// "? key" waiting for its ": value" line
	explicitKey, explicitIndent := "", -1
	offset := 0
	lines := strings.SplitAfter(s, "\n")
	for li, raw := range lines {
		lineStart := offset
		offset += len(raw)
		line := strings.TrimRight(raw, "\r\n")
		bom := len(line) - len(strings.TrimPrefix(line, "\xef\xbb\xbf"))
		body := strings.TrimLeft(line[bom:], " \t")
		indent := len(line) - bom - len(body)
		if body == "" || body[0] == '#' {
			continue
		}
		if blockIndent >= 0 {
			if indent > blockIndent {
				continue
			}
			blockIndent = -1
		}
		bodyAt := lineStart + bom + indent
		disguiseAt := func(from int, key, raw string) {
			if out := c.keyedValue(key, raw); out != raw {
				copy(b[from:from+len(raw)], out)
			}
		}
		// the key a line at indent belongs to (a sequence may sit at its
		// key's own indent)
		parent := func(orEqual bool) (frame, bool) {
			for len(stack) > 0 {
				top := stack[len(stack)-1]
				if top.indent < indent || orEqual && top.indent == indent {
					return top, true
				}
				stack = stack[:len(stack)-1]
			}
			return frame{}, false
		}
		if m := yamlItemLine.FindStringSubmatch(body); m != nil {
			p, ok := parent(true)
			rest := m[1]
			restAt := bodyAt + len(body) - len(rest)
			switch {
			// (an &anchor or !!tag before the item is read past by scalarValue)
			case rest == "" || yamlMapValue.MatchString(rest) || strings.ContainsAny(rest[:1], "{[|>*#"):
			case prevItem != nil && prevItem.indent == indent && prevItem.flag != "" && !strings.HasPrefix(strings.Trim(rest, `"'`), "-"):
				// - --api-key, then - <value>
				open, value, _ := scalarValue(rest)
				if flagTakesCredential(prevItem.flag, value) {
					from := restAt + len(open)
					copy(b[from:from+len(value)], c.disguise(value))
				}
			case ok && isSecretKeyName(p.key):
				disguiseAt(restAt, p.key, rest)
			case ok && p.secrets != "":
				disguiseAt(restAt, p.secrets, rest)
			}
			flag := ""
			if f := yamlBareFlag.FindStringSubmatch(rest); f != nil && (isSecretFlag(f[1]) || f[1] == "-k") {
				flag = f[1]
			}
			prevItem = &item{indent, flag}
			continue
		}
		prevItem = nil
		// ? X-Other / : <value>, an explicit key
		if body == "?" || strings.HasPrefix(body, "? ") {
			explicitKey, explicitIndent = strings.Trim(strings.TrimSpace(body[1:]), `"'`), indent
			continue
		}
		key, value, isKey := "", "", false
		if m := yamlKeyLine.FindStringSubmatch(body); m != nil && m[1] == m[3] {
			key, value, isKey = m[2], m[4], true
		} else if explicitKey != "" && indent == explicitIndent && (body == ":" || strings.HasPrefix(body, ": ")) {
			key, value, isKey = explicitKey, strings.TrimLeft(body[1:], " \t"), true
		}
		explicitKey = ""
		if isKey {
			p, ok := parent(false)
			valueAt := bodyAt + len(body) - len(value)
			// &anchor / !!tag alone: the value is on the lines below
			props := strings.TrimSpace(yamlProps.ReplaceAllString(value+" ", ""))
			switch {
			case value == "" || value[0] == '#' || props == "" || props[0] == '#':
				secrets := ""
				if secretContainerKey(key) {
					secrets = key
				} else if ok && p.secrets != "" && containerChildKey(p.secrets, key) != "" {
					secrets = p.secrets
				}
				stack = append(stack, frame{indent, key, secrets})
			case value[0] == '|' || value[0] == '>':
				blockIndent = indent
			case ok && !isSecretKeyName(key) && p.secrets != "":
				disguiseAt(valueAt, containerChildKey(p.secrets, key), value)
			case ok && !isSecretKeyName(key) && headerMapKey.MatchString(p.key):
				if open, v, _ := scalarValue(value); looksRandom(v, 16) {
					from := valueAt + len(open)
					copy(b[from:from+len(v)], c.disguise(v))
				}
			default:
				// what the one-line rules read already is kept (idempotent);
				// an explicit key's value is read here
				disguiseAt(valueAt, key, value)
			}
			continue
		}
		// a lone scalar on the line below "api_key:" — one line: the next
		// one is no deeper
		p, ok := parent(false)
		if !ok || !isSecretKeyName(p.key) || strings.Contains(body, ": ") || strings.ContainsAny(body[:1], "{[|>&*!") {
			continue
		}
		if next := nextContentLine(lines[li+1:]); next != "" {
			if nb := strings.TrimLeft(next, " \t"); len(next)-len(nb) >= indent {
				continue
			}
		}
		disguiseAt(bodyAt, p.key, body)
	}
	return string(b)
}

// nextContentLine is the first line of lines that isn't blank or a comment.
func nextContentLine(lines []string) string {
	for _, l := range lines {
		l = strings.TrimRight(l, "\r\n")
		if t := strings.TrimSpace(l); t != "" && t[0] != '#' {
			return l
		}
	}
	return ""
}

// scrubbable: a file whose secrets are disguised. Files a skills glob of the
// manifest collected ship verbatim (IOC-003/008 hash skill files), and so do
// installed packages: neither is where an agent keeps its credentials. No
// other path is judged by its directory names: a config relocated under
// ~/work/skill-lab/ is scrubbed like any other. node_modules is judged below
// the user's home, so a home under some ".../node_modules/" is no package.
func (c *collector) scrubbable(path string) bool {
	slash := filepath.ToSlash(path)
	for _, h := range c.homes {
		home := strings.TrimSuffix(filepath.ToSlash(h), "/")
		if home != "" && strings.HasPrefix(slash, home+"/") {
			slash = slash[len(home):]
			break
		}
	}
	return (!c.inSkillTree || c.configTree) && !strings.Contains(slash, "/node_modules/")
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

// replaceURLFragmentTokens replaces a random token that is a URL's whole
// fragment (…/mcp#<token>; #name=value is urlCredParam's).
func replaceURLFragmentTokens(s string, replace func(string) string) string {
	return urlFragment.ReplaceAllStringFunc(s, func(m string) string {
		g := urlFragment.FindStringSubmatch(m)
		if !randomPathSegment(g[2]) && !hexPathToken.MatchString(g[2]) {
			return m
		}
		return g[1] + replace(g[2]) + g[3]
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
