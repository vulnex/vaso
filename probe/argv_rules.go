package main

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Which arguments of a command line are credentials: the shared argv rules
// (testdata/argv-verdicts.json, held to by TestArgvVerdicts here and by the
// report masker and MCP-003 in TypeScript).
//
//  1. A following element is a flag, not a flag's value, only when it is
//     flag-shaped (--name, -n: ^--?[A-Za-z][A-Za-z0-9_-]*$ with a name that
//     doesn't look random) or exactly "--" (end of options: what follows is
//     a positional). Any other "-"-led element (-Xq9Zr…) is a value.
//  2. -p<v> glued after a password client (mysql, mysqldump, mariadb,
//     mysqladmin, sshpass) is a password unless a reference; a separate
//     -p <v> is one only after sshpass (MySQL/MariaDB take the password glued:
//     in mysql -p app_db, app_db is the database). After psql, pg_dump or
//     redis-cli -p is a port; anywhere else (a MySQL client's separate -p
//     included) -p <v> is a password only when v looks like a credential
//     (MCP-003's looksLikeSecret) and is no port, port mapping, version,
//     package spec, reference or lowercase word. A MySQL/MariaDB client's
//     --password=<v> is its password like a glued -p<v>.
//  3. -k <v> is a credential when v looks random and is no URL, host[:port]
//     or path ("/" and "+" inside a base64 key don't make it one).
//  4. redis-cli -a <v> is a password unless a reference.
//  5. Any credential-named flag (--api-key, --token=…) takes the next value
//     when it looks like a credential.
//  6. MYSQL_PWD=<v>, PGPASSWORD=<v>, SSHPASS=<v>, REDISCLI_AUTH=<v> (a
//     client's password variable) hold a password unless a reference.

// argvHit is a credential inside token tok, bytes [from, to).
type argvHit struct{ tok, from, to int }

var (
	flagShapedRe = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9_-]*$`)
	// clients whose -p is the password
	passwordClients = map[string]bool{"mysql": true, "mysqldump": true, "mariadb": true, "mariadb-dump": true, "mysqladmin": true, "sshpass": true}
	// clients whose -p is a port
	// clients whose -u/--user/--proxy-user value is user:password
	userPassClients = map[string]bool{"curl": true, "curl.exe": true}
	userPassFlags   = map[string]bool{"-u": true, "--user": true, "--proxy-user": true}
	// variables a client reads its password from and nothing else (rule 6)
	clientPasswordVar = regexp.MustCompile(`^(?:MYSQL_PWD|PGPASSWORD|SSHPASS|REDISCLI_AUTH)=`)
	portClients       = map[string]bool{"psql": true, "pg_dump": true, "pg_dumpall": true, "pg_restore": true, "pg_isready": true, "redis-cli": true}
	versionLike       = regexp.MustCompile(`^v?\d+(?:\.\d+)*$`)
	packageSpec       = regexp.MustCompile(`^(?:@[\w.-]+/)?[\w.-]+@[\w.^~*<>=-]+$|^@[\w.-]+/[\w.-]+$`)
	lowerWordRe       = regexp.MustCompile(`^[a-z]+$`)
	hostPort          = regexp.MustCompile(`^[A-Za-z0-9.-]+:\d+$`)
	// ${port}:3000, $PORT: a reference inside a value
	embeddedRef = regexp.MustCompile(`\$\{?[A-Za-z_]`)
)

// flagShaped: a flag, not a value (rule 1); "--" ends the options. A name
// that looks random (-Xq9Zr7Lm2Pv8Kd4Wb6Tn3Hc, a key that happens to start
// with "-") is a value, though made of letters and digits like a flag.
func flagShaped(t string) bool {
	return t == "--" || flagShapedRe.MatchString(t) && !looksRandom(strings.TrimLeft(t, "-"), 12)
}

// clientName is the command a token names, by its file name (/usr/bin/mysql).
func clientName(t string) string {
	return strings.ToLower(filepath.Base(t))
}

// passwordValue: after a password client, any value that isn't a reference.
func passwordValue(v string) bool {
	return v != "" && !isSecretReference(v) && !embeddedRef.MatchString(v)
}

// unknownPassword: -p <v> after an unknown command (rule 2).
// userPassword: the password span of a curl user:password value — after
// the first colon, when one is stored there (not empty, not a reference).
func userPassword(v string) (int, bool) {
	i := strings.IndexByte(v, ':')
	if i < 0 || !passwordValue(v[i+1:]) {
		return 0, false
	}
	return i + 1, true
}

func unknownPassword(v string) bool {
	return looksLikeSecret(v) && !portLike.MatchString(v) && !versionLike.MatchString(v) && !packageSpec.MatchString(v) &&
		!isSecretReference(v) && !embeddedRef.MatchString(v) && !lowerWordRe.MatchString(v)
}

// randomKey: -k <v> (rule 3).
func randomKey(v string) bool {
	return looksRandom(v, 16) && !strings.Contains(v, "://") && !hostPort.MatchString(v) && !isPathValue(v)
}

// credentialFlagValue: the value after a credential-named flag (rule 5).
func credentialFlagValue(v string) bool {
	return credentialLike(v) || passphraseLike(v) && strings.ContainsAny(v, "0123456789")
}

// flagValueSpan is the credential in a credential flag's value: all of it,
// or after a header name and scheme (X-Api-Key:<v>, Authorization: Bearer
// <v>), or after the name of a credential pair in it (Cookie: session=<v>).
func flagValueSpan(v string) (int, int, bool) {
	from := 0
	if h := headerName.FindString(v); h != "" {
		from = len(h)
		for from < len(v) && (v[from] == ' ' || v[from] == '\t') {
			from++
		}
		from += len(authSchemePrefix.FindString(v[from:]))
	}
	if np := nestedPair.FindStringSubmatch(v[from:]); np != nil && isSecretKeyName(np[1]) {
		from += len(np[1]) + 1
	}
	if !credentialFlagValue(v[from:]) {
		return 0, 0, false
	}
	return from, len(v), true
}

// secretFlagValueSpan is flagValueSpan for the value of flag; after a flag
// naming a password or key itself (--password, --pw, --api-key) a plain
// value is the credential too, as in a config's argv pairs (flagTakesCredential).
func secretFlagValueSpan(flag, v string) (int, int, bool) {
	if from, to, ok := flagValueSpan(v); ok {
		return from, to, true
	}
	if strongCredentialFlag(flag) && plainCredential(v) {
		return 0, len(v), true
	}
	return 0, 0, false
}

// judgeArgv returns the credentials among tokens, one command line (a
// segment of one: the caller splits at ; && || |).
func judgeArgv(tokens []string) []argvHit {
	var hits []argvHit
	client := ""
	value := func(i int) (string, bool) {
		if i+1 >= len(tokens) || flagShaped(tokens[i+1]) {
			return "", false
		}
		return tokens[i+1], true
	}
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		switch {
		case t == "--":
			// end of options: the rest are positionals
			return hits
		case clientPasswordVar.MatchString(t):
			// MYSQL_PWD=<pw> mysql, PGPASSWORD=<pw> psql (rule 6)
			eq := strings.IndexByte(t, '=')
			if passwordValue(t[eq+1:]) {
				hits = append(hits, argvHit{i, eq + 1, len(t)})
			}
		case !strings.HasPrefix(t, "-"):
			if name := clientName(t); passwordClients[name] || portClients[name] || userPassClients[name] {
				client = name
			}
		case t == "-p":
			// a separate value is the password only after sshpass; MySQL/MariaDB
			// take it glued (`mysql -p app_db` prompts, app_db is the database)
			if v, ok := value(i); ok {
				if client == "sshpass" && passwordValue(v) || client != "sshpass" && !portClients[client] && unknownPassword(v) {
					hits = append(hits, argvHit{i + 1, 0, len(v)})
				}
				i++
			}
		case strings.HasPrefix(t, "-p") && t[2] != '-' && t[2] != '=':
			v := t[2:]
			if passwordClients[client] && passwordValue(v) || !passwordClients[client] && !portClients[client] && unknownPassword(v) {
				hits = append(hits, argvHit{i, 2, len(t)})
			}
		case userPassFlags[t] && userPassClients[client]:
			if v, ok := value(i); ok {
				if from, ok := userPassword(v); ok {
					hits = append(hits, argvHit{i + 1, from, len(v)})
				}
				i++
			}
		case strings.HasPrefix(t, "--") && userPassFlags[t[:max(strings.IndexByte(t, '='), 0)]] && userPassClients[client]:
			eq := strings.IndexByte(t, '=')
			if from, ok := userPassword(t[eq+1:]); ok {
				hits = append(hits, argvHit{i, eq + 1 + from, len(t)})
			}
		case t == "-a" && client == "redis-cli":
			if v, ok := value(i); ok {
				if passwordValue(v) {
					hits = append(hits, argvHit{i + 1, 0, len(v)})
				}
				i++
			}
		case t == "-k":
			if v, ok := value(i); ok && randomKey(v) {
				hits = append(hits, argvHit{i + 1, 0, len(v)})
				i++
			}
		case strings.HasPrefix(t, "--password=") && passwordClients[client] && client != "sshpass":
			// mysql --password=<pw>: whatever is stored, as glued to -p
			if passwordValue(t[len("--password="):]) {
				hits = append(hits, argvHit{i, len("--password="), len(t)})
			}
		case strings.HasPrefix(t, "--") && strings.Contains(t, "="):
			eq := strings.IndexByte(t, '=')
			if from, to, ok := secretFlagValueSpan(t[:eq], t[eq+1:]); isSecretFlag(t[:eq]) && ok {
				hits = append(hits, argvHit{i, eq + 1 + from, eq + 1 + to})
			}
		case flagShaped(t) && isSecretFlag(t):
			if v, ok := value(i); ok {
				if from, to, ok := secretFlagValueSpan(t, v); ok {
					hits = append(hits, argvHit{i + 1, from, to})
				}
				i++
			}
		}
	}
	return hits
}

// commandToken is one whitespace-separated word of a command line, with the
// quotes and punctuation around it stripped and the quotes inside it left
// out (-p"pw" is the word -ppw): word[i] is line[pos[i]], or line[from+i]
// when pos is nil (nothing was left out inside).
type commandToken struct {
	word     string
	from, to int
	pos      []int
}

// at is where word[i] is in the line.
func (t commandToken) at(i int) int {
	if t.pos == nil {
		return t.from + i
	}
	return t.pos[i]
}

// span is the part of the line holding word[a:b], from its first byte to its
// last (a quote left out inside lies between them).
func (t commandToken) span(a, b int) (int, int) {
	return t.at(a), t.at(b-1) + 1
}

var commandSeparators = map[string]bool{";": true, "&&": true, "||": true, "|": true, "&": true}

func isQuoteByte(ch byte) bool { return ch == '\'' || ch == '"' || ch == '`' }

// quotesBalanced: every kind of quote in s comes in pairs (escaped ones
// counted, so \"pw\" in a JSON string is a quoted word too).
func quotesBalanced(s string) bool {
	return strings.Count(s, "\"")%2 == 0 && strings.Count(s, "'")%2 == 0 && strings.Count(s, "`")%2 == 0
}

// commandSegments splits a line into the words of each command it runs:
// sh -c 'mysql …' && psql … is two segments, sh -c being the start of the
// first. Quotes around and inside a word are not part of it, at any depth of
// escaping (a JSON string's \" and \\\" alike), and $'…' quotes like '…'. A
// quote opening a string of several words ("sh -c 'mysql …'", a JSON value)
// starts a command of its own; one opening and closing a single word after
// a flag (-p "pw", -u \"u:pw\") is that flag's argument; a word with its
// quotes inside (-p"pw", --user="u:pw") ends nothing.
func commandSegments(line string) [][]commandToken {
	var segs [][]commandToken
	var cur []commandToken
	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, cur)
		}
		cur = nil
	}
	space := func(ch byte) bool { return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' }
	for i := 0; i < len(line); {
		for i < len(line) && space(line[i]) {
			i++
		}
		start := i
		for i < len(line) && !space(line[i]) {
			i++
		}
		if start == i {
			break
		}
		from, to := start, i
		begin := false
		for from < to {
			ch := line[from]
			ansiC := ch == '$' && from+1 < to && (line[from+1] == '\'' || line[from+1] == '"')
			if !ansiC && strings.IndexByte("'\"`([{,\\", ch) < 0 {
				break
			}
			begin = begin || isQuoteByte(ch)
			from++
		}
		end, semicolon := false, false
		for to > from && strings.IndexByte("'\"`)]},;\\", line[to-1]) >= 0 {
			end = end || isQuoteByte(line[to-1])
			semicolon = semicolon || line[to-1] == ';'
			to--
		}
		balanced := quotesBalanced(line[start:i])
		// a quoted word after a flag is the flag's argument
		argument := begin && balanced && len(cur) > 0 && flagShaped(cur[len(cur)-1].word)
		// a quote opens or closes a string: a command in one ("sh -c 'mysql
		// …'", a JSON value) is judged on its own, apart from its neighbours
		if begin && !argument {
			flush()
		}
		tok := quotesLeftOut(line, from, to)
		if commandSeparators[tok.word] {
			flush()
			continue
		}
		if tok.word != "" {
			cur = append(cur, tok)
		}
		if semicolon || end && !argument && !(balanced && !begin) {
			flush()
		}
	}
	flush()
	return segs
}

// quotesLeftOut is the word line[from:to] without the quotes inside it and
// the backslashes escaping them.
func quotesLeftOut(line string, from, to int) commandToken {
	if strings.IndexAny(line[from:to], "'\"`") < 0 {
		return commandToken{word: line[from:to], from: from, to: to}
	}
	var word []byte
	var pos []int
	for j := from; j < to; j++ {
		ch := line[j]
		if isQuoteByte(ch) {
			continue
		}
		if ch == '\\' {
			k := j
			for k < to && line[k] == '\\' {
				k++
			}
			if k < to && isQuoteByte(line[k]) {
				j = k - 1
				continue
			}
		}
		word = append(word, ch)
		pos = append(pos, j)
	}
	return commandToken{word: string(word), from: from, to: to, pos: pos}
}

// commandCredentials applies replace to every credential the argv rules
// find in the commands of a line of text.
func commandCredentials(line string, replace func(string) string) string {
	b := []byte(line)
	changed := false
	for _, seg := range commandSegments(line) {
		words := make([]string, len(seg))
		for i, t := range seg {
			words[i] = t.word
		}
		for _, h := range judgeArgv(words) {
			t := seg[h.tok]
			v := t.word[h.from:h.to]
			out := replace(v)
			if len(out) == len(v) {
				// in place, around any quote left out inside the value
				for k := 0; k < len(out); k++ {
					b[t.at(h.from+k)] = out[k]
				}
				changed = changed || out != v
				continue
			}
			// redaction changes the length: rebuild from the end backwards
			return commandCredentialsVariable(line, replace)
		}
	}
	if !changed {
		return line
	}
	return string(b)
}

// commandCredentialsVariable is commandCredentials for a replace that
// changes the length (redaction).
func commandCredentialsVariable(line string, replace func(string) string) string {
	type span struct{ from, to int }
	var spans []span
	for _, seg := range commandSegments(line) {
		words := make([]string, len(seg))
		for i, t := range seg {
			words[i] = t.word
		}
		for _, h := range judgeArgv(words) {
			from, to := seg[h.tok].span(h.from, h.to)
			spans = append(spans, span{from, to})
		}
	}
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		line = line[:sp.from] + replace(line[sp.from:sp.to]) + line[sp.to:]
	}
	return line
}

// argvLines is a cheap filter: a line that may hold a command's credential.
var argvHints = []string{"-p", "-a", "-k", "-u", "--", "mysql", "sshpass", "mariadb", "pgpassword", "rediscli_auth"}

// command: "x" / command = 'x' / {command: x, …} (YAML takes it unquoted)
var commandKey = regexp.MustCompile(`(?:^|[\s{,])["']?command["']?[ \t]*[:=][ \t]*(?:["']([^"'\r\n]+)["']|([^\s,{}\[\]"'#]+))`)

// commandOf is the command a commandKey match names.
func commandOf(m []string) string {
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

// enclosingScopes maps each '[' of s to the span of the object (or TOML
// table) holding it, so an args array finds its server's "command". Strings
// and comments are skipped.
func enclosingScopes(s string, toml bool) map[int][2]int {
	scopes := map[int][2]int{}
	var stack []int // positions of open brackets
	objEnd := map[int]int{}
	var arrays [][2]int // array open, enclosing '{' (-1: none)
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '"' || ch == '\'':
			for i++; i < len(s) && s[i] != ch && s[i] != '\n'; i++ {
				if s[i] == '\\' && !(toml && ch == '\'') {
					i++
				}
			}
		case ch == '#' && toml, ch == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case ch == '{' || ch == '[':
			if ch == '[' {
				obj := -1
				for k := len(stack) - 1; k >= 0; k-- {
					if s[stack[k]] == '{' {
						obj = stack[k]
						break
					}
				}
				arrays = append(arrays, [2]int{i, obj})
			}
			stack = append(stack, i)
		case ch == '}' || ch == ']':
			if len(stack) > 0 {
				if s[stack[len(stack)-1]] == '{' {
					objEnd[stack[len(stack)-1]] = i
				}
				stack = stack[:len(stack)-1]
			}
		}
	}
	for _, a := range arrays {
		if a[1] >= 0 {
			if end, ok := objEnd[a[1]]; ok {
				scopes[a[0]] = [2]int{a[1], end}
				continue
			}
		}
		// a TOML table: from its header to the next one
		from := strings.LastIndex(s[:a[0]], "\n[") + 1
		to := strings.Index(s[a[0]:], "\n[")
		if to < 0 {
			to = len(s)
		} else {
			to += a[0]
		}
		scopes[a[0]] = [2]int{from, to}
	}
	return scopes
}

// argvArraySpans judges every array of strings in a JSON, JSON5 or TOML
// text as an argv (the server's "command" in front when its object names
// one) and returns where the credentials are, in order.
func argvArraySpans(s string, toml bool) [][2]int {
	if !strings.Contains(s, "[") {
		return nil
	}
	var spans [][2]int
	for open, scope := range enclosingScopes(s, toml) {
		items := containerStrings(s, open, toml)
		if len(items) == 0 {
			continue
		}
		argv := make([]string, 0, len(items)+1)
		lead := 0
		if m := commandKey.FindStringSubmatch(s[scope[0]:scope[1]]); m != nil {
			argv = append(argv, commandOf(m))
			lead = 1
		}
		for _, it := range items {
			argv = append(argv, s[it.from:it.to])
		}
		for _, h := range judgeArgv(argv) {
			if h.tok >= lead {
				it := items[h.tok-lead]
				spans = append(spans, [2]int{it.from + h.from, it.from + h.to})
			}
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	return spans
}

// argvArrays disguises the credentials argvArraySpans finds, in place.
func (c *collector) argvArrays(s string, toml bool) string {
	spans := argvArraySpans(s, toml)
	if len(spans) == 0 {
		return s
	}
	b := []byte(s)
	for _, sp := range spans {
		copy(b[sp[0]:sp[1]], c.disguiseArgv(s[sp[0]:sp[1]]))
	}
	return string(b)
}

// redactArgvArrays replaces them with replace (command output: JSON a
// command printed, whose args arrays hold a server's credentials).
func redactArgvArrays(s string, replace string) string {
	spans := argvArraySpans(s, false)
	for i := len(spans) - 1; i >= 0; i-- {
		if i+1 < len(spans) && spans[i][1] > spans[i+1][0] {
			continue
		}
		s = s[:spans[i][0]] + replace + s[spans[i][1]:]
	}
	return s
}

var (
	yamlSeqItem    = regexp.MustCompile(`^([ \t]*)-[ \t]+(.*?)[ \t]*\r?$`)
	yamlCommandKey = regexp.MustCompile(`^([ \t]*)command:[ \t]+(.+?)[ \t]*\r?$`)
)

// yamlArgv judges each YAML block sequence of scalars as an argv, the
// "command:" beside its key in front.
func (c *collector) yamlArgv(s string) string {
	lines := strings.SplitAfter(s, "\n")
	starts := make([]int, len(lines))
	off := 0
	for i, l := range lines {
		starts[i] = off
		off += len(l)
		lines[i] = strings.TrimSuffix(l, "\n")
	}
	b := []byte(s)
	changed := false
	indentOf := func(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }
	for i := 0; i < len(lines); {
		m := yamlSeqItem.FindStringSubmatch(lines[i])
		if m == nil {
			i++
			continue
		}
		indent := len(m[1])
		type item struct{ from, to int }
		var items []item
		var argv []string
		j := i
		for ; j < len(lines); j++ {
			mm := yamlSeqItem.FindStringSubmatch(lines[j])
			if mm == nil || len(mm[1]) != indent {
				break
			}
			raw := mm[2]
			open, value, _ := scalarValue(raw)
			at := starts[j] + strings.Index(lines[j], raw) + len(open)
			items = append(items, item{at, at + len(value)})
			argv = append(argv, value)
		}
		// the key above the sequence and a command: beside it
		lead := 0
		for k := i - 1; k >= 0; k-- {
			if strings.TrimSpace(lines[k]) == "" {
				continue
			}
			keyIndent := indentOf(lines[k])
			for q := k; q >= 0 && q > k-40; q-- {
				if strings.TrimSpace(lines[q]) != "" && indentOf(lines[q]) < keyIndent {
					break
				}
				if cm := yamlCommandKey.FindStringSubmatch(lines[q]); cm != nil && len(cm[1]) == keyIndent {
					_, cmd, _ := scalarValue(cm[2])
					argv = append([]string{cmd}, argv...)
					lead = 1
					break
				}
			}
			break
		}
		for _, h := range judgeArgv(argv) {
			if h.tok < lead {
				continue
			}
			it := items[h.tok-lead]
			v := s[it.from+h.from : it.from+h.to]
			if out := c.disguiseArgv(v); out != v {
				copy(b[it.from+h.from:], out)
				changed = true
			}
		}
		i = j
	}
	if !changed {
		return s
	}
	return string(b)
}

// yamlFlowItem is one scalar of a YAML flow sequence: its value's span.
type yamlFlowItem struct{ from, to int }

// yamlFlowItems returns the scalars directly inside the flow sequence
// opening at open ([-p, "Tz4!…", ssh, host]), quoted or plain, and whether
// the sequence is flat (no nested [ ] or { }) and closes on its line.
func yamlFlowItems(s string, open int) ([]yamlFlowItem, bool) {
	var items []yamlFlowItem
	start := open + 1
	add := func(end int) {
		raw := s[start:end]
		lead := len(raw) - len(strings.TrimLeft(raw, " \t"))
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		q, value, _ := scalarValue(raw)
		at := start + lead + len(q)
		items = append(items, yamlFlowItem{at, at + len(value)})
	}
	for i := open + 1; i < len(s); i++ {
		switch ch := s[i]; ch {
		case '"', '\'':
			for i++; i < len(s) && s[i] != ch && s[i] != '\n'; i++ {
				if s[i] == '\\' && ch == '"' {
					i++
				}
			}
		case '[', '{', '\n', '#':
			return nil, false
		case ',':
			add(i)
			start = i + 1
		case ']':
			add(i)
			return items, true
		}
	}
	return nil, false
}

// yamlFlowArgv judges each flat YAML flow sequence (args: ["-p", x] or
// args: [-p, x], also inside {command: sshpass, args: [...]}) as an argv,
// the command beside it in front: in the same inline mapping, or a
// command: key at its key's indent in the block mapping around it.
func (c *collector) yamlFlowArgv(s string) string {
	if !strings.Contains(s, "[") {
		return s
	}
	b := []byte(s)
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] != '[' {
			continue
		}
		lineStart := strings.LastIndexByte(s[:i], '\n') + 1
		lineEnd := strings.IndexByte(s[i:], '\n')
		if lineEnd < 0 {
			lineEnd = len(s)
		} else {
			lineEnd += i
		}
		before := s[lineStart:i]
		if strings.Count(before, "\"")%2 == 1 || strings.Count(before, "'")%2 == 1 || strings.Contains(before, "#") || !strings.HasSuffix(strings.TrimRight(before, " \t"), ":") {
			continue
		}
		items, ok := yamlFlowItems(s, i)
		if !ok || len(items) == 0 {
			continue
		}
		cmd := ""
		if brace := strings.LastIndexByte(before, '{'); brace >= 0 {
			// {command: sshpass, args: [...]}: the mapping on this line
			if m := commandKey.FindStringSubmatch(s[lineStart+brace : lineEnd]); m != nil {
				cmd = commandOf(m)
			}
		} else {
			cmd = yamlSiblingCommand(s, lineStart)
		}
		argv := make([]string, 0, len(items)+1)
		lead := 0
		if cmd != "" {
			argv = append(argv, cmd)
			lead = 1
		}
		for _, it := range items {
			argv = append(argv, s[it.from:it.to])
		}
		for _, h := range judgeArgv(argv) {
			if h.tok < lead {
				continue
			}
			it := items[h.tok-lead]
			v := s[it.from+h.from : it.from+h.to]
			if out := c.disguiseArgv(v); out != v {
				copy(b[it.from+h.from:], out)
				changed = true
			}
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

// yamlSiblingCommand is the command: value of the block mapping holding the
// key on the line at lineStart (searched up and down at the key's indent).
func yamlSiblingCommand(s string, lineStart int) string {
	lines := strings.Split(s, "\n")
	at := strings.Count(s[:lineStart], "\n")
	indentOf := func(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }
	keyIndent := indentOf(lines[at])
	for _, dir := range []int{-1, 1} {
		for q := at + dir; q >= 0 && q < len(lines) && q > at-40 && q < at+40; q += dir {
			l := strings.TrimRight(lines[q], "\r")
			if strings.TrimSpace(l) == "" {
				continue
			}
			if indentOf(l) < keyIndent {
				break
			}
			if cm := yamlCommandKey.FindStringSubmatch(l); cm != nil && len(cm[1]) == keyIndent {
				_, cmd, _ := scalarValue(cm[2])
				return cmd
			}
		}
	}
	return ""
}
