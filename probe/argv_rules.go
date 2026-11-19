package main

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
//  7. Other clients' password options take any stored value
//     (clientPasswordFlags): sqlcmd/bcp -P, a registry login's -p/--password,
//     smbclient -U user%<pw>, lftp -u user,<pw>, the OpenLDAP tools' -w,
//     the MongoDB tools' -p/--password, htpasswd -b's last argument, a
//     FreeRDP client's /p:<pw>.
//  8. What echo or printf pipes into sudo -S or a registry login's
//     --password-stdin is the password.
//
// In a command string the words are what the shell assembles
// (commandSegments): -p"pass phrase", '-p'"pw", "-ppw" and -p$'pw' are each
// one word.

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
// segment of one: the caller splits at ; && ||). A "|" token separates the
// commands of a pipeline: each is judged on its own, and text echoed into a
// command that reads its password from stdin is that password (rule 8).
func judgeArgv(tokens []string) []argvHit {
	var hits []argvHit
	start := 0
	for i := 0; i <= len(tokens); i++ {
		if i < len(tokens) && tokens[i] != "|" {
			continue
		}
		for _, h := range judgeCommand(tokens[start:i]) {
			h.tok += start
			hits = append(hits, h)
		}
		start = i + 1
	}
	return distinctHits(append(hits, stdinPasswordHits(tokens)...))
}

// distinctHits drops a hit overlapping an earlier one in the same token.
func distinctHits(hits []argvHit) []argvHit {
	var out []argvHit
next:
	for _, h := range hits {
		for _, o := range out {
			if o.tok == h.tok && h.from < o.to && o.from < h.to {
				continue next
			}
		}
		out = append(out, h)
	}
	return out
}

// judgeCommand returns the credentials among the words of one command.
func judgeCommand(tokens []string) []argvHit {
	var hits []argvHit
	client := ""
	value := func(i int) (string, bool) {
		if i+1 >= len(tokens) || flagShaped(tokens[i+1]) {
			return "", false
		}
		return tokens[i+1], true
	}
words:
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		switch {
		case t == "--":
			// end of options: the rest are positionals
			break words
		case clientPasswordVar.MatchString(t):
			// MYSQL_PWD=<pw> mysql, PGPASSWORD=<pw> psql (rule 6)
			// a value with whitespace in it is a script, not one password
			// (`sh -c "PGPASSWORD=pw psql …"` is read word by word)
			eq := strings.IndexByte(t, '=')
			if v := t[eq+1:]; passwordValue(v) && !strings.ContainsAny(v, " \t\r\n") {
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
		case flagShaped(t) && isSecretFlag(t) && !strings.HasSuffix(t, "-stdin"):
			// (--password-stdin is a switch: the password comes from stdin)
			if v, ok := value(i); ok {
				if from, to, ok := secretFlagValueSpan(t, v); ok {
					hits = append(hits, argvHit{i + 1, from, to})
				}
				i++
			}
		}
	}
	return append(hits, clientPasswordHits(tokens)...)
}

// passwordFlag is an option through which a client takes its password:
// short (-P <v>, or glued -P<v>) or long (--password <v>, --password=<v>).
// With sep, the value is user<sep>password and the password is what follows
// the first sep.
type passwordFlag struct {
	flag string
	sep  byte
}

var (
	smbPasswordFlags   = []passwordFlag{{"-U", '%'}, {"--user", '%'}, {"--password", 0}}
	ldapPasswordFlags  = []passwordFlag{{"-w", 0}}
	mongoPasswordFlags = []passwordFlag{{"-p", 0}, {"--password", 0}}
	// clientPasswordFlags: the password options of other clients (rule 7).
	// "login" is a registry CLI's login subcommand (docker login, helm
	// registry login).
	clientPasswordFlags = map[string][]passwordFlag{
		"sqlcmd": {{"-P", 0}, {"-z", 0}, {"-Z", 0}},
		"bcp":    {{"-P", 0}},
		"login":  {{"-p", 0}, {"--password", 0}},
		"lftp":   {{"-u", ','}},

		"smbclient": smbPasswordFlags, "rpcclient": smbPasswordFlags, "smbcacls": smbPasswordFlags, "smbcquotas": smbPasswordFlags,

		"ldapsearch": ldapPasswordFlags, "ldapadd": ldapPasswordFlags, "ldapmodify": ldapPasswordFlags, "ldapdelete": ldapPasswordFlags,
		"ldapmodrdn": ldapPasswordFlags, "ldapcompare": ldapPasswordFlags, "ldapwhoami": ldapPasswordFlags, "ldapexop": ldapPasswordFlags,
		"ldappasswd": {{"-w", 0}, {"-a", 0}, {"-s", 0}},

		"mongo": mongoPasswordFlags, "mongosh": mongoPasswordFlags, "mongodump": mongoPasswordFlags, "mongorestore": mongoPasswordFlags,
		"mongoexport": mongoPasswordFlags, "mongoimport": mongoPasswordFlags, "mongostat": mongoPasswordFlags, "mongotop": mongoPasswordFlags,
		"mongofiles": mongoPasswordFlags,
	}
	// registryCLIs: commands whose login subcommand takes -p/--password
	registryCLIs = map[string]bool{"docker": true, "podman": true, "nerdctl": true, "buildah": true, "skopeo": true, "oras": true, "helm": true}
	// rdpClients: FreeRDP clients (/p:<password>, 2.x /gp:<password>)
	rdpClients = map[string]bool{"xfreerdp": true, "xfreerdp3": true, "wlfreerdp": true, "wlfreerdp3": true, "sdl-freerdp": true, "sdl-freerdp3": true, "wfreerdp": true}
	// echo's own options (echo -n pw | sudo -S)
	echoOption = regexp.MustCompile(`^-[neE]+$`)
	// sudo options that take a value (the next word is not an option)
	sudoValueOption = map[string]bool{"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-R": true, "-T": true, "-U": true, "-r": true, "-t": true}
)

// commandBase is the command a word names, by its file name, lowercased and
// without .exe (sqlcmd.exe).
func commandBase(t string) string {
	return strings.TrimSuffix(clientName(t), ".exe")
}

// clientPasswordHits returns the passwords given through clientPasswordFlags,
// a FreeRDP client's /p:, and htpasswd -b's password argument (rule 7).
func clientPasswordHits(tokens []string) []argvHit {
	var hits []argvHit
	add := func(tok, from int, sep byte) {
		v := tokens[tok][from:]
		if sep != 0 {
			k := strings.IndexByte(v, sep)
			if k < 0 {
				return
			}
			from += k + 1
			v = v[k+1:]
		}
		// --password - reads it from stdin; a URL is the server (mongosh -p <url> prompts)
		if passwordValue(v) && v != "-" && !strings.Contains(v, "://") {
			hits = append(hits, argvHit{tok, from, len(tokens[tok])})
		}
	}
	client := ""
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if t == "--" {
			break
		}
		if !strings.HasPrefix(t, "-") {
			switch name := commandBase(t); {
			case rdpClients[client] && strings.HasPrefix(t, "/p:"):
				add(i, len("/p:"), 0)
			case rdpClients[client] && strings.HasPrefix(t, "/gp:"):
				add(i, len("/gp:"), 0)
			case name == "htpasswd":
				return append(hits, htpasswdHits(tokens, i)...)
			case name == "login" && registryCLIs[client]:
				client = "login"
			case clientPasswordFlags[name] != nil || registryCLIs[name] || rdpClients[name]:
				client = name
			}
			continue
		}
		for _, f := range clientPasswordFlags[client] {
			long := strings.HasPrefix(f.flag, "--")
			if t == f.flag {
				if i+1 < len(tokens) && !flagShaped(tokens[i+1]) {
					add(i+1, 0, f.sep)
					i++
				}
				break
			}
			if long && strings.HasPrefix(t, f.flag+"=") {
				add(i, len(f.flag)+1, f.sep)
				break
			}
			if !long && strings.HasPrefix(t, f.flag) {
				add(i, len(f.flag), f.sep)
				break
			}
		}
	}
	return hits
}

// htpasswdHits: htpasswd -b takes the password as its last argument
// (htpasswd -b[c] file user password, htpasswd -nb user password).
func htpasswdHits(tokens []string, at int) []argvHit {
	batch, noFile := false, false
	var positional []int
	for j := at + 1; j < len(tokens); j++ {
		t := tokens[j]
		if len(positional) == 0 && len(t) > 1 && t[0] == '-' {
			for k := 1; k < len(t); k++ {
				switch t[k] {
				case 'b':
					batch = true
				case 'n':
					noFile = true
				case 'C', 'r':
					// -C cost, -r rounds: the value is the next word or glued
					if k == len(t)-1 {
						j++
					}
					k = len(t)
				}
			}
			continue
		}
		positional = append(positional, j)
	}
	want := 2
	if noFile {
		want = 1
	}
	if !batch || len(positional) <= want || !passwordValue(tokens[positional[want]]) {
		return nil
	}
	p := positional[want]
	return []argvHit{{p, 0, len(tokens[p])}}
}

// stdinPasswordHits: what echo or printf pipes into a command that reads its
// password from stdin (echo pw | sudo -S, | docker login --password-stdin).
func stdinPasswordHits(tokens []string) []argvHit {
	var hits []argvHit
	start, prev := 0, -1
	for i := 0; i <= len(tokens); i++ {
		if i < len(tokens) && tokens[i] != "|" {
			continue
		}
		if prev >= 0 && readsPasswordFromStdin(tokens[start:i]) {
			hits = append(hits, echoedText(tokens, prev, start-1)...)
		}
		prev, start = start, i+1
	}
	return hits
}

// echoedText is the text echo or printf in tokens[from:to] prints, word by word.
func echoedText(tokens []string, from, to int) []argvHit {
	if from >= to {
		return nil
	}
	k := from + 1
	switch commandBase(tokens[from]) {
	case "echo":
		for k < to && echoOption.MatchString(tokens[k]) {
			k++
		}
	case "printf":
		if k < to && tokens[k] == "--" {
			k++
		}
		// printf '%s\n' pw prints its arguments; printf 'pw\n' its format
		if k < to && strings.Contains(tokens[k], "%") {
			k++
		}
	default:
		return nil
	}
	var hits []argvHit
	for ; k < to; k++ {
		if passwordValue(tokens[k]) {
			hits = append(hits, argvHit{k, 0, len(tokens[k])})
		}
	}
	return hits
}

// readsPasswordFromStdin: sudo -S/--stdin, or a registry login with
// --password-stdin or --password - / -p -.
func readsPasswordFromStdin(tokens []string) bool {
	client := ""
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		name := commandBase(t)
		if name == "sudo" && client == "" {
			client = name
			for j := i + 1; j < len(tokens) && strings.HasPrefix(tokens[j], "-") && tokens[j] != "--"; j++ {
				o := tokens[j]
				if o == "--stdin" || !strings.HasPrefix(o, "--") && strings.Contains(o, "S") && flagShapedRe.MatchString(o) {
					return true
				}
				if sudoValueOption[o] {
					j++
				}
			}
			continue
		}
		switch {
		case registryCLIs[name] && (client == "" || client == "sudo"):
			client = name
		case name == "login" && registryCLIs[client]:
			client = "login"
		case client == "login" && (t == "--password-stdin" || t == "--password=-" || (t == "--password" || t == "-p") && i+1 < len(tokens) && tokens[i+1] == "-"):
			return true
		}
	}
	return false
}

// commandToken is one word of a command line as the shell assembles it: the
// quotes around and inside it left out, at any depth of escaping (-p"pw",
// '-p'"pw" and "-ppw" are all the word -ppw), a quoted part spanning spaces
// kept whole (-p"pass phrase"), $'…' read as bash reads it. word[i] is
// line[pos[i]] (line[from+i] when pos is nil); a character decoded from a
// $'…' escape is written as line[pos[i]:ends[i]].
type commandToken struct {
	word     string
	from, to int
	pos      []int
	ends     []int
}

// at is where word[i] is in the line.
func (t commandToken) at(i int) int {
	if t.pos == nil {
		return t.from + i
	}
	return t.pos[i]
}

// end is where word[i] ends in the line.
func (t commandToken) end(i int) int {
	if t.ends == nil {
		return t.at(i) + 1
	}
	return t.ends[i]
}

// span is the part of the line holding word[a:b], from its first byte to its
// last (a quote left out inside lies between them).
func (t commandToken) span(a, b int) (int, int) {
	return t.at(a), t.end(b - 1)
}

// literal: word[a:b] is written in the line byte for byte (no escape decoded).
func (t commandToken) literal(a, b int) bool {
	for i := a; t.ends != nil && i < b; i++ {
		if t.ends[i] != t.pos[i]+1 {
			return false
		}
	}
	return true
}

// commandSegment is one command of a line; pipe: its output is piped into
// the next one.
type commandSegment struct {
	tokens []commandToken
	pipe   bool
}

var commandSeparators = map[string]bool{";": true, "&&": true, "||": true, "|": true, "&": true}

func isQuoteByte(ch byte) bool { return ch == '\'' || ch == '"' || ch == '`' }

// escapesBefore is the number of backslashes right before line[p]: how
// deeply a quote is escaped (" in a shell line, \" in a JSON string, \\\"
// in a shell string inside one).
func escapesBefore(line string, p int) int {
	k := 0
	for p-k > 0 && line[p-k-1] == '\\' {
		k++
	}
	return k
}

// sameQuote: line[p] closes the quote line[q] opened — the same character,
// escaped as deeply.
func sameQuote(line string, p, q int) bool {
	return line[p] == line[q] && escapesBefore(line, p) == escapesBefore(line, q)
}

// closingQuotes maps each quote of the line to the next sameQuote: the
// quote that closes it if it opens one.
func closingQuotes(line string) map[int]int {
	type kind struct {
		ch byte
		k  int
	}
	next := map[int]int{}
	last := map[kind]int{}
	for p := len(line) - 1; p >= 0; p-- {
		if !isQuoteByte(line[p]) {
			continue
		}
		kd := kind{line[p], escapesBefore(line, p)}
		if q, ok := last[kd]; ok {
			next[p] = q
		}
		last[kd] = p
	}
	return next
}

// pairQuotes continues pairing the quotes of line[from:to] with open the
// quote still open before (-1: none) and returns the one still open after
// (-1: none). A quote of another kind inside an open one is part of it.
func pairQuotes(line string, from, to, open int) int {
	for p := from; p < to; p++ {
		if !isQuoteByte(line[p]) {
			continue
		}
		if open < 0 {
			open = p
		} else if sameQuote(line, p, open) {
			open = -1
		}
	}
	return open
}

// closesInside: w ends with a bracket that closes one opened in it (the }
// of ${PASSWORD}, the ) of $(cat f)): part of the word, not punctuation
// around it.
func closesInside(w string) bool {
	open := map[byte]byte{'}': '{', ')': '(', ']': '['}[w[len(w)-1]]
	return open != 0 && strings.Count(w, string(open)) >= strings.Count(w, w[len(w)-1:])
}

// wordAfter: line[from:to] holds more of the word than closing punctuation.
func wordAfter(line string, from, to int) bool {
	for p := from; p < to; p++ {
		if strings.IndexByte("'\"`)]},;\\", line[p]) < 0 {
			return true
		}
	}
	return false
}

// commandSegments splits a line into the words of each command it runs:
// sh -c 'mysql …' && psql … is two segments, sh -c being the start of the
// first. A word is what the shell assembles: quoted and unquoted parts
// written together are one word ('-p'"pw"), and a quote opened inside a word
// (-p"pass phrase", -p\"pass phrase\" in a JSON string) runs to its closing
// quote across spaces. A word that is one quoted string ("-ppw", -p "pw")
// belongs to its command; a quote opening a string of several words ("sh -c
// 'mysql …'", a JSON value) starts a command of its own — after a flag it is
// also that flag's argument (sshpass -p "pass phrase"). A quoted word with
// data punctuation around it (["-p", "x"]: an array item) stands alone.
func commandSegments(line string) []commandSegment {
	var segs []commandSegment
	var cur []commandToken
	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, commandSegment{tokens: cur})
		}
		cur = nil
	}
	var closing map[int]int
	if strings.IndexAny(line, "'\"`") >= 0 {
		closing = closingQuotes(line)
	}
	space := func(ch byte) bool { return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' }
	chunkEnd := func(i int) int {
		for i < len(line) && !space(line[i]) {
			i++
		}
		return i
	}
	for i := 0; i < len(line); {
		for i < len(line) && space(line[i]) {
			i++
		}
		start := i
		i = chunkEnd(i)
		if start == i {
			break
		}
		from := start
		begin := false
		for from < i {
			ch := line[from]
			ansiC := dollarQuote(line, from, i) > 0
			if !ansiC && strings.IndexByte("'\"`([{,\\", ch) < 0 {
				break
			}
			begin = begin || isQuoteByte(ch)
			from++
		}
		open := pairQuotes(line, start, i, -1)
		// a quote opened inside the word: the word runs to its closing quote
		for open >= from && wordAfter(line, open+1, i) {
			c, ok := closing[open]
			if !ok {
				break
			}
			scanned := i
			i = chunkEnd(c + 1)
			open = pairQuotes(line, scanned, i, open)
		}
		to := i
		end, semicolon := false, false
		for to > from && strings.IndexByte("'\"`)]},;\\", line[to-1]) >= 0 && !closesInside(line[from:to]) {
			end = end || isQuoteByte(line[to-1])
			semicolon = semicolon || line[to-1] == ';'
			to--
		}
		balanced := open < 0
		structural := strings.ContainsAny(line[start:from], "([{,") || strings.ContainsAny(line[to:i], ")]},")
		prevFlag := len(cur) > 0 && flagShaped(cur[len(cur)-1].word)
		// a quoted word after a flag is the flag's argument
		argument := begin && balanced && prevFlag
		// a word that is one quoted string belongs to its command
		single := begin && balanced && !structural
		if begin && !argument && !single {
			// a quote opens a string of several words: a command in one ("sh
			// -c 'mysql …'", a JSON value) is judged on its own; after a flag
			// the string is that flag's argument too (sshpass -p "a b")
			if c, ok := closing[open]; ok && !balanced && open < from && prevFlag {
				if inner := c - escapesBefore(line, c); inner > open+1 {
					cur = append(cur, quotesLeftOut(line, open+1, inner))
				}
			}
			flush()
		}
		tok := quotesLeftOut(line, from, to)
		if commandSeparators[tok.word] {
			flush()
			if tok.word == "|" && len(segs) > 0 {
				segs[len(segs)-1].pipe = true
			}
			continue
		}
		if tok.word != "" {
			cur = append(cur, tok)
		}
		if semicolon || end && !argument && !single && !(balanced && !begin) {
			flush()
		}
	}
	flush()
	return segs
}

// ansiEscapes: bash's $'…' backslash escapes.
var ansiEscapes = map[byte]string{'a': "\a", 'b': "\b", 'e': "\x1b", 'E': "\x1b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t", 'v': "\v", '\\': "\\", '\'': "'", '"': "\"", '?': "?"}

var (
	ansiHex   = regexp.MustCompile(`^x([0-9A-Fa-f]{1,2})`)
	ansiOctal = regexp.MustCompile(`^[0-7]{1,3}`)
)

// ansiEscape decodes the escape at the start of s (just after a backslash in
// $'…'): its text and how many bytes of s it takes.
func ansiEscape(s string) (string, int) {
	if t, ok := ansiEscapes[s[0]]; ok {
		return t, 1
	}
	if m := ansiHex.FindStringSubmatch(s[:min(len(s), 3)]); m != nil {
		n, _ := strconv.ParseUint(m[1], 16, 8)
		return string([]byte{byte(n)}), len(m[0])
	}
	if m := ansiOctal.FindString(s[:min(len(s), 3)]); m != "" {
		n, _ := strconv.ParseUint(m, 8, 16)
		return string([]byte{byte(n)}), len(m)
	}
	return "\\" + s[:1], 1
}

// dollarQuote: line[j] is the $ of $'…' or $"…" — the latter also with its
// quote escaped (sshpass -p $\"pw\" in a JSON string) — and the index of
// that quote; 0 otherwise. A $ before an escaped ' is a plain $.
func dollarQuote(line string, j, to int) int {
	if line[j] != '$' || j+1 >= to {
		return 0
	}
	if line[j+1] == '\'' {
		return j + 1
	}
	k := j + 1
	for k < to && line[k] == '\\' {
		k++
	}
	if k < to && line[k] == '"' {
		return k
	}
	return 0
}

// quotesLeftOut is the word line[from:to] without the quotes inside it and
// the backslashes escaping them; $'…' is read as bash does, its escapes
// decoded ($"…" quotes like "…").
func quotesLeftOut(line string, from, to int) commandToken {
	if strings.IndexAny(line[from:to], "'\"`") < 0 {
		return commandToken{word: line[from:to], from: from, to: to}
	}
	var word []byte
	var pos, ends []int
	decoded, ansi := false, false
	for j := from; j < to; j++ {
		ch := line[j]
		switch {
		case ansi && ch == '\\' && j+1 < to:
			text, n := ansiEscape(line[j+1 : to])
			for k := 0; k < len(text); k++ {
				word = append(word, text[k])
				pos = append(pos, j)
				ends = append(ends, j+1+n)
			}
			decoded = true
			j += n
			continue
		case ansi && ch == '\'':
			ansi = false
			continue
		case ansi:
		case dollarQuote(line, j, to) > 0:
			q := dollarQuote(line, j, to)
			ansi = line[q] == '\''
			// $\"…\" in a JSON string: its quote's backslashes go too
			j = q
			continue
		case isQuoteByte(ch):
			continue
		case ch == '\\':
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
		ends = append(ends, j+1)
	}
	tok := commandToken{word: string(word), from: from, to: to, pos: pos}
	if decoded {
		tok.ends = ends
	}
	return tok
}

// commandPipelines is a line's commands as judgeArgv reads them: the words
// of each pipeline, its commands separated by a "|" token.
func commandPipelines(line string) [][]commandToken {
	var out [][]commandToken
	var cur []commandToken
	for _, seg := range commandSegments(line) {
		cur = append(cur, seg.tokens...)
		if seg.pipe {
			cur = append(cur, commandToken{word: "|"})
			continue
		}
		out = append(out, cur)
		cur = nil
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func tokenWords(toks []commandToken) []string {
	words := make([]string, len(toks))
	for i, t := range toks {
		words[i] = t.word
	}
	return words
}

// commandCredentials applies replace to every credential the argv rules
// find in the commands of a line of text.
func commandCredentials(line string, replace func(string) string) string {
	b := []byte(line)
	changed := false
	for _, toks := range commandPipelines(line) {
		for _, h := range judgeArgv(tokenWords(toks)) {
			t := toks[h.tok]
			if !t.literal(h.from, h.to) {
				// written with $'…' escapes: what is written is disguised
				from, to := t.span(h.from, h.to)
				v := line[from:to]
				out := replace(v)
				if len(out) != len(v) {
					return commandCredentialsVariable(line, replace)
				}
				copy(b[from:to], out)
				changed = changed || out != v
				continue
			}
			v := t.word[h.from:h.to]
			out := replace(v)
			if len(out) != len(v) {
				// redaction changes the length: rebuild from the end backwards
				return commandCredentialsVariable(line, replace)
			}
			// in place, around any quote left out inside the value
			for k := 0; k < len(out); k++ {
				b[t.at(h.from+k)] = out[k]
			}
			changed = changed || out != v
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
	for _, toks := range commandPipelines(line) {
		for _, h := range judgeArgv(tokenWords(toks)) {
			from, to := toks[h.tok].span(h.from, h.to)
			spans = append(spans, span{from, to})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].from < spans[j].from })
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		if i > 0 && spans[i-1].to > sp.from {
			continue
		}
		line = line[:sp.from] + replace(line[sp.from:sp.to]) + line[sp.to:]
	}
	return line
}

// argvLines is a cheap filter: a line that may hold a command's credential.
var argvHints = []string{"-p", "-a", "-k", "-u", "--", "-w", "-z", "/p:", "/gp:", "mysql", "sshpass", "mariadb", "pgpassword", "rediscli_auth", "htpasswd", "sudo"}

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
		// the array's own strings: those of an object inside it are values
		// (hooks: [{command: "PGPASSWORD=… psql …"}]), not argv words
		var items []containerString
		for _, it := range containerStrings(s, open, toml) {
			if it.key == "" && it.depth == 1 {
				items = append(items, it)
			}
		}
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

// stringCommands applies replace (same length) to the credentials of the
// command lines a JSON, JSON5 or TOML text holds as string values ("command":
// "MYSQL_PWD=… mysql …"), each string judged as a line of its own. A
// compact file is one line whose quotes run together, which the line rules
// read as one word.
func stringCommands(s string, replace func(string) string) string {
	var b []byte
	for _, q := range quotedStrings(s, 0) {
		v := s[q.from:q.to]
		if !strings.ContainsAny(v, " \t") || !hasArgvHint(v) {
			continue
		}
		out := commandCredentials(v, replace)
		if out == v || len(out) != len(v) {
			continue
		}
		if b == nil {
			b = []byte(s)
		}
		copy(b[q.from:q.to], out)
	}
	if b == nil {
		return s
	}
	return string(b)
}

// hasArgvHint: v holds a word of argvHints (case-insensitive).
func hasArgvHint(v string) bool {
	lower := strings.ToLower(v)
	for _, w := range argvHints {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
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
