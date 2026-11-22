package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sensitiveSinkPatterns mirrors SENSITIVE_SINKS in
// src/analyzers/sensitive-paths.ts pattern for pattern, in the same order
// (all case-insensitive there). The two lists must stay identical:
// TestSensitiveSinksMatchTS here and src/analyzers/sensitive-paths.test.ts
// on the TS side both fail when they drift.
var sensitiveSinkPatterns = []string{
	`(^|\/)\.ssh(\/|$)`,
	`authorized_keys`,
	`(^|\/)\.aws(\/|$)`,
	`(^|\/)\.gnupg(\/|$)`,
	`(^|\/)\.kube(\/|$)`,
	`(^|\/)\.docker(\/|$)`,
	`(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin)$`,
	`^\/etc(\/|$)`,
	`(^|\/)\.config\/gh(\/|$)`,
	`(^|\/)\.config\/gcloud(\/|$)`,
	`(^|\/)\.azure(\/|$)`,
	`(^|\/)\.password-store(\/|$)`,
	`(^|\/)Library\/Keychains(\/|$)`,
	`(^|\/)\.codex\/auth\.json$`,
	`(^|\/)\.(netrc|git-credentials|pgpass|pypirc|npmrc)$`,
	`(^|\/)(Library\/Application Support\/(Google\/Chrome|Chromium|BraveSoftware|Microsoft Edge|Firefox|Arc)|\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)|\.mozilla|Library\/Cookies)(\/|$)`,
	`(^|\/)\.claude\/\.credentials\.json$`,
	`(^|\/)(\.local\/share\/opencode|\.config\/nanoclaw|\.hermes|\.(openclaw(-[^/]+)?|clawdbot)(\/agents\/[^/]+\/agent)?)\/(auth|auth-profiles|auth-state|credentials|account|registry-auth|device-key)\.json$`,
	`(^|\/)\.(openclaw(-[^/]+)?|clawdbot)\/credentials(\/|$)|(^|\/)\.hermes\/mcp-tokens(\/|$)|(^|\/)\.nanobot\/(auth|whatsapp-auth)(\/|$)`,
	`(^|\/)\.(gemini|qwen)\/(oauth_creds|google_accounts|mcp-oauth-tokens|a2a-oauth-tokens)\.json$`,
	`(^|\/)\.local\/share\/devin\/credentials\.toml$|(^|\/)\.abacusai\/keystore\.enc[^/]*$`,
	`(^|\/)(\.grokbot|\.cursor\/sand|sand-data)\/(local-exec-daemon-credential|host-token)\.json$|(^|\/)Grok Bot\/(sand|user)-secrets\.json$`,
	`(^|\/)\.ironclaw\/reborn\/(webui-token|([^/]+\/)?\.reborn-local-dev-secrets-master-key)$|(^|\/)\.?zeroclaw\/\.secret_key$`,
	`(^|\/)openshell\/(gateway\/credentials|docker-sandbox-tokens|gateways\/[^/]+\/mtls)(\/|$)|(^|\/)openshell\/gateways\/[^/]+\/(?:oidc_token\.json|edge_token)$`,
	`(^|\/)\.(vault-token|my\.cnf|mylogin\.cnf|s3cfg|boto)$|(^|\/)\.cargo\/credentials(\.toml)?$|(^|\/)\.config\/rclone\/rclone\.conf$|(^|\/)\.terraform\.d\/credentials\.tfrc\.json$`,
	`(^|\/)\.local\/share\/keyrings(\/|$)`,
	`(^|\/)\.(bash|zsh|sh|python|psql|mysql|sqlite|node_repl|rediscli)_history$|(^|\/)\.zsh_sessions(\/|$)|(^|\/)\.local\/share\/fish\/fish_history$`,
}

var sensitiveSinks = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(sensitiveSinkPatterns))
	for i, p := range sensitiveSinkPatterns {
		res[i] = regexp.MustCompile("(?i)" + p)
	}
	return res
}()

// credentialStoreSinks: the sinks (by index) that are other tools'
// credential-store folders — ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker,
// ~/.config/gh, ~/.config/gcloud, ~/.azure, ~/.password-store,
// ~/Library/Keychains, browser profiles, ~/.local/share/keyrings. Mirrors CREDENTIAL_STORE_SINKS in
// src/analyzers/sensitive-paths.ts (its test reads this list).
var credentialStoreSinks = []int{0, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 25}

// inCredentialStore: p, as written, lies in one of credentialStoreSinks. No
// agent keeps its configuration there; an agent folder an environment
// variable puts there (COPILOT_HOME=~/.aws/cop) ships no content.
func inCredentialStore(p string) bool {
	slash := filepath.ToSlash(p)
	for _, i := range credentialStoreSinks {
		if sensitiveSinks[i].MatchString(slash) {
			return true
		}
	}
	return false
}

// sinkSet is the set of sensitive sinks (by index) a path matches.
func sinkSet(p string) map[int]bool {
	set := make(map[int]bool)
	slash := filepath.ToSlash(p)
	for i, re := range sensitiveSinks {
		if re.MatchString(slash) {
			set[i] = true
		}
	}
	return set
}

// escapesToSink reports whether p is reached through a symlink — base
// itself or a path component below it — that points into a sensitive
// location base does not already name. base is the part of the path VASO
// chose: an explicit manifest path, or a glob's static prefix. A skill linking
// to ~/.ssh or ~/.aws/credentials is the GhostApproval artefact SKL-013
// reports from the link target; the content behind it never leaves the host.
// A unit under /etc/systemd/system linking elsewhere in /etc is not an
// escape, and neither is a real directory that happens to be named .ssh.
// Mirrors sinkLink in src/core/skill-walk.ts.
func escapesToSink(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	named := sinkSet(base)
	if linkIntoSink(base, named) {
		return true
	}
	if rel == "." {
		return false
	}
	cur := base
	for _, comp := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, comp)
		if linkIntoSink(cur, named) {
			return true
		}
	}
	return false
}

// linkIntoSink: link is a symlink whose target — resolved, or as written
// (macOS resolves /etc to /private/etc) — matches a sink outside named.
func linkIntoSink(link string, named map[int]bool) bool {
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	var targets []string
	// spelled as stored (realPath): `.ßh` opens `.ssh` on a case-insensitive
	// volume, and only the stored name is a sink
	if real, err := realPath(link); err == nil {
		targets = append(targets, real)
	}
	if raw, err := os.Readlink(link); err == nil {
		if !filepath.IsAbs(raw) {
			raw = filepath.Join(filepath.Dir(link), raw)
		}
		targets = append(targets, filepath.Clean(raw))
	}
	for _, t := range targets {
		for i := range sinkSet(t) {
			if !named[i] {
				return true
			}
		}
	}
	return false
}

// resolvedIntoSink: the file at p really is in a sensitive location (a
// credential store, an agent's token file) that neither the part of the path
// VASO named (base) nor p's own spelling names — reached through a linked
// directory above it, not a link escapesToSink sees below base: a skills dir
// linked to ~/.claude lists .credentials.json, one linked to ~/.config lists
// gh/hosts.yml. Mirrors inSinkByTarget in src/core/skill-walk.ts.
func resolvedIntoSink(p, base string) bool {
	real, err := realPath(p)
	if err != nil {
		return false
	}
	real = filepath.Clean(real)
	if real == filepath.Clean(p) {
		return false
	}
	named := sinkSet(base)
	for i := range sinkSet(p) {
		named[i] = true
	}
	for i := range sinkSet(real) {
		if !named[i] {
			return true
		}
	}
	return false
}
