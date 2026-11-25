/**
 * Shared catalogue of filesystem paths whose exposure to an agent turns a
 * tool-poisoning, prompt-injection, or symlink-following bug into remote
 * access, persistence, or credential theft. Kept in one place so the MCP
 * filesystem-scope detector (MCP-031) and the symlink-escape detector
 * (SKL-013, GhostApproval / CWE-61) classify the same targets identically.
 */

export interface SensitiveSink {
  re: RegExp;
  label: string;
}

// `iu`: Unicode case folding, as the probe's `(?i)` folds (ſ is s, the
// Kelvin sign K is k) — a case-insensitive volume opens `.ſſh` as `.ssh`.
export const SENSITIVE_SINKS: SensitiveSink[] = [
  { re: /(^|\/)\.ssh(\/|$)/iu, label: 'SSH keys/config (~/.ssh)' },
  { re: /authorized_keys/iu, label: 'SSH authorized_keys (remote-access persistence)' },
  { re: /(^|\/)\.aws(\/|$)/iu, label: 'AWS credentials (~/.aws)' },
  { re: /(^|\/)\.gnupg(\/|$)/iu, label: 'GnuPG keyring (~/.gnupg)' },
  { re: /(^|\/)\.kube(\/|$)/iu, label: 'Kubernetes credentials (~/.kube)' },
  { re: /(^|\/)\.docker(\/|$)/iu, label: 'Docker credentials (~/.docker)' },
  { re: /(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin)$/iu, label: 'shell startup file (code-execution persistence)' },
  { re: /^\/etc(\/|$)/iu, label: 'system configuration (/etc)' },
  { re: /(^|\/)\.config\/gh(\/|$)/iu, label: 'GitHub CLI credentials (~/.config/gh)' },
  { re: /(^|\/)\.config\/gcloud(\/|$)/iu, label: 'Google Cloud credentials (~/.config/gcloud)' },
  { re: /(^|\/)\.azure(\/|$)/iu, label: 'Azure credentials (~/.azure)' },
  { re: /(^|\/)\.password-store(\/|$)/iu, label: 'password store credentials (~/.password-store)' },
  { re: /(^|\/)Library\/Keychains(\/|$)/iu, label: 'macOS keychain credentials (~/Library/Keychains)' },
  { re: /(^|\/)\.codex\/auth\.json$/iu, label: 'Codex credentials (~/.codex/auth.json)' },
  { re: /(^|\/)\.(netrc|git-credentials|pgpass|pypirc|npmrc)$/iu, label: 'credentials file (.netrc, .git-credentials, .pgpass, .pypirc, .npmrc)' },
  { re: /(^|\/)(Library\/Application Support\/(Google\/Chrome|Chromium|BraveSoftware|Microsoft Edge|Firefox|Arc)|\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)|\.mozilla|Library\/Cookies)(\/|$)/iu, label: 'browser profile credentials (cookies, saved passwords)' },
  // Agents' own token stores — the credential files the probe manifest
  // already ships as metadata only (guard test in sensitive-paths.test.ts).
  // Copilot CLI's mcp-secrets / mcp-oauth-config are private stores, judged
  // by store-links.ts. Appended: scope labels name sinks by index.
  { re: /(^|\/)\.claude\/\.credentials\.json$/iu, label: 'Claude Code credentials (~/.claude/.credentials.json)' },
  { re: /(^|\/)(\.local\/share\/opencode|\.config\/nanoclaw|\.hermes|\.(openclaw(-[^/]+)?|clawdbot)(\/agents\/[^/]+\/agent)?)\/(auth|auth-profiles|auth-state|credentials|account|registry-auth|device-key)\.json$/iu, label: 'agent credentials (auth.json, credentials.json)' },
  { re: /(^|\/)\.(openclaw(-[^/]+)?|clawdbot)\/credentials(\/|$)|(^|\/)\.hermes\/mcp-tokens(\/|$)|(^|\/)\.nanobot\/(auth|whatsapp-auth)(\/|$)/iu, label: 'agent credentials directory (OpenClaw, Hermes, Nanobot)' },
  { re: /(^|\/)\.(gemini|qwen)\/(oauth_creds|google_accounts|mcp-oauth-tokens|a2a-oauth-tokens)\.json$/iu, label: 'Gemini CLI / Qwen Code credentials (oauth_creds.json)' },
  { re: /(^|\/)\.local\/share\/devin\/credentials\.toml$|(^|\/)\.abacusai\/keystore\.enc[^/]*$|(^|\/)\.config\/muse\/auth\.json$/iu, label: 'agent credentials (Devin CLI credentials.toml, Abacus.AI keystore, Muse Code auth.json)' },
  { re: /(^|\/)(\.grokbot|\.cursor\/sand|sand-data)\/(local-exec-daemon-credential|host-token)\.json$|(^|\/)Grok Bot\/(sand|user)-secrets\.json$/iu, label: 'Grok Bot credentials (local exec credential, secret stores)' },
  { re: /(^|\/)\.ironclaw\/reborn\/(webui-token|([^/]+\/)?\.reborn-local-dev-secrets-master-key)$|(^|\/)\.?zeroclaw\/\.secret_key$/iu, label: 'agent credentials (IronClaw WebUI token / master key, ZeroClaw secret key)' },
  { re: /(^|\/)openshell\/(gateway\/credentials|docker-sandbox-tokens|gateways\/[^/]+\/mtls)(\/|$)|(^|\/)openshell\/gateways\/[^/]+\/(?:oidc_token\.json|edge_token)$/iu, label: 'OpenShell credentials (key-encryption key, sandbox tokens, mTLS keys)' },
  // Other tools' credential files, keyring and typed-command history: a
  // config or skill path linked to one is neither read nor shipped. History
  // is every dot-file ending in "history" (.irb_history, .Rhistory,
  // .ksh_history, …) plus .histfile and .lesshst — the probe's credentialName
  // set, not a list of known shells.
  { re: /(^|\/)\.(vault-token|my\.cnf|mylogin\.cnf|s3cfg|boto)$|(^|\/)\.cargo\/credentials(\.toml)?$|(^|\/)\.config\/rclone\/rclone\.conf$|(^|\/)\.terraform\.d\/credentials\.tfrc\.json$/iu, label: 'credentials file (.vault-token, .my.cnf, .s3cfg, .boto, cargo, rclone, terraform)' },
  { re: /(^|\/)\.local\/share\/keyrings(\/|$)/iu, label: 'GNOME keyring credentials (~/.local/share/keyrings)' },
  { re: /(^|\/)\.([\w-]*history|histfile|lesshst)$|(^|\/)\.zsh_sessions(\/|$)|(^|\/)\.local\/share\/fish\/fish_history$/iu, label: 'shell or REPL history (typed commands and passwords: any ~/.*history, .histfile, .lesshst)' },
];

/**
 * Return the labels of every sensitive sink a path string matches. Empty when
 * the path reaches no sensitive location. Leading-dash tokens (CLI flags) and
 * empty strings are ignored so option-like args don't produce false matches.
 */
export function classifySensitivePath(path: string): string[] {
  if (!path || path.startsWith('-')) return [];
  return SENSITIVE_SINKS.filter((s) => s.re.test(path)).map((s) => s.label);
}

/**
 * The folders of SENSITIVE_SINKS (by index) that are other tools' credential
 * stores — ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.docker, ~/.config/gh,
 * ~/.config/gcloud, ~/.azure, ~/.password-store, ~/Library/Keychains,
 * browser profiles, ~/.local/share/keyrings. No agent keeps its configuration there, so an agent
 * folder placed in one (COPILOT_HOME=~/.aws/cop, CODEX_HOME=~/.ssh/codex)
 * is not read on either side: credentialStoreOf. The probe's copy is
 * credentialStoreSinks in probe/sensitive_sinks.go.
 */
export const CREDENTIAL_STORE_SINKS: readonly number[] = [0, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 25];

/** The credential store (CREDENTIAL_STORE_SINKS) a path lies in, by how it is written; undefined for none. */
export function credentialStoreOf(path: string): string | undefined {
  if (!path || path.startsWith('-')) return undefined;
  return CREDENTIAL_STORE_SINKS.map(i => SENSITIVE_SINKS[i]).find(s => s.re.test(path))?.label;
}

/**
 * Credential stores a program reads secrets from, by path: the credential
 * entries of SENSITIVE_SINKS (not shell startup files or all of /etc, which
 * matter as write targets) plus files that hold secrets by name. The skill
 * analyzers use it to tell a credential read (SKL-006/010, SKL-001's source)
 * from a skill reading its own data.
 */
const CREDENTIAL_SINK_LABELS = /SSH|AWS|GnuPG|Kubernetes|Docker|credentials/;
const CREDENTIAL_FILES: RegExp[] = [
  /\/\.ssh\//i,
  /\/\.aws\//i,
  /\/\.gnupg\//i,
  /\/\.kube\//i,
  /\/\.env/i,
  /\/etc\/(?:passwd|shadow|hosts)/i,
  /\/\.docker\/config/i,
  // credential stores by file name — not any path containing the word
  // (`docs/secretary-notes.md`, `credentials-guide.md`)
  /(?:^|[\/])\.?credentials(?:\.(?:json|toml|ya?ml|csv|ini|db))?$/i,
  /(?:^|[\/])\.?secrets?(?:\.(?:json|toml|ya?ml|env|txt))?$/i,
  /client_secret[\w.-]*\.json$/i,
  /(?:^|[\/])\.(?:git-credentials|netrc|pgpass|npmrc|pypirc)$/i,
  /(?:^|[\/])id_(?:rsa|dsa|ecdsa|ed25519)$/i,
];

/** Whether a path names a credential store (see CREDENTIAL_FILES). */
export function isCredentialPath(path: string): boolean {
  if (!path || path.startsWith('-')) return false;
  // `.env` relative to the working directory is the same secret file
  const rooted = path.startsWith('/') ? path : `/${path}`;
  return CREDENTIAL_FILES.some(re => re.test(rooted))
    || SENSITIVE_SINKS.some(s => CREDENTIAL_SINK_LABELS.test(s.label) && s.re.test(rooted));
}
