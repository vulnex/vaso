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

export const SENSITIVE_SINKS: SensitiveSink[] = [
  { re: /(^|\/)\.ssh(\/|$)/i, label: 'SSH keys/config (~/.ssh)' },
  { re: /authorized_keys/i, label: 'SSH authorized_keys (remote-access persistence)' },
  { re: /(^|\/)\.aws(\/|$)/i, label: 'AWS credentials (~/.aws)' },
  { re: /(^|\/)\.gnupg(\/|$)/i, label: 'GnuPG keyring (~/.gnupg)' },
  { re: /(^|\/)\.kube(\/|$)/i, label: 'Kubernetes credentials (~/.kube)' },
  { re: /(^|\/)\.docker(\/|$)/i, label: 'Docker credentials (~/.docker)' },
  { re: /(^|\/)\.(bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin)$/i, label: 'shell startup file (code-execution persistence)' },
  { re: /^\/etc(\/|$)/i, label: 'system configuration (/etc)' },
  { re: /(^|\/)\.config\/gh(\/|$)/i, label: 'GitHub CLI credentials (~/.config/gh)' },
  { re: /(^|\/)\.config\/gcloud(\/|$)/i, label: 'Google Cloud credentials (~/.config/gcloud)' },
  { re: /(^|\/)\.azure(\/|$)/i, label: 'Azure credentials (~/.azure)' },
  { re: /(^|\/)\.password-store(\/|$)/i, label: 'password store credentials (~/.password-store)' },
  { re: /(^|\/)Library\/Keychains(\/|$)/i, label: 'macOS keychain credentials (~/Library/Keychains)' },
  { re: /(^|\/)\.codex\/auth\.json$/i, label: 'Codex credentials (~/.codex/auth.json)' },
  { re: /(^|\/)\.(netrc|git-credentials|pgpass|pypirc|npmrc)$/i, label: 'credentials file (.netrc, .git-credentials, .pgpass, .pypirc, .npmrc)' },
  { re: /(^|\/)(Library\/Application Support\/(Google\/Chrome|Chromium|BraveSoftware|Microsoft Edge|Firefox|Arc)|\.config\/(google-chrome|chromium|BraveSoftware|microsoft-edge)|\.mozilla|Library\/Cookies)(\/|$)/i, label: 'browser profile credentials (cookies, saved passwords)' },
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
