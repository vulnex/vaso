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
