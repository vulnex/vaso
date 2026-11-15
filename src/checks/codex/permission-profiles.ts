import { join, normalize } from 'node:path';
import { expandHome } from '../../analyzers/broad-paths.js';

/**
 * Codex permission profiles (learn.chatgpt.com/docs/permissions):
 * `default_permissions` selects a built-in profile (`:read-only`,
 * `:workspace`, `:danger-full-access`) or a `[permissions.<name>]` table,
 * which may `extends` another profile and grant filesystem access by path
 * (`read` / `write` / `deny`, special paths such as `:root`, or a table
 * scoping nested `<subpath-or-glob> = …` entries under that root, `.` being
 * the root itself) and network
 * access (`network.enabled`, `network.domains`). Profiles replace
 * `sandbox_mode` / `[sandbox_workspace_write]`; the two don't compose.
 */

const CREDENTIAL_DIRS = ['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.codex'];

/** Why a writable path is too broad: `/`, the home directory or a parent of
 *  it, a system config dir, or a credential directory. */
export function broadRoot(root: string, home: string): string | undefined {
  if (root === ':root') return '":root" is the whole filesystem';
  // `<dir>/**` and `<dir>/*` write everything below <dir>: judge <dir>
  const p = normalize(expandHome(root, home)).replace(/(.)\/+$/, '$1').replace(/(?:\/\*\*?)+$/, '') || '/';
  if (p === '/' || p === home || home.startsWith(p + '/')) return `"${p}" covers the home directory`;
  if (p === '/etc' || p.startsWith('/etc/')) return `"${p}" is system configuration`;
  const cred = CREDENTIAL_DIRS.find(d => p === join(home, d) || p.startsWith(join(home, d) + '/'));
  return cred ? `"${p}" holds credentials (~/${cred})` : undefined;
}

export interface PermissionFinding {
  level: 'critical' | 'warning';
  snippet: string;
  detail: string;
}

const MAX_EXTENDS = 16;

/** Writable paths of a profile's filesystem table, with how each is spelled. */
function writablePaths(name: string, filesystem: Record<string, unknown>): Array<{ path: string; snippet: string }> {
  const out: Array<{ path: string; snippet: string }> = [];
  for (const [root, access] of Object.entries(filesystem)) {
    if (access === 'write') {
      out.push({ path: root, snippet: `[permissions.${name}.filesystem] "${root}" = "write"` });
      continue;
    }
    const nested = record(access);
    // `:workspace_roots` entries are relative to each workspace root
    if (!nested || root === ':workspace_roots') continue;
    for (const [sub, subAccess] of Object.entries(nested)) {
      if (subAccess !== 'write') continue;
      out.push({
        path: sub === '.' || sub === '' ? root : join(root, sub),
        snippet: `[permissions.${name}.filesystem."${root}"] "${sub}" = "write"`,
      });
    }
  }
  return out;
}

function record(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

/** What the profile `default_permissions` selects grants beyond a workspace sandbox. */
export function judgeDefaultPermissions(data: Record<string, unknown>, home: string): PermissionFinding[] {
  const selected = data.default_permissions;
  if (typeof selected !== 'string' || !selected) return [];
  const findings: PermissionFinding[] = [];
  const profiles = record(data.permissions) ?? {};
  const seen = new Set<string>();

  let name: string | undefined = selected;
  for (let depth = 0; name && depth < MAX_EXTENDS && !seen.has(name); depth++) {
    seen.add(name);
    if (name === ':danger-full-access') {
      // Codex rejects a profile extending :danger-full-access: the config
      // doesn't load, so nothing it says takes effect
      if (name !== selected) return [];
      findings.push({
        level: 'critical',
        snippet: `default_permissions = "${selected}"`,
        detail: 'default_permissions selects ":danger-full-access" — Codex commands run without a sandbox',
      });
      break;
    }
    if (name.startsWith(':')) break; // :read-only, :workspace
    const profile = record(profiles[name]);
    if (!profile) break;

    for (const { path, snippet } of writablePaths(name, record(profile.filesystem) ?? {})) {
      const broad = broadRoot(path, home);
      if (broad) {
        findings.push({
          level: 'critical',
          snippet,
          detail: `profile grants write access to ${broad} — sandboxed commands can modify it (shell rc files, credentials)`,
        });
      }
    }

    const network = record(profile.network);
    if (network?.enabled === true) {
      const domains = record(network.domains);
      const allowed = domains ? Object.entries(domains).filter(([, v]) => v === 'allow').map(([d]) => d) : [];
      // A domain allowlist bounds where commands can connect
      if (allowed.length === 0 || allowed.some(d => d === '*' || d === '**')) {
        findings.push({
          level: 'warning',
          snippet: `[permissions.${name}.network] enabled = true`,
          detail: 'Sandboxed commands have outbound network access to any host — a prompt-injected command can exfiltrate workspace data',
        });
      }
    }

    name = typeof profile.extends === 'string' ? profile.extends : undefined;
  }
  return findings;
}
