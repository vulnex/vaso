import { posix } from 'node:path';
import { expandHome } from '../../analyzers/broad-paths.js';
import { MAX_GLOB_LENGTH, pathGlobMatch } from '../../analyzers/wildcard.js';
import { truncateSnippet } from '../../core/patterns.js';

const { join, normalize, dirname } = posix;

/**
 * Codex permission profiles (learn.chatgpt.com/docs/permissions):
 * `default_permissions` selects a built-in profile (`:read-only`,
 * `:workspace`, `:danger-full-access`) or a `[permissions.<name>]` table,
 * which may `extends` another profile and grant filesystem access by path
 * (`read` / `write` / `deny`, special paths such as `:root`, or a table
 * scoping nested `<subpath-or-glob> = …` entries under that root, `.` being
 * the root itself), add profile-defined workspace roots
 * (`workspace_roots."<path>" = true`, which receive the `:workspace_roots`
 * rules) and network access (`network.enabled`, `network.domains` — domain
 * rules are enforced only by the network proxy, `features.network_proxy`).
 * Profiles replace `sandbox_mode` / `[sandbox_workspace_write]`; the two
 * don't compose.
 *
 * Precedence: a child profile overrides its parent; within the merged
 * profile, a more specific path overrides a broader one, and on the same
 * path deny beats write beats read. Codex rejects an `extends` of
 * `:danger-full-access`, an unknown parent and a cycle — such a config
 * never runs, so it yields no finding here. A glob path supports only
 * `deny`: a `read` / `write` entry whose path holds glob characters once a
 * single trailing `/**` is removed is rejected (openai/codex#36725,
 * codex-rs permissions.rs compile_read_write_glob_path, "filesystem glob
 * path … only supports `deny` access"). The selected profile then fails to
 * compile and Codex doesn't load the config, so such an entry is reported at
 * info and the profile's other grants are not judged: none of them apply.
 */

const CREDENTIAL_DIRS = ['.ssh', '.aws', '.gnupg', '.kube', '.docker', '.codex'];

// Codex reads a path as a glob when it holds * ? [ or ] (codex-rs
// permission_path.rs contains_glob_chars_for_platform); braces and
// backslashes alone are literal path characters
const GLOB_CHARS = /[*?[\]]/;
/** Longest glob a detail quotes in full. */
const MAX_SHOWN_GLOB = 100;

/** Paths whose write access is too broad (see broadRoot), for glob matching. */
function sensitiveCandidates(home: string): string[] {
  const out = ['/', '/etc'];
  for (let p = home; p !== '/' && p !== '.'; p = dirname(p)) out.push(p);
  for (const d of CREDENTIAL_DIRS) out.push(join(home, d));
  return out;
}

/** `<dir>/*` / `<dir>/**` (repeated) → `<dir>`, without a backtracking regex. */
function stripTrailingWildcards(p: string): string {
  for (;;) {
    if (p.endsWith('/**')) p = p.slice(0, -3);
    else if (p.endsWith('/*')) p = p.slice(0, -2);
    else return p;
  }
}

/** Why a writable path is too broad: `/`, the home directory or a parent of
 *  it, a system config dir, or a credential directory — or a glob that can
 *  match one of them. `path` is the path as judged, `why` the reason. */
export function broadReason(root: string, home: string): { path: string; why: string } | undefined {
  if (root === ':root') return { path: ':root', why: 'is the whole filesystem' };
  // `<dir>/**` and `<dir>/*` write everything below <dir>: judge <dir>
  const p = stripTrailingWildcards(trimSlash(normalize(expandHome(root, home)))) || '/';
  if (GLOB_CHARS.test(p)) {
    // No real path is this long; a glob this long is judged by length alone
    if (p.length > MAX_GLOB_LENGTH) return { path: truncateSnippet(p, 60), why: `is a glob too long to judge (${p.length} characters)` };
    const hit = sensitiveCandidates(home).find(c => pathGlobMatch(p, c));
    const shown = p.length > MAX_SHOWN_GLOB ? `${Array.from(p).slice(0, MAX_SHOWN_GLOB).join('')}… (${p.length} characters)` : p;
    if (hit) return { path: shown, why: `can match ${whichClause(broadReason(hit, home))}` };
    // a glob inside /etc or a credential dir (`~/.ssh/auth*`)
    const literal = dirname(p.slice(0, p.search(GLOB_CHARS)) + 'x');
    const inside = literal !== '/' && (literal === '/etc' || literal.startsWith('/etc/')
      || CREDENTIAL_DIRS.some(d => literal === join(home, d) || literal.startsWith(join(home, d) + '/')));
    return inside ? { path: shown, why: `is inside ${whichClause(broadReason(literal, home))}` } : undefined;
  }
  if (p === '/') return { path: p, why: 'is the whole filesystem' };
  if (p === home || home.startsWith(p + '/')) return { path: p, why: 'covers the home directory' };
  if (p === '/etc' || p.startsWith('/etc/')) return { path: p, why: 'is system configuration' };
  const cred = CREDENTIAL_DIRS.find(d => p === join(home, d) || p.startsWith(join(home, d) + '/'));
  return cred ? { path: p, why: `holds credentials (~/${cred})` } : undefined;
}

/** `"<path>", which <reason>` — for a reason that follows a noun. */
export function whichClause(r: { path: string; why: string } | undefined): string {
  return r ? `"${r.path}", which ${r.why}` : '';
}

/** `"<path>" <reason>`, or undefined when the path isn't too broad. */
export function broadRoot(root: string, home: string): string | undefined {
  const r = broadReason(root, home);
  return r && `"${r.path}" ${r.why}`;
}

export interface PermissionFinding {
  /** info: an entry Codex rejects (it grants nothing) */
  level: 'critical' | 'warning' | 'info';
  snippet: string;
  detail: string;
}

const MAX_EXTENDS = 16;

type Access = 'read' | 'write' | 'deny';
const RANK: Record<Access, number> = { read: 0, write: 1, deny: 2 };
const WS = ':workspace_roots';

interface Entry {
  access: Access;
  snippet: string;
  /** A read/write grant on a glob path, which Codex refuses. */
  rejected?: boolean;
}

/** A read/write entry Codex refuses: glob characters left once one trailing `/**` is removed. */
function rejectedGlobGrant(key: string, access: Access): boolean {
  if (access === 'deny') return false;
  return GLOB_CHARS.test(key.endsWith('/**') ? key.slice(0, -3) : key);
}

function isAccess(v: unknown): v is Access {
  return v === 'read' || v === 'write' || v === 'deny';
}

function record(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

function trimSlash(p: string): string {
  return p.length > 1 ? p.replace(/\/+$/, '') : p;
}

/** The normalized key a filesystem entry targets: an absolute path (`~` and
 *  `:root` resolved), `:workspace_roots[/<sub>]`, another special token, or
 *  undefined for a parent traversal Codex rejects. */
function entryKey(root: string, sub: string | undefined, home: string): string | undefined {
  const rel = sub === undefined ? '.' : trimSlash(normalize(sub || '.'));
  if (rel === '..' || rel.startsWith('../') || rel.startsWith('/')) return undefined;
  if (root === WS) return rel === '.' ? WS : `${WS}/${rel}`;
  const base = root === ':root' ? '/' : root;
  if (base.startsWith(':')) return rel === '.' ? base : undefined; // :tmpdir, :minimal, … take `.` only
  const abs = expandHome(base, home);
  return trimSlash(normalize(rel === '.' ? abs : join(abs, rel)));
}

/** One profile's own filesystem entries, same-path ties resolved deny > write > read. */
function profileEntries(name: string, filesystem: Record<string, unknown>, home: string): Map<string, Entry> {
  const out = new Map<string, Entry>();
  const put = (key: string | undefined, access: Access, snippet: string) => {
    if (!key) return;
    const prev = out.get(key);
    if (!prev || RANK[access] > RANK[prev.access]) out.set(key, { access, snippet, rejected: rejectedGlobGrant(key, access) || undefined });
  };
  for (const [root, access] of Object.entries(filesystem)) {
    if (isAccess(access)) {
      put(entryKey(root, undefined, home), access, `[permissions.${name}.filesystem] "${root}" = "${access}"`);
      continue;
    }
    for (const [sub, subAccess] of Object.entries(record(access) ?? {})) {
      if (!isAccess(subAccess)) continue;
      put(entryKey(root, sub, home), subAccess, `[permissions.${name}.filesystem."${root}"] "${sub}" = "${subAccess}"`);
    }
  }
  return out;
}

/** features.network_proxy = true, or a [features.network_proxy] table with enabled = true. */
function networkProxyActive(data: Record<string, unknown>): boolean {
  const proxy = record(data.features)?.network_proxy;
  return proxy === true || record(proxy)?.enabled === true;
}

/**
 * The profile chain `default_permissions` selects, child first; undefined
 * when Codex rejects it (cycle, unknown parent, `:danger-full-access` parent).
 */
function profileChain(selected: string, profiles: Record<string, unknown>): { chain: Array<[string, Record<string, unknown>]>; base?: string } | undefined {
  const chain: Array<[string, Record<string, unknown>]> = [];
  const seen = new Set<string>();
  let name: string | undefined = selected;
  while (name) {
    if (name.startsWith(':')) {
      if (name === ':danger-full-access') return undefined;
      return { chain, base: name };
    }
    const profile = record(profiles[name]);
    if (!profile || seen.has(name) || chain.length >= MAX_EXTENDS) return undefined;
    seen.add(name);
    chain.push([name, profile]);
    name = typeof profile.extends === 'string' ? profile.extends : undefined;
  }
  return { chain };
}

/** What the profile `default_permissions` selects grants beyond a workspace sandbox. */
export function judgeDefaultPermissions(data: Record<string, unknown>, home: string): PermissionFinding[] {
  const selected = data.default_permissions;
  if (typeof selected !== 'string' || !selected) return [];
  if (selected === ':danger-full-access') {
    return [{
      level: 'critical',
      snippet: `default_permissions = "${selected}"`,
      detail: 'default_permissions selects ":danger-full-access" — Codex commands run without a sandbox',
    }];
  }
  const resolved = profileChain(selected, record(data.permissions) ?? {});
  if (!resolved || resolved.chain.length === 0) return [];

  // Merge base → child: a child entry replaces its parent's entry for the same path
  const fs = new Map<string, Entry & { profile: string }>();
  if (resolved.base === ':workspace') fs.set(WS, { access: 'write', snippet: `extends = ":workspace"`, profile: selected });
  const roots = new Map<string, { enabled: boolean; snippet: string }>();
  let network: { enabled: boolean; snippet: string } | undefined;
  const domains = new Map<string, unknown>();
  for (const [name, profile] of [...resolved.chain].reverse()) {
    for (const [key, entry] of profileEntries(name, record(profile.filesystem) ?? {}, home)) {
      fs.set(key, { ...entry, profile: name });
    }
    for (const [root, on] of Object.entries(record(profile.workspace_roots) ?? {})) {
      if (typeof on !== 'boolean') continue;
      roots.set(trimSlash(normalize(expandHome(root, home))), { enabled: on, snippet: `[permissions.${name}.workspace_roots] "${root}" = ${on}` });
    }
    const net = record(profile.network);
    if (typeof net?.enabled === 'boolean') network = { enabled: net.enabled, snippet: `[permissions.${name}.network] enabled = ${net.enabled}` };
    for (const [d, v] of Object.entries(record(net?.domains) ?? {})) domains.set(d, v);
  }

  const findings: PermissionFinding[] = [];
  const critical = (snippet: string, broad: string, via = '') => findings.push({
    level: 'critical',
    snippet,
    detail: `profile grants write access to ${broad}${via} — sandboxed commands can modify it (shell rc files, credentials)`,
  });
  const broadOf = (path: string) => {
    const r = broadReason(path, home);
    return r && whichClause(r);
  };

  // A rejected entry fails the whole profile: Codex doesn't load the config
  const rejected = [...fs.values()].filter(e => e.rejected);
  if (rejected.length > 0) {
    return rejected.map(entry => ({
      level: 'info' as const,
      snippet: entry.snippet,
      detail: 'Codex rejects this entry and does not load the config: a glob path supports only "deny" access (use an exact path, or a trailing /** for a subtree) — it grants nothing',
    }));
  }

  for (const [key, entry] of fs) {
    if (entry.access !== 'write') continue;
    if (key.startsWith(':')) continue;
    const broad = broadOf(key);
    if (broad) critical(entry.snippet, broad);
  }

  // Profile-defined workspace roots receive the :workspace_roots rules
  const wsWrites = [...fs].filter(([key, e]) => e.access === 'write' && (key === WS || key.startsWith(`${WS}/`)));
  for (const [root, { enabled, snippet }] of roots) {
    if (!enabled) continue;
    for (const [key, entry] of wsWrites) {
      const path = key === WS ? root : join(root, key.slice(WS.length + 1));
      if (fs.get(path)?.access === 'deny') continue;
      const broad = broadOf(path);
      if (broad) {
        critical(snippet, broad, ` (a workspace root with ${key === WS ? '":workspace_roots" write' : entry.snippet})`);
        break;
      }
    }
  }

  if (network?.enabled) {
    const allowed = [...domains].filter(([, v]) => v === 'allow').map(([d]) => d);
    const proxy = networkProxyActive(data);
    if (allowed.length === 0 || allowed.some(d => d === '*' || d === '**')) {
      findings.push({
        level: 'warning',
        snippet: network.snippet,
        detail: 'Sandboxed commands have outbound network access to any host — a prompt-injected command can exfiltrate workspace data',
      });
    } else if (!proxy) {
      findings.push({
        level: 'warning',
        snippet: network.snippet,
        detail: 'Sandboxed commands have outbound network access to any host — the profile\'s domain allowlist is enforced only when features.network_proxy = true, so a prompt-injected command can exfiltrate workspace data',
      });
    }
  }
  return findings;
}
