import { dirname, join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentType, ScanContext } from '../core/types.js';
import type { MCPConfig, MCPServerEntry } from './types.js';
import { parseJsonLenient } from '../core/jsonc.js';
import { scanCwd } from '../adapters/project-configs.js';
import { isDisabledServerConfig } from './disabled.js';
import { parseServerMap } from './discovery.js';
import { claudeConfigPaths, claudeManagedMcpPath, claudeManagedSettingsPaths } from '../adapters/claude-code.js';
import { geminiHome } from '../adapters/gemini.js';
import { qwenHome } from '../adapters/qwen-code.js';
import { wildcardMatch } from '../analyzers/wildcard.js';

/**
 * Servers an agent's settings switch off by name or policy rather than with a
 * switch in the entry itself. Marked `disabled` — never connected — like an
 * `enabled: false` entry. A file several agents read (a project `.mcp.json`
 * is Claude Code's and Copilot CLI's) is marked only when every one of them
 * leaves the server off.
 *
 * Claude Code (code.claude.com/docs/en/managed-mcp, /en/mcp):
 *  - `managed-mcp.json` in the managed directory, when it parses, takes
 *    exclusive control: no user, project or local server loads. Its own
 *    servers are discovered (a claude-code config) and still honour the
 *    denylist; they skip the allowlist unless they use `${VAR}` outside `env`;
 *  - `deniedMcpServers` from every settings scope blocks matching servers
 *    (`serverName` exact, `serverCommand` exact argv, `serverUrl` globbed per URL part; `${VAR}` expanded on both sides);
 *  - `allowedMcpServers`, when set in any scope (only the managed ones under
 *    `allowManagedMcpServersOnly`), blocks the rest — a stdio server must match a
 *    `serverCommand` (a name counts only without command entries), a remote
 *    one a `serverUrl` (a name counts only without URL entries);
 *  - `disabledMcpjsonServers` (any settings file, or the project's entry in
 *    ~/.claude.json) rejects project `.mcp.json` servers;
 *  - `projects[<path>].disabledMcpServers` in ~/.claude.json turns off that
 *    project's local-scope servers.
 * Gemini CLI (geminicli.com/docs/tools/mcp-server): `mcp.allowed` / `mcp.excluded`
 *   (exact names; older top-level `allowMCPServers` / `excludeMCPServers`),
 *   workspace settings over user settings, and `/mcp disable` state in
 *   `~/.gemini/mcp-server-enablement.json` (`{ "<name>": { "enabled": false } }`,
 *   names case-insensitive).
 * Qwen Code (qwenlm.github.io/qwen-code-docs): `mcp.allowed` / `mcp.excluded`
 *   with `*` / `?` globs, excluded winning.
 */
export async function applyOffLists(configs: MCPConfig[], fs: FSProvider, home: string, projectDir?: string): Promise<void> {
  const rules = new Map<AgentType, OffRule>();
  for (const agent of OFF_LIST_AGENTS) {
    if (!configs.some(c => c.agents?.includes(agent))) continue;
    const rule = await agentOffRule(agent, fs, home, projectDir);
    if (rule) rules.set(agent, rule);
  }
  if (rules.size === 0) return;

  for (const config of configs) {
    const agents = config.agents ?? [];
    if (agents.length === 0 || !agents.some(a => rules.has(a))) continue;
    config.servers = config.servers.map(server => {
      if (server.disabled) return server;
      const off = agents.every(a => rules.get(a)?.(config, server) ?? false);
      return off ? { ...server, disabled: true } : server;
    });
  }
}

/** Where a server is declared, as the off-list rules need it. */
export type OffRuleConfig = Pick<MCPConfig, 'filePath' | 'scope' | 'projectRoot'>;
export type OffRule = (config: OffRuleConfig, server: MCPServerEntry) => boolean;

/** Agents whose settings switch servers off by name or policy. */
export const OFF_LIST_AGENTS = ['claude-code', 'gemini-cli', 'qwen-code'] as const;
type OffListAgent = typeof OFF_LIST_AGENTS[number];

/** One agent's off-list rule, or undefined when its settings switch nothing off. */
export async function agentOffRule(agent: OffListAgent, fs: FSProvider, home: string, projectDir?: string): Promise<OffRule | undefined> {
  if (agent === 'claude-code') return claudeOff(fs, home, projectDir);
  if (agent === 'gemini-cli') return geminiOff(fs, home, projectDir);
  return qwenOff(fs, home, projectDir);
}

/**
 * For an agent's own checks: whether the agent never starts a server it
 * declares — switched off in its entry (where the agent honours that) or by
 * the agent's off-lists, exactly as discovery marks it in the inventory.
 * Project scope is inferred like discovery assigns it: a project `.mcp.json`
 * belongs to its folder, `projects[<path>]` entries of ~/.claude.json to
 * `<path>` (pass it as `projectRoot`).
 */
export type ServerOffPredicate = (
  name: string,
  raw: unknown,
  where: { filePath: string; projectRoot?: string },
) => boolean;

export async function serverOffPredicate(ctx: ScanContext): Promise<ServerOffPredicate> {
  const agent = ctx.installation.agent;
  const honoursEntrySwitch = agent !== 'claude-code' && agent !== 'claude-desktop';
  const rule = (OFF_LIST_AGENTS as readonly AgentType[]).includes(agent)
    ? await agentOffRule(agent as OffListAgent, ctx.fs, ctx.fs.homedir(), scanCwd(ctx.fs)).catch(() => undefined)
    : undefined;
  return (name, raw, where) => {
    if (honoursEntrySwitch && isDisabledServerConfig(raw)) return true;
    if (!rule || !raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
    const entry = parseServerMap({ [name]: raw })[0];
    if (!entry) return false;
    const projectRoot = where.projectRoot
      ?? (where.filePath.endsWith('/.mcp.json') || where.filePath.endsWith('\\.mcp.json') ? dirname(where.filePath) : undefined);
    return rule({ filePath: where.filePath, ...(projectRoot ? { scope: 'project', projectRoot } : {}) }, entry);
  };
}

async function readObject(fs: FSProvider, path: string): Promise<Record<string, unknown> | undefined> {
  try {
    const data = parseJsonLenient(await fs.readFile(path));
    return data && typeof data === 'object' && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const record = (v: unknown): Record<string, unknown> | undefined =>
  (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined);

interface PolicyEntry {
  serverName?: string;
  serverCommand?: string[];
  serverUrl?: string;
}

function policyEntries(v: unknown): PolicyEntry[] {
  if (!Array.isArray(v)) return [];
  return v.flatMap((raw): PolicyEntry[] => {
    const e = record(raw);
    if (!e) return [];
    if (typeof e.serverName === 'string') return [{ serverName: e.serverName }];
    if (Array.isArray(e.serverCommand)) return [{ serverCommand: e.serverCommand.map(String) }];
    if (typeof e.serverUrl === 'string') return [{ serverUrl: e.serverUrl }];
    return [];
  });
}

/** Default port of a URL scheme, as Claude Code applies it to a pattern written without a port. */
const DEFAULT_PORTS: Record<string, string> = { http: '80', https: '443', ws: '80', wss: '443' };

/** `*` glob over one URL part, case-insensitive for scheme and host (no RegExp: patterns come from config). */
function glob(pattern: string, text: string, ignoreCase = false): boolean {
  return wildcardMatch(pattern, text, { ignoreCase });
}

const bareHost = (h: string) => h.toLowerCase().replace(/\.$/, '');

/**
 * A `serverUrl` pattern against a server URL (code.claude.com/docs/en/managed-mcp,
 * "How serverUrl entries match"): scheme, host, port and path are matched
 * separately. `*` globs within its part only; the host is case-insensitive
 * and a trailing FQDN dot is ignored; the path is case-sensitive, and a
 * pattern without a path matches every path. Without a port, a pattern whose
 * host is written out matches the scheme's default port only, one with a `*`
 * in the host matches every port.
 */
export function urlMatches(pattern: string, url: string): boolean {
  const p = /^([^:/]*):\/\/([^/]*)(\/.*)?$/s.exec(pattern);
  if (!p) return false;
  let server: URL;
  try {
    server = new URL(url);
  } catch {
    return false;
  }
  const [, patScheme, authority, patPath] = p;
  const scheme = server.protocol.replace(/:$/, '').toLowerCase();
  if (!glob(patScheme, scheme, true)) return false;

  const hostPort = authority.slice(authority.lastIndexOf('@') + 1);
  const m = /^(\[[^\]]*\]|[^:]*)(?::([^:]*))?$/.exec(hostPort);
  if (!m) return false;
  const [, patHost, patPort] = m;
  if (!glob(bareHost(patHost), bareHost(server.hostname), true)) return false;

  const defaultPort = DEFAULT_PORTS[scheme] ?? '';
  const port = server.port || defaultPort;
  if (patPort !== undefined) {
    if (!glob(patPort, port)) return false;
  } else if (!patHost.includes('*') && port !== defaultPort) {
    return false;
  }

  if (patPath === undefined) return true;
  return glob(patPath, server.pathname + server.search);
}

/**
 * `${VAR}` / `${VAR:-default}` expansion, which Claude Code applies to
 * `serverCommand` / `serverUrl` values on both sides before matching. A
 * variable with no value and no default is left as written.
 */
export function expandClaudeVars(value: string, fs: FSProvider, home: string): string {
  if (!value.includes('${')) return value;
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (whole, name: string, fallback: string | undefined) => {
    // HOME is the scanned user's home (also on a snapshot, which carries no HOME)
    const v = name === 'HOME' || (name === 'USERPROFILE' && fs.platform === 'win32') ? home : fs.getEnv?.(name);
    if (v !== undefined && v !== '') return v;
    return fallback ?? whole;
  });
}

/** `${VAR}` outside `env`: a managed-mcp.json server that uses one is still checked against the allowlist. */
function usesVarOutsideEnv(server: MCPServerEntry): boolean {
  const values = [server.command ?? '', ...(server.args ?? []), server.url ?? '', ...Object.values(server.headers ?? {})];
  return values.some(v => /\$\{[^}]*\}/.test(v));
}

type Expand = (value: string) => string;

function commandMatches(argv: string[], server: MCPServerEntry, expand: Expand): boolean {
  if (!server.command) return false;
  const actual = [server.command, ...(server.args ?? [])].map(expand);
  return argv.length === actual.length && argv.every((a, i) => expand(a) === actual[i]);
}

function urlEntryMatches(pattern: string, server: MCPServerEntry, expand: Expand): boolean {
  return server.url !== undefined && urlMatches(expand(pattern), expand(server.url));
}

function matchesAny(entries: PolicyEntry[], server: MCPServerEntry, expand: Expand): boolean {
  return entries.some(e => (e.serverName !== undefined && e.serverName === server.name)
    || (e.serverCommand !== undefined && commandMatches(e.serverCommand, server, expand))
    || (e.serverUrl !== undefined && urlEntryMatches(e.serverUrl, server, expand)));
}

function allowedBy(entries: PolicyEntry[], server: MCPServerEntry, expand: Expand): boolean {
  const remote = server.transport !== 'stdio';
  const strict = remote ? entries.some(e => e.serverUrl !== undefined) : entries.some(e => e.serverCommand !== undefined);
  return entries.some(e => (remote
    ? e.serverUrl !== undefined && urlEntryMatches(e.serverUrl, server, expand)
    : e.serverCommand !== undefined && commandMatches(e.serverCommand, server, expand))
    || (!strict && e.serverName !== undefined && e.serverName === server.name));
}

/**
 * Whether managed-mcp.json takes exclusive control: only a file Claude Code
 * can read and parse does. One that fails to parse is reported by Claude
 * Code ("failed to parse") and the user's servers keep loading.
 */
async function managedMcpInEffect(fs: FSProvider, path: string): Promise<boolean> {
  try {
    const data: unknown = JSON.parse((await fs.readFile(path)).replace(/^﻿/, ''));
    return data !== null && typeof data === 'object' && !Array.isArray(data);
  } catch {
    return false;
  }
}

async function claudeOff(fs: FSProvider, home: string, projectDir?: string): Promise<OffRule | undefined> {
  const paths = claudeConfigPaths(home, fs);
  const managed = (await Promise.all((await claudeManagedSettingsPaths(fs)).map(p => readObject(fs, p))))
    .filter((d): d is Record<string, unknown> => d !== undefined);
  const others = (await Promise.all([
    join(paths.claudeDir, 'settings.json'),
    ...(projectDir ? [join(projectDir, '.claude', 'settings.json'), join(projectDir, '.claude', 'settings.local.json')] : []),
  ].map(p => readObject(fs, p)))).filter((d): d is Record<string, unknown> => d !== undefined);
  const all = [...managed, ...others];
  const managedMcp = claudeManagedMcpPath(fs);
  const exclusive = await managedMcpInEffect(fs, managedMcp);

  const denied = all.flatMap(d => policyEntries(d.deniedMcpServers));
  const lockAllow = managed.some(d => d.allowManagedMcpServersOnly === true);
  const allowSources = (lockAllow ? managed : all).filter(d => Array.isArray(d.allowedMcpServers));
  const allowed = allowSources.length > 0 ? allowSources.flatMap(d => policyEntries(d.allowedMcpServers)) : undefined;
  const rejectedMcpjson = new Set(all.flatMap(d => strings(d.disabledMcpjsonServers)));
  const expand: Expand = v => expandClaudeVars(v, fs, home);

  const state = await readObject(fs, paths.rootStateFile);
  const projects = record(state?.projects) ?? {};
  const projectList = (root: string | undefined, key: string) => new Set(root ? strings(record(projects[root])?.[key]) : []);

  if (!exclusive && denied.length === 0 && !allowed && rejectedMcpjson.size === 0 && Object.keys(projects).length === 0) return undefined;
  return (config, server) => {
    if (matchesAny(denied, server, expand)) return true;
    // The organization's own servers skip the allowlist unless they use ${VAR} outside env
    if (config.filePath === managedMcp) return allowed !== undefined && usesVarOutsideEnv(server) && !allowedBy(allowed, server, expand);
    if (exclusive) return true;
    if (allowed && !allowedBy(allowed, server, expand)) return true;
    const localScope = config.filePath === paths.rootStateFile && config.scope === 'project';
    if (localScope) return projectList(config.projectRoot, 'disabledMcpServers').has(server.name);
    const mcpjson = config.scope === 'project' && config.filePath.endsWith('.mcp.json');
    if (mcpjson) return rejectedMcpjson.has(server.name) || projectList(config.projectRoot, 'disabledMcpjsonServers').has(server.name);
    return false;
  };
}

async function geminiOff(fs: FSProvider, home: string, projectDir?: string): Promise<OffRule | undefined> {
  const dir = geminiHome(home, fs);
  const user = await readObject(fs, join(dir, 'settings.json'));
  const project = projectDir ? await readObject(fs, join(projectDir, '.gemini', 'settings.json')) : undefined;
  // Workspace settings override user settings key by key
  const pick = (key: 'allowed' | 'excluded', legacy: string): string[] | undefined => {
    for (const s of [project, user]) {
      const v = record(s?.mcp)?.[key] ?? s?.[legacy];
      if (Array.isArray(v)) return strings(v);
    }
    return undefined;
  };
  const allowed = pick('allowed', 'allowMCPServers');
  const excluded = new Set(pick('excluded', 'excludeMCPServers') ?? []);
  const enablement = record(await readObject(fs, join(dir, 'mcp-server-enablement.json'))) ?? {};
  const switchedOff = new Set(Object.entries(enablement)
    .filter(([, v]) => record(v)?.enabled === false)
    .map(([k]) => k.trim().toLowerCase()));
  if (!allowed && excluded.size === 0 && switchedOff.size === 0) return undefined;
  return (_config, server) => excluded.has(server.name)
    || (allowed !== undefined && !allowed.includes(server.name))
    || switchedOff.has(server.name.trim().toLowerCase());
}

function globMatch(pattern: string, name: string): boolean {
  return wildcardMatch(pattern, name, { question: true });
}

async function qwenOff(fs: FSProvider, home: string, projectDir?: string): Promise<OffRule | undefined> {
  const user = await readObject(fs, join(qwenHome(home, fs), 'settings.json'));
  const project = projectDir ? await readObject(fs, join(projectDir, '.qwen', 'settings.json')) : undefined;
  const pick = (key: 'allowed' | 'excluded'): string[] | undefined => {
    for (const s of [project, user]) {
      const v = record(s?.mcp)?.[key];
      if (Array.isArray(v)) return strings(v);
    }
    return undefined;
  };
  const allowed = pick('allowed');
  const excluded = pick('excluded') ?? [];
  if (!allowed && excluded.length === 0) return undefined;
  return (_config, server) => excluded.some(p => globMatch(p, server.name))
    || (allowed !== undefined && !allowed.some(p => globMatch(p, server.name)));
}
