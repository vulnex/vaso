import { join } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentType } from '../core/types.js';
import type { MCPConfig, MCPServerEntry } from './types.js';
import { parseJsonLenient } from '../core/jsonc.js';
import { claudeConfigPaths, claudeManagedDir, claudeManagedSettingsPaths } from '../adapters/claude-code.js';
import { geminiHome } from '../adapters/gemini.js';
import { qwenHome } from '../adapters/qwen-code.js';

/**
 * Servers an agent's settings switch off by name or policy rather than with a
 * switch in the entry itself. Marked `disabled` — never connected — like an
 * `enabled: false` entry. A file several agents read (a project `.mcp.json`
 * is Claude Code's and Copilot CLI's) is marked only when every one of them
 * leaves the server off.
 *
 * Claude Code (code.claude.com/docs/en/managed-mcp, /en/mcp):
 *  - `managed-mcp.json` in the managed directory takes exclusive control: no
 *    user, project or local server loads;
 *  - `deniedMcpServers` from every settings scope blocks matching servers
 *    (`serverName` exact, `serverCommand` exact argv, `serverUrl` with `*`);
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
  const rules = new Map<AgentType, (config: MCPConfig, server: MCPServerEntry) => boolean>();
  const claude = await claudeOff(configs, fs, home, projectDir);
  if (claude) rules.set('claude-code', claude);
  const gemini = await geminiOff(fs, home, projectDir);
  if (gemini) rules.set('gemini-cli', gemini);
  const qwen = await qwenOff(fs, home, projectDir);
  if (qwen) rules.set('qwen-code', qwen);
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

function urlMatches(pattern: string, url: string): boolean {
  const re = new RegExp(`^${pattern.split('*').map(p => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}(?:/.*)?$`, 'i');
  return re.test(url);
}

function commandMatches(argv: string[], server: MCPServerEntry): boolean {
  if (!server.command) return false;
  const actual = [server.command, ...(server.args ?? [])];
  return argv.length === actual.length && argv.every((a, i) => a === actual[i]);
}

function matchesAny(entries: PolicyEntry[], server: MCPServerEntry): boolean {
  return entries.some(e => (e.serverName !== undefined && e.serverName === server.name)
    || (e.serverCommand !== undefined && commandMatches(e.serverCommand, server))
    || (e.serverUrl !== undefined && server.url !== undefined && urlMatches(e.serverUrl, server.url)));
}

function allowedBy(entries: PolicyEntry[], server: MCPServerEntry): boolean {
  const remote = server.transport !== 'stdio';
  const strict = remote ? entries.some(e => e.serverUrl !== undefined) : entries.some(e => e.serverCommand !== undefined);
  return entries.some(e => (remote
    ? e.serverUrl !== undefined && server.url !== undefined && urlMatches(e.serverUrl, server.url)
    : e.serverCommand !== undefined && commandMatches(e.serverCommand, server))
    || (!strict && e.serverName !== undefined && e.serverName === server.name));
}

async function claudeOff(configs: MCPConfig[], fs: FSProvider, home: string, projectDir?: string): Promise<((c: MCPConfig, s: MCPServerEntry) => boolean) | undefined> {
  if (!configs.some(c => c.agents?.includes('claude-code'))) return undefined;
  const paths = claudeConfigPaths(home, fs);
  const managed = (await Promise.all((await claudeManagedSettingsPaths(fs)).map(p => readObject(fs, p))))
    .filter((d): d is Record<string, unknown> => d !== undefined);
  const others = (await Promise.all([
    join(paths.claudeDir, 'settings.json'),
    ...(projectDir ? [join(projectDir, '.claude', 'settings.json'), join(projectDir, '.claude', 'settings.local.json')] : []),
  ].map(p => readObject(fs, p)))).filter((d): d is Record<string, unknown> => d !== undefined);
  const all = [...managed, ...others];
  const exclusive = await fs.access(join(claudeManagedDir(fs), 'managed-mcp.json')).catch(() => false);

  const denied = all.flatMap(d => policyEntries(d.deniedMcpServers));
  const lockAllow = managed.some(d => d.allowManagedMcpServersOnly === true);
  const allowSources = (lockAllow ? managed : all).filter(d => Array.isArray(d.allowedMcpServers));
  const allowed = allowSources.length > 0 ? allowSources.flatMap(d => policyEntries(d.allowedMcpServers)) : undefined;
  const rejectedMcpjson = new Set(all.flatMap(d => strings(d.disabledMcpjsonServers)));

  const state = await readObject(fs, paths.rootStateFile);
  const projects = record(state?.projects) ?? {};
  const projectList = (root: string | undefined, key: string) => new Set(root ? strings(record(projects[root])?.[key]) : []);

  if (!exclusive && denied.length === 0 && !allowed && rejectedMcpjson.size === 0 && Object.keys(projects).length === 0) return undefined;
  return (config, server) => {
    if (exclusive) return true;
    if (matchesAny(denied, server)) return true;
    if (allowed && !allowedBy(allowed, server)) return true;
    const localScope = config.filePath === paths.rootStateFile && config.scope === 'project';
    if (localScope) return projectList(config.projectRoot, 'disabledMcpServers').has(server.name);
    const mcpjson = config.scope === 'project' && config.filePath.endsWith('.mcp.json');
    if (mcpjson) return rejectedMcpjson.has(server.name) || projectList(config.projectRoot, 'disabledMcpjsonServers').has(server.name);
    return false;
  };
}

async function geminiOff(fs: FSProvider, home: string, projectDir?: string): Promise<((c: MCPConfig, s: MCPServerEntry) => boolean) | undefined> {
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
  const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
  return re.test(name);
}

async function qwenOff(fs: FSProvider, home: string, projectDir?: string): Promise<((c: MCPConfig, s: MCPServerEntry) => boolean) | undefined> {
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
