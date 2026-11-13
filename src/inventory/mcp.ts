import { isAbsolute, join, relative } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, AgentType, McpServerItem } from '../core/types.js';
import type { MCPConfig, MCPServerEntry } from '../mcp/types.js';
import { MCPDiscovery, parseServerMap, userConfigLocations } from '../mcp/discovery.js';
import { parseJsonLenient } from '../core/jsonc.js';
import { parseTomlSafe } from '../core/toml-safe.js';
import { REBORN_STORAGE_SUBDIRS, isIronclawLegacy } from '../adapters/ironclaw.js';
import { runnerPackage } from '../mcp/package-pin.js';
import { maskArgSecrets, maskUrlSecrets } from '../mcp/config-secrets.js';
import { scanCwd } from '../adapters/project-configs.js';

export interface McpAssignment {
  /** Servers per installation; only installations whose MCP configs VASO reads have an entry. */
  byInstallation: Map<AgentInstallation, McpServerItem[]>;
  /** Servers in files no detected agent owns. */
  host: McpServerItem[];
}

function isWithin(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/** Leading path segments two paths share. */
function sharedDepth(a: string, b: string): number {
  const x = a.split('/');
  const y = b.split('/');
  let n = 0;
  while (n < x.length && n < y.length && x[n] === y[n]) n++;
  return n;
}

/** One server as reports carry it: env and header names only, credentials in URLs and argv masked. */
export function mcpServerItem(config: MCPConfig, server: MCPServerEntry): McpServerItem {
  const pkg = runnerPackage(server.command, server.args);
  const envNames = server.env ? Object.keys(server.env).sort() : [];
  const headerNames = server.headers ? Object.keys(server.headers).sort() : [];
  return {
    name: server.name,
    configFile: config.filePath,
    scope: config.scope ?? 'user',
    ...(config.projectRoot ? { project: config.projectRoot } : {}),
    transport: server.transport,
    ...(server.command ? { command: server.command } : {}),
    ...(server.args?.length ? { args: maskArgSecrets(server.args, server.command) } : {}),
    ...(server.url ? { url: maskUrlSecrets(server.url) } : {}),
    ...(pkg ? { package: { runner: pkg.runner, ecosystem: pkg.ecosystem, name: pkg.name, spec: pkg.spec, pin: pkg.pin } } : {}),
    ...(envNames.length ? { envNames } : {}),
    ...(headerNames.length ? { headerNames } : {}),
    ...(server.disabled ? { disabled: true } : {}),
  };
}

/**
 * Give each discovered config's servers to the installation that loads them.
 * A config names the agents that read it; among an agent's installations, a
 * project config goes to the project installation under its root (else the
 * user installation), and the closest installation by path wins — an
 * OpenClaw profile's config goes to that profile. Only installations under
 * `home` or the project are given servers: discovery reads the scanning
 * user's files, not other users' (--all-users).
 */
export function assignMcpServers(
  installations: AgentInstallation[],
  configs: MCPConfig[],
  options: { home: string; inventoried: ReadonlySet<AgentType>; projectDir?: string },
): McpAssignment {
  const own = (inst: AgentInstallation) => isWithin(inst.installDir, options.home)
    || (options.projectDir !== undefined && isWithin(inst.installDir, options.projectDir));
  const byInstallation = new Map<AgentInstallation, McpServerItem[]>();
  for (const inst of installations) {
    if (options.inventoried.has(inst.agent) && own(inst)) byInstallation.set(inst, []);
  }
  const host: McpServerItem[] = [];

  for (const config of configs) {
    const items = config.servers.map(s => mcpServerItem(config, s));
    const agents = config.agents ?? [];
    if (agents.length === 0) {
      host.push(...items);
      continue;
    }
    for (const agent of agents) {
      const candidates = [...byInstallation.keys()].filter(i => i.agent === agent);
      if (candidates.length === 0) continue; // agent not installed: nothing loads it
      const inProject = config.projectRoot
        ? candidates.filter(i => i.profile === 'project' && isWithin(i.installDir, config.projectRoot!))
        : [];
      const pool = inProject.length > 0 ? inProject : candidates.filter(i => i.profile !== 'project');
      const target = (pool.length > 0 ? pool : candidates)
        .map(i => ({ i, depth: sharedDepth(i.installDir, config.filePath) }))
        .sort((a, b) => b.depth - a.depth || Number(Boolean(a.i.agentName)) - Number(Boolean(b.i.agentName)))[0].i;
      byInstallation.get(target)!.push(...items);
    }
  }
  return { byInstallation, host };
}

/** Agents whose MCP configs discovery reads (OpenClaw's is found by its own loader). */
export function inventoriedAgents(fs: FSProvider): Set<AgentType> {
  const agents = new Set<AgentType>(['openclaw', 'gemini-cli', 'zeroclaw', 'nanoclaw', 'ironclaw']);
  for (const loc of userConfigLocations(fs.platform, fs.homedir(), fs)) for (const a of loc.agents) agents.add(a);
  return agents;
}

/**
 * Discover the host's MCP configs and assign their servers. Never throws: a
 * discovery failure leaves every installation without an MCP list.
 */
export async function discoverMcpAssignment(installations: AgentInstallation[], fs: FSProvider): Promise<McpAssignment> {
  try {
    const projectDir = scanCwd(fs);
    const result = await new MCPDiscovery(fs).discover(fs.platform, projectDir, { includeDisabled: true });
    const nanoclaw = (await Promise.all(installations.filter(i => i.agent === 'nanoclaw').map(i => nanoclawGroupConfigs(i.installDir, fs)))).flat();
    const ironclaw = (await Promise.all(installations.filter(i => i.agent === 'ironclaw' && !isIronclawLegacy(i)).map(i => ironclawExtensionConfigs(i.installDir, fs)))).flat();
    return assignMcpServers(installations, [...result.configs, ...nanoclaw, ...ironclaw], { home: fs.homedir(), inventoried: inventoriedAgents(fs), projectDir });
  } catch {
    return { byInstallation: new Map(), host: [] };
  }
}

/**
 * NanoClaw keeps each agent group's MCP servers in its database and writes
 * them to `<checkout>/groups/<folder>/container.json` (`mcpServers`, stdio or
 * http) when the group's container starts — a group that never ran has none
 * on disk yet.
 */
export async function nanoclawGroupConfigs(installDir: string, fs: FSProvider): Promise<MCPConfig[]> {
  const groupsDir = join(installDir, 'groups');
  let groups: string[];
  try {
    groups = await fs.readdir(groupsDir);
  } catch {
    return [];
  }
  const configs: MCPConfig[] = [];
  for (const group of groups.sort()) {
    const filePath = join(groupsDir, group, 'container.json');
    let data: unknown;
    try {
      data = parseJsonLenient(await fs.readFile(filePath));
    } catch {
      continue;
    }
    const servers = parseServerMap((data as Record<string, unknown> | null)?.mcpServers);
    if (servers.length > 0) configs.push({ source: `NanoClaw (group ${group})`, agents: ['nanoclaw'], filePath, servers });
  }
  return configs;
}

/**
 * IronClaw 1.x (Reborn) has no MCP server list: MCP servers come as installed
 * extension packages, `<reborn home>/<profile storage>/system/extensions/<id>/
 * manifest.toml` (`reborn.extension_manifest.v3`), whose `[mcp]` section names
 * the server (`server = "https://…"`, hosted). Credentials stay in IronClaw's
 * secret store: the manifest only says which header carries one
 * (`[[mcp.credentials]] injection`). Verified with ironclaw 1.4.0's bundled
 * Notion and NEAR AI extensions.
 */
export async function ironclawExtensionConfigs(rebornHome: string, fs: FSProvider): Promise<MCPConfig[]> {
  const configs: MCPConfig[] = [];
  for (const sub of REBORN_STORAGE_SUBDIRS) {
    const extDir = join(rebornHome, sub, 'system', 'extensions');
    let ids: string[];
    try {
      ids = await fs.readdir(extDir);
    } catch {
      continue;
    }
    for (const id of ids.sort()) {
      const filePath = join(extDir, id, 'manifest.toml');
      let data: Record<string, unknown>;
      try {
        data = parseTomlSafe(await fs.readFile(filePath)) as Record<string, unknown>;
      } catch {
        continue;
      }
      const server = ironclawMcpServer(id, data);
      if (server) configs.push({ source: `IronClaw (extension ${id})`, agents: ['ironclaw'], scope: 'extension', filePath, servers: [server] });
    }
  }
  return configs;
}

function ironclawMcpServer(id: string, manifest: Record<string, unknown>): MCPServerEntry | undefined {
  const mcp = manifest.mcp;
  if (!mcp || typeof mcp !== 'object' || Array.isArray(mcp)) return undefined;
  const m = mcp as Record<string, unknown>;
  const url = typeof m.server === 'string' ? m.server : typeof m.url === 'string' ? m.url : undefined;
  const command = typeof m.command === 'string' && m.command ? m.command : undefined;
  if (!url && !command) return undefined;
  // header names only: the values are handles into the secret store
  const headers: Record<string, string> = {};
  for (const cred of Array.isArray(m.credentials) ? m.credentials : []) {
    const inj = (cred as Record<string, unknown> | null)?.injection as Record<string, unknown> | undefined;
    if (inj?.type === 'header' && typeof inj.name === 'string') headers[inj.name] = `<secret store: ${String((cred as Record<string, unknown>).handle ?? '')}>`;
  }
  return {
    name: typeof manifest.id === 'string' ? manifest.id : id,
    ...(command ? { command, args: Array.isArray(m.args) ? m.args.map(String) : undefined } : {}),
    ...(url ? { url } : {}),
    ...(Object.keys(headers).length ? { headers } : {}),
    transport: url ? (/\/sse\b/.test(url) ? 'sse' : 'streamable-http') : 'stdio',
  };
}

/** Attach each installation's MCP servers (detect); returns the host-level ones. */
export async function attachMcpInventories(installations: AgentInstallation[], fs: FSProvider): Promise<McpServerItem[]> {
  const { byInstallation, host } = await discoverMcpAssignment(installations, fs);
  for (const [inst, servers] of byInstallation) {
    inst.inventory = { skillsDirs: [], skills: [], otherEntries: [], ...inst.inventory, mcpServers: servers };
  }
  return host;
}
