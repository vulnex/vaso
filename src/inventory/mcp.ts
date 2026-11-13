import { isAbsolute, relative } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, AgentType, McpServerItem } from '../core/types.js';
import type { MCPConfig, MCPServerEntry } from '../mcp/types.js';
import { MCPDiscovery, userConfigLocations } from '../mcp/discovery.js';
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
  const agents = new Set<AgentType>(['openclaw', 'gemini-cli']);
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
    const result = await new MCPDiscovery(fs).discover(fs.platform, projectDir);
    return assignMcpServers(installations, result.configs, { home: fs.homedir(), inventoried: inventoriedAgents(fs), projectDir });
  } catch {
    return { byInstallation: new Map(), host: [] };
  }
}

/** Attach each installation's MCP servers (detect); returns the host-level ones. */
export async function attachMcpInventories(installations: AgentInstallation[], fs: FSProvider): Promise<McpServerItem[]> {
  const { byInstallation, host } = await discoverMcpAssignment(installations, fs);
  for (const [inst, servers] of byInstallation) {
    inst.inventory = { skillsDirs: [], skills: [], otherEntries: [], ...inst.inventory, mcpServers: servers };
  }
  return host;
}
