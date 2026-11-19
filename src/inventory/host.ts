import type { AgentInstallation, HostInventory, McpServerItem } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { userConfigLocations } from '../mcp/discovery.js';
import { findSharedMcpServers } from './shared.js';

/**
 * What a host carries beyond its agents — one shape for `vaso scan`
 * (`ScanResult.hostInventory`) and `vaso detect`: servers no detected agent
 * owns, servers several installations share, and why the lists may be
 * partial. With an agent filter only the shared servers among the filtered
 * installations are kept: the rest belongs to no agent.
 */
export function buildHostInventory(
  installations: AgentInstallation[],
  host: { mcpServers: McpServerItem[]; incomplete?: string[] },
  options: { agentFilter?: boolean } = {},
): HostInventory {
  const shared = findSharedMcpServers(installations);
  const incomplete = options.agentFilter ? [] : host.incomplete ?? [];
  return {
    mcpServers: options.agentFilter ? [] : host.mcpServers,
    ...(shared.length > 0 ? { sharedMcpServers: shared } : {}),
    ...(incomplete.length > 0 ? { incomplete } : {}),
  };
}

/** Nothing to report: a scan leaves `hostInventory` out. */
export function isEmptyHostInventory(host: HostInventory): boolean {
  return host.mcpServers.length === 0 && !host.sharedMcpServers?.length && !host.incomplete?.length;
}

/**
 * Host-level MCP files a remote scan can't list: VS Code's user
 * settings.json is the whole editor config, so the probe records only that
 * it exists — MCP servers in its `mcp.servers` (an older form than mcp.json)
 * go unlisted, and the report says so.
 */
export async function hostInventoryGaps(fs: FSProvider): Promise<string[]> {
  if (fs.kind !== 'snapshot') return [];
  const settings = userConfigLocations(fs.platform, fs.homedir(), fs).find(l => l.source === 'VS Code (settings.json)');
  if (!settings || !(await fs.access(settings.path).catch(() => false))) return [];
  return [`${settings.path}: VS Code settings are not collected by the remote probe — MCP servers in its \`mcp.servers\` are not listed (scan locally)`];
}
