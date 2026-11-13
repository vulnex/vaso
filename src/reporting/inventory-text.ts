import type { AgentInventory, McpServerItem } from '../core/types.js';

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "12 skills, 3 MCP servers" — MCP left out for agents whose MCP configs VASO doesn't read. */
export function surfaceCounts(inventory: AgentInventory): string {
  const parts = [plural(inventory.skills.length, 'skill')];
  if (inventory.otherEntries.length > 0) parts.push(plural(inventory.otherEntries.length, 'other skills-dir entry', 'other skills-dir entries'));
  if (inventory.mcpServers) parts.push(plural(inventory.mcpServers.length, 'MCP server'));
  return parts.join(', ');
}

/** What a server runs or reaches: package spec with its pin, else URL, else command line. */
export function mcpTarget(server: McpServerItem): string {
  if (server.package) {
    const pin = server.package.pin;
    return pin === 'exact' || pin === 'local' ? server.package.spec : `${server.package.spec} (${pin === 'none' ? 'unpinned' : pin})`;
  }
  if (server.url) return server.url;
  return [server.command, ...(server.args ?? [])].filter(Boolean).join(' ');
}

/** "project /srv/app", "user", "extension". */
export function mcpScope(server: McpServerItem): string {
  return server.project ? `${server.scope} ${server.project}` : server.scope;
}
