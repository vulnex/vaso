import type { AgentInventory, McpServerItem, SkillsDirInfo } from '../core/types.js';

/** Note after a skills directory: '' when present, else why it holds nothing. */
export function skillsDirNote(dir: SkillsDirInfo): string {
  if (dir.exists) return '';
  return dir.unverified ? '(not scanned — not verified)' : '(not present)';
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "12 skills, 3 MCP servers" — MCP left out for agents whose MCP configs VASO doesn't read. */
export function surfaceCounts(inventory: AgentInventory): string {
  // No skills directory walked (all refused or not collected): unknown, not "0 skills"
  const notScanned = inventory.skillsDirs.length > 0 && inventory.skillsDirs.every(d => d.unverified);
  const parts = [notScanned
    ? 'skills not scanned'
    : `${plural(inventory.skills.length, 'skill')}${inventory.incomplete?.length ? ' (skills inventory incomplete)' : ''}`];
  if (inventory.otherEntries.length > 0) parts.push(plural(inventory.otherEntries.length, 'other skills-dir entry', 'other skills-dir entries'));
  if (inventory.mcpServers) {
    const off = inventory.mcpServers.filter(s => s.disabled).length;
    parts.push(`${plural(inventory.mcpServers.length, 'MCP server')}${off ? ` (${off} disabled)` : ''}`);
  }
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
