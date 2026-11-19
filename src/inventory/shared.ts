import type { AgentInstallation, McpServerItem, SharedMcpServer } from '../core/types.js';

/** PyPI treats `-`, `_` and `.` alike and ignores case (PEP 503). */
const pypiName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

/** What makes two configured servers the same server. */
export function mcpServerKey(server: McpServerItem): string | undefined {
  if (server.package && server.package.pin !== 'local') {
    return server.package.ecosystem === 'pypi' ? `pypi:${pypiName(server.package.name)}` : `npm:${server.package.name.toLowerCase()}`;
  }
  if (server.url) {
    try {
      const u = new URL(server.url);
      return `url:${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, '')}`;
    } catch {
      return `url:${server.url}`;
    }
  }
  if (server.command) return `command:${[server.command, ...(server.args ?? [])].join(' ')}`;
  return undefined;
}

const UNPINNED = new Set(['none', 'tag', 'range']);

/**
 * MCP servers configured for two or more installations in separate config
 * files — one file several agents read (Devin CLI and Windsurf share one) is
 * one configuration, not a shared server. Descriptive: shared servers are
 * not findings, but an update or compromise of one reaches every agent
 * listed, and an unpinned one can change under all of them at once.
 */
export function findSharedMcpServers(installations: AgentInstallation[]): SharedMcpServer[] {
  const groups = new Map<string, SharedMcpServer>();
  for (const inst of installations) {
    for (const server of inst.inventory?.mcpServers ?? []) {
      if (server.disabled) continue; // never launched: shares nothing
      const key = mcpServerKey(server);
      if (!key) continue;
      const group = groups.get(key) ?? { key, users: [], unpinned: false };
      groups.set(key, group);
      // One entry per configured server: a file can declare one name twice
      // (~/.claude.json's user scope and a project's), pinned differently
      if (group.users.some(u => u.installDir === inst.installDir && u.agentName === inst.agentName && u.configFile === server.configFile
        && u.server === server.name && u.project === server.project)) continue;
      group.users.push({
        agent: inst.agent,
        ...(inst.agentName ? { agentName: inst.agentName } : {}),
        ...(inst.profile ? { profile: inst.profile } : {}),
        installDir: inst.installDir,
        server: server.name,
        configFile: server.configFile,
        ...(server.project !== undefined ? { project: server.project } : {}),
        ...(server.package ? { pin: server.package.pin } : {}),
      });
      if (server.package && UNPINNED.has(server.package.pin)) group.unpinned = true;
    }
  }
  return [...groups.values()]
    .filter(g => new Set(g.users.map(u => `${u.agent}\0${u.installDir}\0${u.agentName ?? ''}`)).size >= 2
      && new Set(g.users.map(u => u.configFile)).size >= 2)
    .sort((a, b) => Number(b.unpinned) - Number(a.unpinned) || b.users.length - a.users.length || a.key.localeCompare(b.key));
}
