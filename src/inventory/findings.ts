import { relative } from 'node:path';
import type { AgentInventory, CheckResult, McpServerItem } from '../core/types.js';
import { relEscapes } from '../core/path-rel.js';

function isWithin(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || !relEscapes(rel);
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Where an agent MCP check names a server in its evidence: the key path it
 * writes (`mcpServers.<name>`, `mcp_servers.<name>`, `mcp.<name>`,
 * `mcp.servers[<name>]`, project servers behind `projects[<path>].`), or the
 * quoted name (`Server "<name>"`, `MCP server "<name>"`). Matching the bare
 * name anywhere linked `db` to `--conn db` and `api` to `api.v2`.
 */
function serverPattern(server: McpServerItem): RegExp {
  const n = escapeRegex(server.name);
  const scope = server.project !== undefined
    ? `projects\\[${escapeRegex(server.project)}\\]\\.`
    : '(?<!\\]\\.)';
  const keyPath = `(?:^|[\\s"'({,])${scope}(?:tools\\.)?(?:mcpServers|mcp_servers|mcp)\\.${n}(?=[.:\\s=\\[]|$)`;
  const bracket = `(?:^|[\\s"'({,])${scope}mcp\\.servers\\[${n}\\]`;
  const quoted = `[Ss]erver "${n}"`;
  return new RegExp(`${keyPath}|${bracket}|${quoted}`);
}

/**
 * Attach to each inventoried skill, other entry and MCP server the ids of the
 * failed checks that point at it. A skill or entry: evidence in its folder
 * (or the folder its symlink leads to). An MCP server: evidence in its config
 * file naming it the way the checks do (serverPattern), in its own scope. A
 * disabled server is never launched — findings about it aren't linked.
 */
export function linkInventoryFindings(inventory: AgentInventory, results: CheckResult[]): void {
  const failed = results.filter(r => !r.passed && r.evidence?.length);
  const idsIn = (dirs: string[]) => [...new Set(failed
    .filter(r => r.evidence!.some(e => dirs.some(d => isWithin(e.file, d))))
    .map(r => r.id))];
  for (const skill of inventory.skills) {
    const ids = idsIn(skill.symlinkTarget ? [skill.path, skill.symlinkTarget] : [skill.path]);
    if (ids.length > 0) skill.findings = ids;
  }
  for (const entry of inventory.otherEntries) {
    const ids = idsIn([entry.path]);
    if (ids.length > 0) entry.findings = ids;
  }
  // Each evidence item goes to the server(s) it names — the longest name when
  // two match (`mcpServers.api.v2.url` is server `api.v2`, not `api`)
  const servers = (inventory.mcpServers ?? []).filter(s => !s.disabled).map(s => ({ s, re: serverPattern(s) }));
  const links = new Map<McpServerItem, Set<string>>();
  for (const r of failed) {
    for (const e of r.evidence!) {
      const hits = servers.filter(({ s, re }) => s.configFile === e.file && (re.test(e.snippet ?? '') || re.test(e.detail ?? '')));
      if (hits.length === 0) continue;
      const longest = Math.max(...hits.map(h => h.s.name.length));
      for (const { s } of hits) {
        if (s.name.length !== longest) continue;
        if (!links.has(s)) links.set(s, new Set());
        links.get(s)!.add(r.id);
      }
    }
  }
  for (const [server, ids] of links) server.findings = [...ids];
}
