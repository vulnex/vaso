import { basename, dirname, isAbsolute, resolve, sep } from 'node:path';
import type { AgentInventory, CheckResult, McpServerItem } from '../core/types.js';
import { serverSpan } from './spans.js';

/** How path.relative compares paths: resolved, and case-blind on Windows. */
const pathKey = sep === '\\' ? (p: string) => resolve(p).toLowerCase() : (p: string) => resolve(p);

/**
 * The ids of the checks with evidence at or below each directory: every
 * evidence file and each of its ancestors, once — a lookup per inventory
 * entry then answers "evidence within this folder" (path.relative's test)
 * without comparing every entry with every evidence item.
 */
function evidenceIndex(failed: CheckResult[]): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const r of failed) {
    const seen = new Set<string>();
    for (const e of r.evidence!) {
      for (let cur = pathKey(e.file); !seen.has(cur); cur = dirname(cur)) {
        seen.add(cur);
        let ids = index.get(cur);
        if (!ids) index.set(cur, (ids = new Set()));
        ids.add(r.id);
        if (dirname(cur) === cur) break;
      }
    }
  }
  return index;
}

/** Claude Code's state file (`~/.claude.json`, or under $CLAUDE_CONFIG_DIR). */
const isClaudeStateFile = (file: string) => basename(file) === '.claude.json';

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Where an agent MCP check names a server in its evidence: the key path it
 * writes (`mcpServers.<name>`, `mcp_servers.<name>`, `mcp.<name>`,
 * `mcp.servers[<name>]`, Abacus.AI's array `mcpServers[<name>]`, project servers behind `projects[<path>].` in ~/.claude.json), or the
 * quoted name (`Server "<name>"`, `MCP server "<name>"`). Matching the bare
 * name anywhere linked `db` to `--conn db` and `api` to `api.v2`.
 */
function serverPattern(server: McpServerItem): RegExp {
  const n = escapeRegex(server.name);
  // Only ~/.claude.json keeps project servers under `projects[<path>]`; a
  // project's own file (.mcp.json, .cursor/mcp.json, .devin/config.json)
  // names them at the top level like a user file
  const scope = server.project !== undefined && isClaudeStateFile(server.configFile)
    ? `projects\\[${escapeRegex(server.project)}\\]\\.`
    : '(?<!\\]\\.)';
  const keyPath = `(?:^|[\\s"'({,])${scope}(?:tools\\.)?(?:mcpServers|mcp_servers|mcp)\\.${n}(?=[.:\\s=\\[]|$)`;
  const bracket = `(?:^|[\\s"'({,])${scope}(?:mcp\\.servers|mcpServers)\\[${n}\\]`;
  const quoted = `[Ss]erver "${n}"`;
  return new RegExp(`${keyPath}|${bracket}|${quoted}`);
}

/**
 * Files evidence about a server sits in: its config file, or — for a check
 * reporting the mode of what the server launches (CD-009) — its absolute
 * command and that command's directory.
 */
function inServerFiles(server: McpServerItem, file: string): boolean {
  if (file === server.configFile) return true;
  const cmd = server.command;
  return cmd !== undefined && isAbsolute(cmd) && (file === cmd || file === dirname(cmd));
}

/** The server whose entry most narrowly spans `line` of `file`; none when two tie. */
function byLine<T extends { s: McpServerItem }>(servers: T[], file: string, line: number): T[] {
  const holding = servers
    .map(x => ({ x, span: serverSpan(x.s) }))
    .filter(({ x, span }) => x.s.configFile === file && span !== undefined && span[0] <= line && line <= span[1]);
  if (holding.length === 0) return [];
  const width = (span: readonly [number, number]) => span[1] - span[0];
  const narrowest = Math.min(...holding.map(h => width(h.span!)));
  const best = holding.filter(h => width(h.span!) === narrowest);
  return best.length === 1 ? [best[0].x] : [];
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
  const index = evidenceIndex(failed);
  // in result order, as before
  const order = new Map<string, number>();
  failed.forEach((r, i) => { if (!order.has(r.id)) order.set(r.id, i); });
  const idsIn = (dirs: string[]) => {
    const ids = new Set<string>();
    for (const d of dirs) for (const id of index.get(pathKey(d)) ?? []) ids.add(id);
    return [...ids].sort((a, b) => order.get(a)! - order.get(b)!);
  };
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
      let hits = servers.filter(({ s, re }) => inServerFiles(s, e.file) && (re.test(e.snippet ?? '') || re.test(e.detail ?? '')));
      // A bare config line (IOC-001's URL, CFG-002's key) names no server:
      // the entry whose lines hold it, when exactly one does most narrowly
      if (hits.length === 0 && e.line !== undefined) hits = byLine(servers, e.file, e.line);
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
