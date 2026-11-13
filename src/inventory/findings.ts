import { isAbsolute, relative } from 'node:path';
import type { AgentInventory, CheckResult } from '../core/types.js';

function isWithin(path: string, dir: string): boolean {
  const rel = relative(dir, path);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Attach to each inventoried skill and MCP server the ids of the failed
 * checks that point at it. A skill: evidence in its folder, or in the folder
 * its symlink leads to. An MCP server: evidence in its config file whose
 * snippet or detail names it as a whole word (`mcpServers.<name>…`, the form
 * the agent MCP checks write).
 */
export function linkInventoryFindings(inventory: AgentInventory, results: CheckResult[]): void {
  const failed = results.filter(r => !r.passed && r.evidence?.length);
  for (const skill of inventory.skills) {
    const dirs = skill.symlinkTarget ? [skill.path, skill.symlinkTarget] : [skill.path];
    const ids = failed
      .filter(r => r.evidence!.some(e => dirs.some(d => isWithin(e.file, d))))
      .map(r => r.id);
    if (ids.length > 0) skill.findings = [...new Set(ids)];
  }
  for (const server of inventory.mcpServers ?? []) {
    const named = new RegExp(`(^|[^\\w-])${escapeRegex(server.name)}([^\\w-]|$)`);
    const ids = failed
      .filter(r => r.evidence!.some(e => e.file === server.configFile && named.test(`${e.snippet ?? ''}\n${e.detail ?? ''}`)))
      .map(r => r.id);
    if (ids.length > 0) server.findings = [...new Set(ids)];
  }
}
