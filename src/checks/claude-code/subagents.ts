import { extname, join } from 'node:path';
import type { ScanContext } from '../../core/types.js';
import { parseYamlSafe } from '../../core/yaml-safe.js';

/** One sub-agent definition (`<installDir>/agents/**\/*.md`) and its YAML frontmatter. */
export interface Subagent {
  file: string;
  content: string;
  frontmatter: Record<string, unknown>;
}

/** The `---`-delimited YAML block at the top of a markdown file, parsed; {} when absent or invalid. */
export function parseFrontmatter(content: string): Record<string, unknown> {
  const m = /^﻿?---[ \t]*\r?\n([\s\S]{0,65536}?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(content);
  if (!m) return {};
  try {
    const data = parseYamlSafe(m[1]);
    return data && typeof data === 'object' && !Array.isArray(data) ? data as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

/**
 * Sub-agent files of this installation: `agents/` under its directory
 * (~/.claude/agents for the user install, <repo>/.claude/agents for a
 * project). Unreadable files are skipped.
 */
export async function readSubagents(ctx: ScanContext): Promise<Subagent[]> {
  const dir = join(ctx.installation.installDir, 'agents');
  const out: Subagent[] = [];
  let entries;
  try {
    entries = await ctx.fs.readdirEntries(dir, { recursive: true });
  } catch {
    return out;
  }
  if (!Array.isArray(entries)) return out;
  for (const entry of entries) {
    if (!entry.isFile || extname(entry.name).toLowerCase() !== '.md') continue;
    const file = entry.parentPath ? join(entry.parentPath, entry.name) : join(dir, entry.name);
    try {
      const content = await ctx.fs.readFile(file);
      out.push({ file, content, frontmatter: parseFrontmatter(content) });
    } catch {
      // unreadable
    }
  }
  return out;
}

/**
 * Inline MCP server definitions in a sub-agent's `mcpServers` frontmatter:
 * the documented list form (`- name: {command, args}`; a bare `- name`
 * references a configured server and defines nothing) or a map.
 */
export function inlineMcpServers(frontmatter: Record<string, unknown>): Array<[string, Record<string, unknown>]> {
  const raw = frontmatter.mcpServers;
  const out: Array<[string, Record<string, unknown>]> = [];
  const addMap = (map: Record<string, unknown>) => {
    for (const [name, def] of Object.entries(map)) {
      if (def && typeof def === 'object' && !Array.isArray(def)) out.push([name, def as Record<string, unknown>]);
    }
  };
  if (Array.isArray(raw)) {
    for (const item of raw) if (item && typeof item === 'object' && !Array.isArray(item)) addMap(item as Record<string, unknown>);
  } else if (raw && typeof raw === 'object') {
    addMap(raw as Record<string, unknown>);
  }
  return out;
}
