import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { MCPServerSource } from './types.js';

export interface MCPToolDefinition {
  name: string;
  description?: string;
  schema?: string;
}

export interface ToolBaseline {
  serverName: string;
  identity: string;
  timestamp: string;
  tools: Record<string, string>;
}

export interface ToolBaselineDiff {
  changed: { name: string; oldHash: string; newHash: string }[];
  added: string[];
  removed: string[];
}

export interface ToolBaselineStore {
  load(key: string): Promise<ToolBaseline | null>;
  save(key: string, baseline: ToolBaseline): Promise<void>;
}

export class FileToolBaselineStore implements ToolBaselineStore {
  constructor(private readonly baseDir: string) {}

  async load(key: string): Promise<ToolBaseline | null> {
    try {
      const raw = await readFile(join(this.baseDir, `${key}.json`), 'utf-8');
      return JSON.parse(raw) as ToolBaseline;
    } catch {
      return null;
    }
  }

  async save(key: string, baseline: ToolBaseline): Promise<void> {
    await mkdir(this.baseDir, { recursive: true });
    await writeFile(join(this.baseDir, `${key}.json`), JSON.stringify(baseline, null, 2), 'utf-8');
  }
}

export class InMemoryToolBaselineStore implements ToolBaselineStore {
  private readonly data = new Map<string, ToolBaseline>();

  async load(key: string): Promise<ToolBaseline | null> {
    return this.data.get(key) ?? null;
  }

  async save(key: string, baseline: ToolBaseline): Promise<void> {
    this.data.set(key, baseline);
  }

  size(): number {
    return this.data.size;
  }

  keys(): string[] {
    return Array.from(this.data.keys());
  }
}

export function defaultBaselineStore(): ToolBaselineStore {
  return new FileToolBaselineStore(join(homedir(), '.vaso', 'mcp-tool-baselines'));
}

function sourceIdentity(source: MCPServerSource): string {
  return source.localPath ?? source.packageName ?? source.serverName;
}

export function baselineKey(source: MCPServerSource, hostname?: string): string {
  const identity = sourceIdentity(source);
  const hash = createHash('sha256')
    .update(identity)
    .update('|')
    .update(source.serverName)
    .update('|')
    .update(hostname ?? '')
    .digest('hex')
    .slice(0, 16);
  const slug = source.serverName.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 32);
  return `${slug}-${hash}`;
}

function hashToolDefinition(tool: MCPToolDefinition): string {
  const payload = JSON.stringify({
    name: tool.name,
    description: tool.description ?? '',
    schema: tool.schema ?? '',
  });
  return createHash('sha256').update(payload).digest('hex');
}

function toolsToHashMap(tools: MCPToolDefinition[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const tool of tools) {
    map[tool.name] = hashToolDefinition(tool);
  }
  return map;
}

export function makeBaseline(source: MCPServerSource, tools: MCPToolDefinition[]): ToolBaseline {
  return {
    serverName: source.serverName,
    identity: sourceIdentity(source),
    timestamp: new Date().toISOString(),
    tools: toolsToHashMap(tools),
  };
}

export async function diffToolBaseline(
  store: ToolBaselineStore,
  source: MCPServerSource,
  currentTools: MCPToolDefinition[],
  hostname?: string,
): Promise<{ diff: ToolBaselineDiff; isFirstScan: boolean }> {
  const key = baselineKey(source, hostname);
  const existing = await store.load(key);
  const baseline = makeBaseline(source, currentTools);

  if (!existing) {
    await store.save(key, baseline);
    return {
      diff: { changed: [], added: [], removed: [] },
      isFirstScan: true,
    };
  }

  const diff: ToolBaselineDiff = { changed: [], added: [], removed: [] };

  for (const [name, hash] of Object.entries(baseline.tools)) {
    if (name in existing.tools) {
      if (existing.tools[name] !== hash) {
        diff.changed.push({ name, oldHash: existing.tools[name], newHash: hash });
      }
    } else {
      diff.added.push(name);
    }
  }

  for (const name of Object.keys(existing.tools)) {
    if (!(name in baseline.tools)) {
      diff.removed.push(name);
    }
  }

  await store.save(key, baseline);

  return { diff, isFirstScan: false };
}

/**
 * Extract MCP tool definitions from server source code.
 * Scans for common MCP SDK registration patterns.
 */
export function extractToolDefinitions(sourceCode: string): MCPToolDefinition[] {
  const tools: MCPToolDefinition[] = [];
  const seen = new Set<string>();

  // Pattern 1: server.tool("name", "description", { schema }, handler)
  const serverToolRe = /\.tool\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?(?:,\s*(\{[^}]*\})\s*)?/g;
  let match: RegExpExecArray | null;
  while ((match = serverToolRe.exec(sourceCode)) !== null) {
    const name = match[1];
    if (seen.has(name)) continue;
    seen.add(name);
    tools.push({
      name,
      description: match[2] ?? undefined,
      schema: match[3] ?? undefined,
    });
  }

  // Pattern 2: addTool({ name: "...", description: "...", inputSchema: {...} })
  const addToolRe = /addTool\(\s*\{[^}]*name:\s*['"]([^'"]+)['"][^}]*(?:description:\s*['"]([^'"]*?)['"])?/g;
  while ((match = addToolRe.exec(sourceCode)) !== null) {
    const name = match[1];
    if (seen.has(name)) continue;
    seen.add(name);
    tools.push({
      name,
      description: match[2] ?? undefined,
    });
  }

  // Pattern 3: registerTool("name", ...) or register_tool("name", ...)
  const registerToolRe = /register[_]?[Tt]ool\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*?)['"])?/g;
  while ((match = registerToolRe.exec(sourceCode)) !== null) {
    const name = match[1];
    if (seen.has(name)) continue;
    seen.add(name);
    tools.push({
      name,
      description: match[2] ?? undefined,
    });
  }

  // Pattern 4: { name: "tool_name", description: "...", handler: ... } in tools arrays
  const toolObjRe = /\{\s*name:\s*['"]([^'"]+)['"](?:\s*,\s*description:\s*['"]([^'"]*?)['"])?[^}]*handler\s*:/g;
  while ((match = toolObjRe.exec(sourceCode)) !== null) {
    const name = match[1];
    if (seen.has(name)) continue;
    seen.add(name);
    tools.push({
      name,
      description: match[2] ?? undefined,
    });
  }

  return tools;
}
