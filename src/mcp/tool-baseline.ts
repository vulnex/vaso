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
  const byName = new Map<string, MCPToolDefinition>();

  // Record a tool, merging so a richer later match (one that carries a
  // description/schema) upgrades an earlier name-only one — extraction is then
  // order-independent across the patterns below.
  const record = (name: string, description?: string, schema?: string): void => {
    const existing = byName.get(name);
    if (!existing) {
      byName.set(name, { name, description, schema });
      return;
    }
    if (description && !existing.description) existing.description = description;
    if (schema && !existing.schema) existing.schema = schema;
  };

  const runPattern = (re: RegExp, hasSchema = false): void => {
    let match: RegExpExecArray | null;
    while ((match = re.exec(sourceCode)) !== null) {
      record(match[1], match[2] ?? undefined, hasSchema ? (match[3] ?? undefined) : undefined);
    }
  };

  // Pattern 1: server.tool("name", "description", { schema }, handler).
  // Description capture tolerates escaped quotes (\") so a poisoning payload
  // cannot evade extraction by embedding a quote mid-string.
  runPattern(/\.tool\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]((?:[^'"\\]|\\.)*)['"]\s*)?(?:,\s*(\{[^}]*\})\s*)?/g, true);

  // Pattern 2: addTool({ name: "...", description: "...", inputSchema: {...} })
  runPattern(/addTool\(\s*\{[^}]*name:\s*['"]([^'"]+)['"][^}]*(?:description:\s*['"]((?:[^'"\\]|\\.)*?)['"])?/g);

  // Pattern 3: registerTool("name", ...) / register_tool("name", ...)
  runPattern(/register[_]?[Tt]ool\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]((?:[^'"\\]|\\.)*?)['"])?/g);

  // Pattern 4: { name: "tool_name", description: "...", handler: ... } in arrays
  runPattern(/\{\s*name:\s*['"]([^'"]+)['"](?:\s*,\s*description:\s*['"]((?:[^'"\\]|\\.)*?)['"])?[^}]*handler\s*:/g);

  // The modern MCP SDK style separates the name and the config object, often
  // across `const` declarations and one tool per module:
  //   const name = "echo";
  //   const config = { title: "...", description: "...", inputSchema: ... };
  //   server.registerTool(name, config, handler);
  // Patterns 1–4 (which expect inline string-literal args) miss this entirely,
  // so packaged/bundled servers extracted via --resolve-packages yielded no
  // tools. Patterns 5–7 recover the common modern shapes. The lazy length
  // bounds keep each pairing local to one declaration/config block.

  // Pattern 5: a `name`/`toolName` const, then a config object's `description:`.
  runPattern(/(?:const|let|var)\s+(?:tool)?[Nn]ame\s*=\s*['"]([^'"]+)['"][\s\S]{0,400}?\bdescription\s*:\s*['"]((?:[^'"\\]|\\.)*?)['"]/g);

  // Pattern 6: inline registerTool/tool with a config object carrying description.
  runPattern(/(?:register[_]?[Tt]ool|\.tool)\(\s*['"]([^'"]+)['"]\s*,\s*\{[\s\S]{0,400}?\bdescription\s*:\s*['"]((?:[^'"\\]|\\.)*?)['"]/g);

  // Pattern 7: an object literal with both `name:` and `description:` fields.
  runPattern(/\bname\s*:\s*['"]([^'"]+)['"][\s\S]{0,200}?\bdescription\s*:\s*['"]((?:[^'"\\]|\\.)*?)['"]/g);

  return [...byName.values()];
}

/**
 * Extract MCP prompt / slash-command names from server source code. Prompts
 * surface as slash commands in MCP clients, so cross-server name collisions
 * (MCP-026) create command-routing ambiguity the same way tool collisions do.
 */
export function extractPromptNames(sourceCode: string): string[] {
  const names = new Set<string>();
  const add = (n?: string) => {
    if (n) names.add(n);
  };

  // Inline: server.prompt("name", ...) / registerPrompt("name", ...)
  let match: RegExpExecArray | null;
  const inlineRe = /(?:registerPrompt|\.prompt)\(\s*['"]([^'"]+)['"]/g;
  while ((match = inlineRe.exec(sourceCode)) !== null) add(match[1]);

  // Separated: const name = "name"; ... registerPrompt(name, config, handler)
  const sepRe =
    /(?:const|let|var)\s+(?:prompt)?[Nn]ame\s*=\s*['"]([^'"]+)['"][\s\S]{0,400}?registerPrompt\(/g;
  while ((match = sepRe.exec(sourceCode)) !== null) add(match[1]);

  return [...names];
}
