import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

export interface MCPToolDefinition {
  name: string;
  description?: string;
  schema?: string;
}

export interface ToolBaseline {
  serverName: string;
  timestamp: string;
  tools: Record<string, string>; // tool name → SHA-256 hash
}

export interface ToolBaselineDiff {
  changed: { name: string; oldHash: string; newHash: string }[];
  added: string[];
  removed: string[];
}

const BASELINE_DIR = join(homedir(), '.vaso', 'mcp-tool-baselines');

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

function baselinePath(serverName: string): string {
  // Sanitize server name for use as filename
  const safe = serverName.replace(/[^a-zA-Z0-9_-]/g, '_');
  return join(BASELINE_DIR, `${safe}.json`);
}

export async function saveToolBaseline(serverName: string, tools: MCPToolDefinition[]): Promise<void> {
  await mkdir(BASELINE_DIR, { recursive: true });
  const baseline: ToolBaseline = {
    serverName,
    timestamp: new Date().toISOString(),
    tools: toolsToHashMap(tools),
  };
  await writeFile(baselinePath(serverName), JSON.stringify(baseline, null, 2), 'utf-8');
}

export async function loadToolBaseline(serverName: string): Promise<ToolBaseline | null> {
  try {
    const raw = await readFile(baselinePath(serverName), 'utf-8');
    return JSON.parse(raw) as ToolBaseline;
  } catch {
    return null;
  }
}

export async function diffToolBaseline(
  serverName: string,
  currentTools: MCPToolDefinition[],
): Promise<{ diff: ToolBaselineDiff; isFirstScan: boolean }> {
  const existing = await loadToolBaseline(serverName);
  const currentMap = toolsToHashMap(currentTools);

  if (!existing) {
    // First scan — save baseline and signal no comparison available
    await saveToolBaseline(serverName, currentTools);
    return {
      diff: { changed: [], added: [], removed: [] },
      isFirstScan: true,
    };
  }

  const diff: ToolBaselineDiff = { changed: [], added: [], removed: [] };

  // Check for changed and added tools
  for (const [name, hash] of Object.entries(currentMap)) {
    if (name in existing.tools) {
      if (existing.tools[name] !== hash) {
        diff.changed.push({ name, oldHash: existing.tools[name], newHash: hash });
      }
    } else {
      diff.added.push(name);
    }
  }

  // Check for removed tools
  for (const name of Object.keys(existing.tools)) {
    if (!(name in currentMap)) {
      diff.removed.push(name);
    }
  }

  // Save updated baseline
  await saveToolBaseline(serverName, currentTools);

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
  // Captures: name, optional description, optional schema block
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
