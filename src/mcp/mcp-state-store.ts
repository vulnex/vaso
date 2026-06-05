import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

/**
 * Small JSON key/value store for MCP checks that need to remember state across
 * scans (MCP-027 package-version history, MCP-028 config-drift baseline). Kept
 * separate from the tool-baseline store, whose value shape is tool-specific.
 */
export interface McpStateStore {
  load<T = unknown>(key: string): Promise<T | null>;
  save(key: string, value: unknown): Promise<void>;
}

export class FileMcpStateStore implements McpStateStore {
  constructor(private readonly baseDir: string) {}

  async load<T = unknown>(key: string): Promise<T | null> {
    try {
      return JSON.parse(await readFile(join(this.baseDir, `${sanitizeKey(key)}.json`), 'utf-8')) as T;
    } catch {
      return null;
    }
  }

  async save(key: string, value: unknown): Promise<void> {
    await mkdir(this.baseDir, { recursive: true });
    await writeFile(join(this.baseDir, `${sanitizeKey(key)}.json`), JSON.stringify(value, null, 2), 'utf-8');
  }
}

export class InMemoryMcpStateStore implements McpStateStore {
  private readonly data = new Map<string, string>();

  async load<T = unknown>(key: string): Promise<T | null> {
    const raw = this.data.get(key);
    return raw === undefined ? null : (JSON.parse(raw) as T);
  }

  async save(key: string, value: unknown): Promise<void> {
    this.data.set(key, JSON.stringify(value));
  }
}

export function defaultMcpStateStore(): McpStateStore {
  return new FileMcpStateStore(join(homedir(), '.vaso', 'mcp-state'));
}

function sanitizeKey(key: string): string {
  return key.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120) || 'state';
}
