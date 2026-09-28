import type { ParsedConfig } from '../../core/types.js';

/** `<stateDir>/config.json` — Atomic Agent's single settings file. */
export function atomicConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return configs.filter(c => c.format === 'json' && c.filePath.endsWith('config.json'));
}

export function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

export function asRecordArray(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.map(asRecord).filter((r): r is Record<string, unknown> => !!r) : [];
}

/** `mcp.servers[]` entries: `{ name, enabled, transport: { kind, command, args, url, headers }, trust, env }`. */
export function mcpServers(data: Record<string, unknown>): Record<string, unknown>[] {
  return asRecordArray(asRecord(data.mcp)?.servers);
}

/** `llm.providers[]` entries: `{ id, kind, url, baseUrl, apiKey, headers, subscriptionCli, ... }`. */
export function llmProviders(data: Record<string, unknown>): Record<string, unknown>[] {
  return asRecordArray(asRecord(data.llm)?.providers);
}

export function serverName(server: Record<string, unknown>, index: number): string {
  return typeof server.name === 'string' && server.name ? server.name : `#${index}`;
}

/** Disabled servers never start — skip them. */
export function isEnabled(entry: Record<string, unknown>): boolean {
  return entry.enabled !== false;
}

export function mask(value: string): string {
  return `${value.slice(0, 4)}…(${value.length} chars)`;
}

const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i;

/** Hostname of a URL, or undefined when it doesn't parse. */
export function urlHost(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

export function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOST.test(host);
}
