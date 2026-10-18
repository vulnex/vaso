import type { ParsedConfig } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

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

/**
 * Atomic Agent's `coerceIntLike`: a number, or a string holding an integer
 * ("5", " 5 ", "5.0", "+5"); undefined otherwise.
 */
export function coerceIntLike(v: unknown): number | undefined {
  if (typeof v === 'number') return v;
  if (typeof v !== 'string') return undefined;
  const t = v.trim();
  if (!/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t)) return undefined;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : undefined;
}

/** Atomic Agent's `parseBool`: booleans and 1/true/yes/on, 0/false/no/off (any case). */
export function parseAtomicBool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (typeof v !== 'string') return undefined;
  const t = v.toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(t)) return true;
  if (['0', 'false', 'no', 'off'].includes(t)) return false;
  return undefined;
}

/**
 * The approval level config.json loads as (`resolveApprovalLevel`):
 * agent.approvalLevel (1–5) when set, else legacy agent.approvalRequired
 * (true → 1, false → 5). undefined: unset, or a value Atomic rejects.
 */
export function atomicApprovalLevel(config: ParsedConfig): { level: number; snippet: string } | undefined {
  const raw = getNestedValue(config.data, 'agent.approvalLevel');
  if (raw != null) {
    const level = coerceIntLike(raw);
    return level !== undefined && level >= 1 && level <= 5
      ? { level, snippet: `agent.approvalLevel: ${JSON.stringify(raw)}` }
      : undefined;
  }
  const legacy = getNestedValue(config.data, 'agent.approvalRequired');
  const required = legacy == null ? undefined : parseAtomicBool(legacy);
  return required === undefined ? undefined : { level: required ? 1 : 5, snippet: `agent.approvalRequired: ${JSON.stringify(legacy)}` };
}
