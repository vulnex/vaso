import type { ParsedConfig } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export interface OpenclawAgentEntry {
  id: string;
  /** Where the entry sits: `agents.entries.<id>` or `agents.list[<i>]`. */
  path: string;
  config: ParsedConfig;
  data: Record<string, unknown>;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/**
 * Per-agent entries of an OpenClaw config. 2026.9.4 keys them by id under
 * `agents.entries.<id>` (each may override `sandbox`, `tools.exec`,
 * `tools.fs`, …); earlier 2026.x builds used an `agents.list[]` array with an
 * `id` per item. An entry's override beats `agents.defaults` / root `tools`
 * for that agent, so a single weak entry is enough to expose it.
 */
export function openclawAgentEntries(configs: ParsedConfig[]): OpenclawAgentEntry[] {
  const out: OpenclawAgentEntry[] = [];
  for (const config of configs) {
    const entries = asRecord(getNestedValue(config.data, 'agents.entries'));
    for (const [id, value] of Object.entries(entries ?? {})) {
      const data = asRecord(value);
      if (data) out.push({ id, path: `agents.entries.${id}`, config, data });
    }
    const list = getNestedValue(config.data, 'agents.list');
    if (Array.isArray(list)) {
      list.forEach((item, i) => {
        const data = asRecord(item);
        if (data && typeof data.id === 'string') out.push({ id: data.id, path: `agents.list[${i}]`, config, data });
      });
    }
  }
  return out;
}
