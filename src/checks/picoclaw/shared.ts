import { basename } from 'node:path';
import type { ParsedConfig } from '../../core/types.js';
import { compileForeignRegex } from '../../analyzers/foreign-regex.js';

const NON_MAIN_CONFIGS = new Set(['auth.json', 'launcher-config.json', '.security.yml']);

/** The agent's config.json (possibly relocated/renamed via PICOCLAW_CONFIG). */
export function picoMainConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return configs.filter(c => c.format === 'json' && isObject(c.data) && !NON_MAIN_CONFIGS.has(basename(c.filePath)));
}

/** The web launcher's settings (`launcher-config.json`, next to config.json). */
export function picoLauncherConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return configs.filter(c => c.format === 'json' && isObject(c.data) && basename(c.filePath) === 'launcher-config.json');
}

function isObject(v: unknown): boolean {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

export function stringList(v: unknown): string[] {
  if (typeof v === 'string') return v.trim() ? [v.trim()] : [];
  if (!Array.isArray(v)) return [];
  return v.map(x => (typeof x === 'number' ? String(x) : x)).filter((x): x is string => typeof x === 'string' && x.trim() !== '');
}

/** `tools.exec` — enabled unless explicitly turned off (ToolConfig.enabled). */
export function execConfig(data: Record<string, unknown>): { enabled: boolean; cfg: Record<string, unknown> } {
  const cfg = asRecord(asRecord(data.tools)?.exec) ?? {};
  return { enabled: cfg.enabled !== false, cfg };
}

export interface PicoChannel {
  name: string;
  type: string;
  cfg: Record<string, unknown>;
  settings: Record<string, unknown>;
}

/** Enabled entries of `channel_list` (schema v3). Non-object entries are ignored. */
export function enabledChannels(data: Record<string, unknown>): PicoChannel[] {
  const list = asRecord(data.channel_list);
  if (!list) return [];
  const out: PicoChannel[] = [];
  for (const [name, raw] of Object.entries(list)) {
    const cfg = asRecord(raw);
    if (!cfg || cfg.enabled !== true) continue;
    out.push({
      name,
      type: typeof cfg.type === 'string' && cfg.type ? cfg.type : name,
      cfg,
      settings: asRecord(cfg.settings) ?? {},
    });
  }
  return out;
}

/**
 * Channels whose senders are external chat users. `pico` is the token-gated
 * WebSocket used by the launcher UI (PCL-005); `maixcam` is a local device link.
 */
export function isChatChannel(ch: PicoChannel): boolean {
  return ch.type !== 'pico' && ch.type !== 'maixcam';
}

/**
 * Compile a PicoClaw (Go RE2) pattern as a JS RegExp, Go-only syntax
 * translated (foreign-regex.ts). Returns undefined when it can't be run
 * here. The pattern comes from config: run it with `testSamples`, never
 * `re.test`.
 */
export function compileGoRegex(pattern: string): RegExp | undefined {
  const c = compileForeignRegex(pattern, 'go');
  return c.kind === 'ok' ? c.re : undefined;
}
