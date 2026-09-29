import type { ParsedConfig } from '../../core/types.js';

/**
 * Lyrie reads its settings from `<checkout>/.env` (Bun auto-loads it); the
 * adapter also loads ~/.lyrie/config.json (Python CLI key store, JSON), so
 * env-variable checks must look at env-format configs only.
 */
export function lyrieEnvConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return configs.filter(c => c.format === 'env' && c.data && typeof c.data === 'object');
}

/** String value of an env key (undefined for absent / non-string). */
export function envString(config: ParsedConfig, key: string): string | undefined {
  const v = (config.data as Record<string, unknown>)[key];
  return typeof v === 'string' ? v.trim() : undefined;
}

/**
 * True when the value is a real setting: non-empty, not a `${VAR}`
 * reference, and not an `.env.example` placeholder such as `sk-ant-...`
 * or `<token>`.
 */
export function isRealValue(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const s = v.trim();
  if (!s) return false;
  if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(s)) return false;
  if (s.endsWith('...')) return false;
  if (/^<[^>]*>$/.test(s)) return false;
  return true;
}

/** Lyrie's boolean env parsing is `=== "true"` (a few keys also accept "1"). */
export function envTrue(config: ParsedConfig, key: string, acceptOne = false): boolean {
  const v = envString(config, key)?.toLowerCase();
  return v === 'true' || (acceptOne && v === '1');
}
