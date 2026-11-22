import { basename, dirname } from 'node:path';
import type { ParsedConfig } from '../../core/types.js';

/** Bun's precedence among a checkout's env files (higher wins). */
function layerRank(filePath: string): number {
  const name = basename(filePath);
  if (name === '.env') return 0;
  if (name === '.env.local') return 2;
  if (name.endsWith('.local')) return 3; // .env.<mode>.local
  return 1; // .env.<mode>
}

/**
 * Lyrie reads its settings from `<checkout>/.env` and the layered files Bun
 * auto-loads over it (`.env.<NODE_ENV>`, `.env.local`, `.env.<NODE_ENV>.local`);
 * the adapter also loads ~/.lyrie/config.json (Python CLI key store, JSON), so
 * env-variable checks must look at env-format configs only.
 *
 * Each file keeps only the keys it actually decides: a key a
 * higher-precedence file in the same checkout also sets is dropped from the
 * lower one, so a value is judged — and fixed — in the file that wins.
 */
export function lyrieEnvConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  const envs = configs.filter(c => c.format === 'env' && c.data && typeof c.data === 'object');
  return envs.map(c => {
    const shadowing = envs.filter(o => o !== c && dirname(o.filePath) === dirname(c.filePath)
      && layerRank(o.filePath) > layerRank(c.filePath));
    if (shadowing.length === 0) return c;
    const data = Object.fromEntries(Object.entries(c.data as Record<string, unknown>)
      .filter(([k]) => !shadowing.some(o => k in (o.data as Record<string, unknown>))));
    return { ...c, data };
  });
}

const winners = new WeakMap<object, Map<string, string>>();

/**
 * One config per checkout holding the values Bun actually hands Lyrie: the
 * checkout's env files merged in precedence order (a higher layer's key
 * wins). For checks that combine several keys (a channel's token with its
 * DM policy and allowlist) — judging each file alone misses a policy set in
 * `.env.local` over a token in `.env`. `filePath` is the checkout's lowest
 * layer (normally `.env`); `envFile` names the file a key's value comes from.
 */
export function lyrieMergedEnvs(configs: ParsedConfig[]): ParsedConfig[] {
  const byDir = new Map<string, ParsedConfig[]>();
  for (const c of configs) {
    if (c.format !== 'env' || !c.data || typeof c.data !== 'object') continue;
    const list = byDir.get(dirname(c.filePath)) ?? [];
    list.push(c);
    byDir.set(dirname(c.filePath), list);
  }
  return [...byDir.values()].map(list => {
    const layers = [...list].sort((a, b) => layerRank(a.filePath) - layerRank(b.filePath));
    if (layers.length === 1) return layers[0];
    const data: Record<string, unknown> = {};
    const from = new Map<string, string>();
    for (const layer of layers) {
      for (const [k, v] of Object.entries(layer.data as Record<string, unknown>)) {
        data[k] = v;
        from.set(k, layer.filePath);
      }
    }
    winners.set(data, from);
    return { ...layers[0], data };
  });
}

/** The env file `key`'s value comes from (the config's own file when unset or unmerged). */
export function envFile(config: ParsedConfig, key: string): string {
  return winners.get(config.data as object)?.get(key) ?? config.filePath;
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

/**
 * True when the key is configured: non-empty and not an `.env.example`
 * placeholder. A `${VAR}` reference counts — Bun expands it when Lyrie starts
 * (use isRealValue to ask whether a literal secret is stored in the file).
 */
export function isConfigured(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  const s = v.trim();
  return s !== '' && !s.endsWith('...') && !/^<[^>]*>$/.test(s);
}

/** Expand a leading `$HOME` / `${HOME}` / `~` (Bun expands env references in .env). */
export function expandHomeRef(v: string, home: string): string {
  return v.replace(/^(?:\$\{HOME\}|\$HOME\b|~(?=\/|$))/, home);
}

/** Lyrie's boolean env parsing is `=== "true"` (a few keys also accept "1"):
 *  exact, so `TRUE` or `True` is false. */
export function envTrue(config: ParsedConfig, key: string, acceptOne = false): boolean {
  const v = envString(config, key);
  return v === 'true' || (acceptOne && v === '1');
}
