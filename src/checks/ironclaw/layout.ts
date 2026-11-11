import { basename, join } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import {
  IRONCLAW_LEGACY_UNUSED_PROFILE,
  IRONCLAW_REBORN_PROFILE_ENV,
  isIronclawLegacy,
  isRebornConfigData,
  ironclawServiceUnitPaths,
} from '../../adapters/ironclaw.js';
import { isLoopbackAddress, isWildcardAddress } from '../../core/listen-address.js';

/*
 * Layout helpers shared by the IC-* checks. The adapter emits one
 * installation per generation: the 1.x Reborn home (no `profile`) and, when
 * present, the 0.x base dir (`profile: 'legacy'`, or `'legacy-unused'` when
 * the installed binary is 1.x and no longer reads it).
 */

export function isLegacy(ctx: ScanContext): boolean {
  if (isIronclawLegacy(ctx.installation)) return true;
  if (ctx.installation.profile !== undefined) return false;
  // No layout marker (hand-built contexts, plugins): a Reborn install never
  // loads a .env, so a .env without a Reborn config.toml is the 0.x layout.
  return ctx.configs.some(c => c.format === 'env' || basename(c.filePath) === '.env')
    && !ctx.configs.some(c => basename(c.filePath) === 'config.toml' && isRebornConfigData(c.data));
}

/** 0.x state that a 1.x binary ignores — behavioural settings are dead,
 *  secrets at rest still matter. */
export function isLegacyUnused(ctx: ScanContext): boolean {
  return ctx.installation.profile === IRONCLAW_LEGACY_UNUSED_PROFILE;
}

export function table(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export function str(value: unknown): string | undefined {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number') return String(value);
  return undefined;
}

export function truthy(value: unknown): boolean {
  if (value === true) return true;
  const s = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return s === 'true' || s === '1' || s === 'yes' || s === 'on';
}

export function falsy(value: unknown): boolean {
  if (value === false) return true;
  const s = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return s === 'false' || s === '0' || s === 'no' || s === 'off';
}

// ── 1.x Reborn ──────────────────────────────────────────────────────────

/** `<reborn home>/config.toml` (1.x installation only). */
export function rebornConfig(ctx: ScanContext): ParsedConfig | undefined {
  if (isLegacy(ctx)) return undefined;
  return ctx.configs.find(c => basename(c.filePath) === 'config.toml');
}

/** Provider entries of `<reborn home>/providers.json` (a JSON array). */
export function rebornProviders(ctx: ScanContext): { config: ParsedConfig; entries: Record<string, unknown>[] } | undefined {
  if (isLegacy(ctx)) return undefined;
  const config = ctx.configs.find(c => basename(c.filePath) === 'providers.json');
  if (!config) return undefined;
  const data = config.data as unknown;
  const entries = Array.isArray(data) ? data.filter((e): e is Record<string, unknown> => !!table(e)) : [];
  return { config, entries };
}

/** A `[section]` table of the Reborn config.toml. */
export function rebornSection(ctx: ScanContext, section: string): Record<string, unknown> | undefined {
  return table(rebornConfig(ctx)?.data?.[section]);
}

/** 1-based line of the first `key = …` assignment in a TOML/JSON file. */
export function lineOf(config: ParsedConfig, key: string): number | undefined {
  const re = new RegExp(`^\\s*"?${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"?\\s*[=:]`);
  const idx = config.raw.split('\n').findIndex(l => re.test(l));
  return idx >= 0 ? idx + 1 : undefined;
}

/**
 * Line of `key` inside the TOML table `tablePath` (`llm.backup` matches
 * `[llm.backup]`, `[llm."backup"]` and a root `llm.backup.key = …`), so a
 * second table's key isn't attributed to the first one's line.
 */
export function tableLineOf(config: ParsedConfig, tablePath: string, key: string): number | undefined {
  const norm = (k: string): string => k.replace(/\s+/g, '').replace(/"([^"]*)"|'([^']*)'/g, '$1$2');
  const esc = (k: string): string => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const keyRe = new RegExp(`^\\s*"?${esc(key)}"?\\s*=`);
  const want = norm(tablePath);
  let current = '';
  const lines = config.raw.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const header = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(lines[i]);
    if (header) {
      current = norm(header[1]);
      continue;
    }
    if (current === want && keyRe.test(lines[i])) return i + 1;
    const eq = lines[i].indexOf('=');
    if (current === '' && eq > 0 && norm(lines[i].slice(0, eq)) === `${want}.${key}`) return i + 1;
  }
  return lineOf(config, key);
}

export interface ServiceUnit { file: string; raw: string }

/** `ironclaw service install` units (systemd user unit / launchd agent). Read
 *  raw — neither format is a config the loader understands. */
export async function rebornServiceUnits(ctx: ScanContext): Promise<ServiceUnit[]> {
  if (isLegacy(ctx) || !ctx.fs) return [];
  const home = ctx.fs.homedir();
  // Units live in the owning user's home; for --all-users installs derive it
  // from the default Reborn home location.
  const ownerHome = ctx.installation.installDir.endsWith(join('.ironclaw', 'reborn'))
    ? ctx.installation.installDir.slice(0, -join('.ironclaw', 'reborn').length - 1)
    : home;
  const out: ServiceUnit[] = [];
  for (const file of ironclawServiceUnitPaths(ownerHome, ctx.fs)) {
    try {
      if (!(await ctx.fs.access(file))) continue;
      out.push({ file, raw: await ctx.fs.readFile(file) });
    } catch {
      // unreadable — skip
    }
  }
  return out;
}

export interface ProfileSource { profile: string; file: string; line?: number; via: string }

/** Every place the effective boot profile is selected (env wins over file). */
export async function rebornProfileSources(ctx: ScanContext): Promise<ProfileSource[]> {
  const out: ProfileSource[] = [];
  const config = rebornConfig(ctx);
  const fromFile = str(table(config?.data?.boot)?.profile);
  if (config && fromFile) {
    out.push({ profile: fromFile, file: config.filePath, line: lineOf(config, 'profile'), via: '[boot].profile' });
  }
  const scanningUserInstall = ctx.fs && ctx.installation.user === undefined;
  const fromEnv = scanningUserInstall ? ctx.fs.getEnv(IRONCLAW_REBORN_PROFILE_ENV)?.trim() : undefined;
  if (fromEnv) {
    out.push({ profile: fromEnv, file: 'environment', via: IRONCLAW_REBORN_PROFILE_ENV });
  }
  for (const unit of await rebornServiceUnits(ctx)) {
    const lines = unit.raw.split('\n');
    // systemd: Environment="IRONCLAW_REBORN_PROFILE=x"; launchd: <key>…</key><string>x</string>
    const inline = /IRONCLAW_REBORN_PROFILE=([A-Za-z0-9-]+)/;
    for (let i = 0; i < lines.length; i++) {
      const m = inline.exec(lines[i]);
      if (m) out.push({ profile: m[1], file: unit.file, line: i + 1, via: 'service unit' });
      if (lines[i].includes(`<key>${IRONCLAW_REBORN_PROFILE_ENV}</key>`)) {
        const next = /<string>([^<]+)<\/string>/.exec(lines[i] + (lines[i + 1] ?? ''));
        if (next) out.push({ profile: next[1].trim(), file: unit.file, line: i + 1, via: 'service unit' });
      }
    }
  }
  return out;
}

// ── 0.x legacy ──────────────────────────────────────────────────────────

export function legacyEnv(ctx: ScanContext): ParsedConfig | undefined {
  if (!isLegacy(ctx)) return undefined;
  return ctx.configs.find(c => c.format === 'env' || basename(c.filePath) === '.env');
}

/** 0.x `config.toml` settings overlay (serde of `Settings`). */
export function legacyToml(ctx: ScanContext): ParsedConfig | undefined {
  if (!isLegacy(ctx)) return undefined;
  return ctx.configs.find(c => basename(c.filePath) === 'config.toml');
}

export interface Setting { value: unknown; file: string; key: string; config: ParsedConfig }

/**
 * A 0.x setting as declared in `.env` (flat env name) and/or the
 * `config.toml` overlay (`section.field`). Returns every declaration found.
 */
export function legacySetting(ctx: ScanContext, envKey: string | undefined, tomlPath?: string): Setting[] {
  const out: Setting[] = [];
  const env = legacyEnv(ctx);
  if (env && envKey && env.data[envKey] !== undefined) {
    out.push({ value: env.data[envKey], file: env.filePath, key: envKey, config: env });
  }
  const toml = legacyToml(ctx);
  if (toml && tomlPath) {
    let cur: unknown = toml.data;
    for (const part of tomlPath.split('.')) cur = table(cur)?.[part];
    if (cur !== undefined) out.push({ value: cur, file: toml.filePath, key: tomlPath, config: toml });
  }
  return out;
}

// ── shared ──────────────────────────────────────────────────────────────

/** Loopback in any spelling (src/core/listen-address.ts). */
export function isLoopbackHost(host: string): boolean {
  return isLoopbackAddress(host);
}

/** Any spelling of the unspecified address (src/core/listen-address.ts); empty means unset. */
export function isWildcardHost(host: string): boolean {
  return host.trim() !== '' && isWildcardAddress(host);
}

/** Host of an http(s) URL, or undefined if it doesn't parse. */
export function urlHost(url: string): { scheme: string; host: string } | undefined {
  try {
    const u = new URL(url.trim());
    return { scheme: u.protocol.replace(/:$/, ''), host: u.hostname };
  } catch {
    return undefined;
  }
}

export function evidenceAt(config: ParsedConfig, key: string, detail: string, snippet?: string): Evidence {
  const line = lineOf(config, key);
  return { file: config.filePath, ...(line ? { line } : {}), ...(snippet ? { snippet } : {}), detail };
}
