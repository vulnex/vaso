import { basename, join } from 'node:path';
import type { ParsedConfig, ScanContext } from '../../core/types.js';
import { DATA_FILES, grokBotHome, grokBotUserDataDir } from '../../adapters/grok-bot.js';

/**
 * Shared helpers for the Grok Bot checks. Semantics come from the 0.71.2
 * app.asar (settings schema in main-core, permission engine in the local exec
 * daemon):
 * - settings.json holds the active account's settings at top level and every
 *   other signed-in account's under `accountScopes.<scopeHash>`.
 * - `localToolPermission` ("always" | "ask" | "never", default "ask") governs
 *   what the cloud agent may do on this computer: run commands, send input,
 *   read/write files, list directories and read other AI tools' setup. The
 *   effective value is the stricter of it and `localToolPermissionCeiling`
 *   (team-admin policy mirrored by the app).
 */

export type LocalPermission = 'always' | 'ask' | 'never';
const RANK: Record<LocalPermission, number> = { never: 0, ask: 1, always: 2 };

export function asPermission(v: unknown): LocalPermission | undefined {
  return v === 'always' || v === 'ask' || v === 'never' ? v : undefined;
}

/** The stricter of the user's choice (default "ask") and the admin ceiling. */
export function effectivePermission(choice: unknown, ceiling: unknown): LocalPermission {
  const c = asPermission(choice) ?? 'ask';
  const cap = asPermission(ceiling);
  return cap && RANK[cap] < RANK[c] ? cap : c;
}

export function settingsConfig(ctx: ScanContext): ParsedConfig | undefined {
  return ctx.configs.find(c => basename(c.filePath) === DATA_FILES.settings);
}

export interface AccountBlock {
  /** Dot path prefix inside settings.json for evidence ('' for the active account). */
  path: string;
  /** Key segments of the block (fix target; [] for the active account) — a scope hash may contain a dot. */
  segments: string[];
  /** Human label for evidence. */
  label: string;
  data: Record<string, unknown>;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** The active account's block plus every parked account's. */
export function accountBlocks(config: ParsedConfig): AccountBlock[] {
  const blocks: AccountBlock[] = [{ path: '', segments: [], label: 'active account', data: config.data }];
  const scopes = config.data.accountScopes;
  if (isRecord(scopes)) {
    for (const [hash, block] of Object.entries(scopes)) {
      if (!isRecord(block) || hash === config.data.activeAccountScope) continue;
      const key = /^[A-Za-z0-9_-]+$/.test(hash) ? hash : JSON.stringify(hash);
      blocks.push({ path: `accountScopes.${key}.`, segments: ['accountScopes', hash], label: `account ${hash.slice(0, 8)}…`, data: block });
    }
  }
  return blocks;
}

export function dataRoot(ctx: ScanContext): string {
  return ctx.installation.installDir;
}

export function userDataDir(ctx: ScanContext): string {
  return grokBotUserDataDir(grokBotHome(ctx.installation.installDir, ctx.fs), ctx.fs);
}

/** Parse a JSON state file; undefined when absent, unreadable or not JSON. */
export async function readJson(ctx: ScanContext, path: string): Promise<unknown> {
  try {
    return JSON.parse(await ctx.fs.readFile(path));
  } catch {
    return undefined;
  }
}

export function dataFile(ctx: ScanContext, name: string): string {
  return join(dataRoot(ctx), name);
}

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

export function envFlag(ctx: ScanContext, name: string): boolean {
  return TRUTHY.has((ctx.fs.getEnv(name) ?? '').trim().toLowerCase());
}

/** Environment overrides only describe the scanning user's own session. */
export function isOwnSession(ctx: ScanContext): boolean {
  return grokBotHome(ctx.installation.installDir, ctx.fs) === ctx.fs.homedir();
}
