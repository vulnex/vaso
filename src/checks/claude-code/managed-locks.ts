import type { ScanContext } from '../../core/types.js';
import { basename, dirname } from 'node:path';
import { claudeManagedSettingsPaths } from '../../adapters/claude-code.js';

/**
 * Managed-settings locks that switch off what user, project and local
 * settings define (code.claude.com/docs/en/settings-reference):
 * `allowManagedPermissionRulesOnly` (only managed allow/ask/deny rules apply),
 * `allowManagedHooksOnly` (user, project, local and plugin hooks are
 * blocked) and a managed `disableAllHooks` (no hook runs). Each names the
 * managed file that sets it. Honoured only from managed settings.
 *
 * Claude Code merges `managed-settings.json` first, then the
 * `managed-settings.d/*.json` drop-ins in alphabetical order, and a later
 * file's single value replaces an earlier one (code.claude.com/docs/en/
 * managed-settings) — so a drop-in's `false` undoes the base file's `true`.
 */
export interface ManagedLocks {
  permissionRulesOnly?: string;
  hooksOnly?: string;
  allHooksOff?: string;
  /** Set when the merged managed settings set `disableAllHooks: false` —
   *  the managed value wins over every user, project and local file. */
  allHooksOnInManaged?: string;
  /** The managed settings files (a config in one of them is not locked out). */
  managedFiles: Set<string>;
}

/**
 * A settings file as Claude Code reads it: strict JSON (a leading BOM is
 * fine). A file with comments or trailing commas is rejected whole —
 * `claude doctor` 2.1.281 reports "Invalid settings … Expected object" and
 * none of its keys apply — so VASO's lenient parse must not lend it a lock.
 */
function strictSettings(raw: string): Record<string, unknown> | undefined {
  try {
    const data: unknown = JSON.parse(raw.replace(/^\uFEFF/, ''));
    return data && typeof data === 'object' && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

export async function claudeManagedLocks(ctx: ScanContext): Promise<ManagedLocks> {
  const paths = await claudeManagedSettingsPaths(ctx.fs);
  const locks: ManagedLocks = { managedFiles: new Set(paths) };
  for (const file of paths) {
    let raw = ctx.configs.find(c => c.filePath === file)?.raw;
    if (raw === undefined) {
      try {
        raw = await ctx.fs.readFile(file);
      } catch {
        continue; // absent or unreadable
      }
    }
    const data = strictSettings(raw);
    if (!data || typeof data !== 'object' || Array.isArray(data)) continue;
    const d = data as Record<string, unknown>;
    // Later files replace earlier values; only booleans are valid settings
    if (typeof d.allowManagedPermissionRulesOnly === 'boolean') locks.permissionRulesOnly = d.allowManagedPermissionRulesOnly ? file : undefined;
    if (typeof d.allowManagedHooksOnly === 'boolean') locks.hooksOnly = d.allowManagedHooksOnly ? file : undefined;
    if (typeof d.disableAllHooks === 'boolean') {
      locks.allHooksOff = d.disableAllHooks ? file : undefined;
      locks.allHooksOnInManaged = d.disableAllHooks ? undefined : file;
    }
  }
  return locks;
}

/**
 * Settings files that carry `disableAllHooks`, lowest precedence first:
 * user/shared-project `settings.json`, then `settings.local.json`
 * (code.claude.com/docs/en/settings#settings-precedence). `~/.claude.json`
 * and `.mcp.json` are not settings files — a key there does nothing.
 *
 * User settings are `~/.claude/settings.json` only (Claude Code 2.1.281
 * `dAe("userSettings")` = config dir + `settings.json`, or
 * `cowork_settings.json`): a `settings.local.json` in the user dir is read
 * only as the local settings of a session started in `~` itself, so for the
 * user installation it does not rank.
 */
const SETTINGS_RANK: Record<string, number> = { 'settings.json': 0, 'settings.local.json': 1 };

/** `settings.local.json` in the user installation's own config dir. */
function isUserDirLocal(ctx: ScanContext, file: string): boolean {
  return ctx.installation.profile !== 'project' && dirname(file) === ctx.installation.installDir;
}

/** The non-managed settings file whose `disableAllHooks` is left after
 *  precedence, with its value; undefined when none sets it. */
function scopedAllHooks(ctx: ScanContext, locks: ManagedLocks): { file: string; value: boolean } | undefined {
  let best: { file: string; value: boolean; rank: number } | undefined;
  for (const c of ctx.configs) {
    if (locks.managedFiles.has(c.filePath)) continue;
    const rank = SETTINGS_RANK[basename(c.filePath)];
    if (rank === undefined) continue;
    if (rank === 1 && isUserDirLocal(ctx, c.filePath)) continue;
    const value = strictSettings(c.raw)?.disableAllHooks;
    if (typeof value !== 'boolean') continue;
    // Same rank: the later file wins (the repo-root settings.local.json is
    // loaded after the working directory's, and its value applies)
    if (!best || rank >= best.rank) best = { file: c.filePath, value, rank };
  }
  return best && { file: best.file, value: best.value };
}

/**
 * Why `disableAllHooks` stops what `file` defines, or undefined. Claude Code
 * reads the value left after settings precedence (code.claude.com/docs/en/
 * hooks): managed > local > project > user, so a later `false` undoes an
 * earlier `true`. A managed `true` stops everything; a `true` left from a
 * user, project or local file stops what those scopes define, not what
 * managed settings define. Only settings files count.
 */
export function allHooksOffReason(ctx: ScanContext, locks: ManagedLocks, file: string): string | undefined {
  if (locks.allHooksOff) return `${locks.allHooksOff} sets disableAllHooks`;
  if (locks.allHooksOnInManaged || locks.managedFiles.has(file)) return undefined;
  const scoped = scopedAllHooks(ctx, locks);
  return scoped?.value ? `${scoped.file} sets disableAllHooks` : undefined;
}
