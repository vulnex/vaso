import { dirname } from 'node:path';
import type { Evidence, ParsedConfig, ScanContext } from '../../core/types.js';
import { markUnreachable, queryPermissions } from '../../core/permissions.js';
import { nanobotWorkspaceDir } from '../../adapters/nanobot.js';
import { isLoopbackAddress } from '../../core/listen-address.js';

/*
 * Shared helpers for the NB-* checks. Every accessor tolerates the shapes a
 * real ~/.nanobot/config.json has: sections that are null or absent, snake_case
 * aliases for camelCase keys, and scalar settings (sendProgress, sendMaxRetries,
 * transcriptionLanguage: null, …) mixed in among the channel objects.
 */

export function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

export function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
}

// Pydantic v2 lax-mode bool coercion: nanobot's config models accept these
// strings (case-insensitive) and 0/1 wherever a bool is declared.
const PY_TRUE = new Set(['true', '1', 'yes', 'on', 't', 'y']);
const PY_FALSE = new Set(['false', '0', 'no', 'off', 'f', 'n']);

/** The boolean pydantic would load `v` as, or undefined when it isn't one. */
export function pyBool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v;
  if (v === 0 || v === 1) return v === 1;
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase();
    if (PY_TRUE.has(s)) return true;
    if (PY_FALSE.has(s)) return false;
  }
  return undefined;
}

/** Read a key that nanobot accepts in camelCase or snake_case. */
export function pick(obj: Record<string, unknown> | undefined, camel: string): unknown {
  if (!obj) return undefined;
  if (camel in obj) return obj[camel];
  const snake = camel.replace(/[A-Z]/g, c => `_${c.toLowerCase()}`);
  return obj[snake];
}

/** Walk a dotted camelCase path, accepting snake_case at each level. */
export function getPath(data: unknown, path: string): unknown {
  let cur: unknown = data;
  for (const key of path.split('.')) {
    const rec = asRecord(cur);
    if (!rec) return undefined;
    cur = pick(rec, key);
  }
  return cur;
}

/** The parsed ~/.nanobot/config.json (nanobot's only settings file). */
export function nanobotConfigs(configs: ParsedConfig[]): ParsedConfig[] {
  return configs.filter(c => c.format === 'json' && c.filePath.endsWith('config.json') && asRecord(c.data));
}

/** Channel sections of `channels` — object values only (scalar settings skipped). */
export function channelSections(data: Record<string, unknown>): Array<[string, Record<string, unknown>]> {
  const channels = asRecord(data.channels);
  if (!channels) return [];
  const out: Array<[string, Record<string, unknown>]> = [];
  for (const [name, value] of Object.entries(channels)) {
    const section = asRecord(value);
    if (section) out.push([name, section]);
  }
  return out;
}

/** Channels default to disabled; only an explicit `enabled: true` starts one
 *  (the always-on websocket channel is handled separately by NB-008). */
export function isChannelEnabled(section: Record<string, unknown>): boolean {
  return pyBool(section.enabled) === true;
}

/** Loopback in any spelling asyncio binds as such (`127.1`, `0x7f.1`, `::1`) — src/core/listen-address.ts. */
export function isLoopbackHost(host: string): boolean {
  return isLoopbackAddress(host);
}

export function nonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

/** The agent workspace for this installation (agents.defaults.workspace). */
export function workspaceDir(ctx: ScanContext): string {
  const data = nanobotConfigs(ctx.configs)[0]?.data;
  return nanobotWorkspaceDir(ctx.installation.installDir, data, ctx.fs);
}

/**
 * World-writable paths among `paths` (files or directories), with
 * parent-traversal mitigation applied. Group write is not reported: nanobot
 * creates its files under the default umask, which on user-private-group
 * systems (Ubuntu, Fedora) yields 0664/0775 without exposing them to anyone
 * but the owner.
 */
export async function worldWritable(
  ctx: ScanContext,
  paths: Array<{ path: string; what: string }>,
): Promise<Evidence[]> {
  const evidence: Evidence[] = [];
  for (const { path, what } of paths) {
    try {
      if (!(await ctx.fs.access(path))) continue;
      const perms = await queryPermissions(ctx.fs, path);
      if (perms === 'unsupported' || !perms.worldWrite) continue;
      const e: Evidence = { file: path, snippet: `mode 0${perms.octal}`, detail: `${what} is world-writable` };
      const barrier = await worldTraversalBarrier(ctx, path);
      if (barrier) {
        e.mitigated = true;
        e.detail += ` — mitigated: not reachable by other users, parent ${barrier} blocks traversal`;
      }
      evidence.push(e);
    } catch {
      // unreadable — skip
    }
  }
  return evidence;
}

/** First ancestor directory other users cannot traverse (no world x bit).
 *  Unknown ancestors count as traversable, like markUnreachable. */
export async function worldTraversalBarrier(ctx: ScanContext, path: string): Promise<string | undefined> {
  for (let dir = dirname(path); ; dir = dirname(dir)) {
    try {
      const q = await queryPermissions(ctx.fs, dir);
      if (q !== 'unsupported' && !q.worldExec) return `${dir} (${q.octal})`;
    } catch {
      // unknown — treat as traversable
    }
    if (dirname(dir) === dir) return undefined;
  }
}

/** Evidence for files readable by group/world, with parent mitigation. */
export async function readableByOthersEvidence(
  ctx: ScanContext,
  paths: Array<{ path: string; what: string }>,
): Promise<Evidence[]> {
  const evidence: Evidence[] = [];
  for (const { path, what } of paths) {
    try {
      const perms = await queryPermissions(ctx.fs, path);
      if (perms === 'unsupported' || !(perms.groupRead || perms.worldRead)) continue;
      evidence.push({
        file: path,
        snippet: `mode 0${perms.octal}`,
        detail: `${what} is readable by ${perms.worldRead ? 'all users' : 'group members'} (should be 0600)`,
      });
    } catch {
      // missing or unreadable — skip
    }
  }
  await markUnreachable(ctx.fs, evidence);
  return evidence;
}
