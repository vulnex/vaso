import { buildBroadPaths, isBroadPath } from '../../analyzers/broad-paths.js';

/**
 * Cursor permission rules (cursor.com/docs/cli/reference/permissions):
 * `Shell(commandBase)` or `Shell(command:args)` (`Shell(curl:*)` = curl with
 * any arguments), `Read(pathOrGlob)` / `Write(pathOrGlob)` with relative
 * (workspace) or absolute paths, `WebFetch(domain)`, `Mcp(server:tool)`.
 */
export interface CursorRule {
  tool: string;
  /** The parenthesised argument, trimmed; undefined for a bare `Shell`. */
  arg?: string;
}

export function parseCursorRule(rule: string): CursorRule | undefined {
  const m = /^\s*([A-Za-z]+)\s*(?:\(\s*(.*?)\s*\))?\s*$/.exec(rule);
  if (!m) return undefined;
  return { tool: m[1].toLowerCase(), arg: m[2] };
}

const WILDCARD = /^\*+$/;
const SHELLS = new Set(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'cmd', 'powershell', 'pwsh']);
const RISKY_COMMANDS = new Set(['rm', 'sudo', 'curl', 'wget', 'nc', 'ncat', 'eval', 'exec']);

/** The command base of a Shell rule argument — `curl` for `curl:*` and `curl`. */
function shellBase(arg: string): string {
  const colon = arg.indexOf(':');
  return (colon === -1 ? arg : arg.slice(0, colon)).trim().toLowerCase();
}

/** A Shell rule that allows any command, a shell, or a risky command (with any arguments). */
export function isOverbroadShell(rule: string): boolean {
  const parsed = parseCursorRule(rule);
  if (!parsed || parsed.tool !== 'shell') return false;
  if (parsed.arg === undefined || parsed.arg === '') return true;
  const base = shellBase(parsed.arg);
  return WILDCARD.test(base) || SHELLS.has(base) || RISKY_COMMANDS.has(base);
}

/** A rule whose whole argument is a wildcard: `X(*)`, `X(**)`, `Shell(*:*)`, `Mcp(*:*)`. */
export function isCatchAll(rule: string): boolean {
  const parsed = parseCursorRule(rule);
  if (!parsed?.arg) return false;
  return parsed.arg.split(':').every(part => WILDCARD.test(part.trim()));
}

/**
 * Strip trailing glob segments: `/**` → `/`, `~/**` → `~`, a bare `**` → ``.
 * A segment counts only when it is all wildcards, so `src/**` stays `src`.
 */
function globRoot(path: string): string {
  const segments = path.split('/');
  while (segments.length > 0 && WILDCARD.test(segments[segments.length - 1])) segments.pop();
  if (segments.length === 1 && segments[0] === '') return '/';
  return segments.join('/');
}

/**
 * A Read/Write rule over the whole workspace (`*`, `**`), or rooted at `/`,
 * the home directory, /tmp or /etc (`/`, `/**`, `~/**`, `/etc/**`).
 */
export function overbroadPathRule(rule: string, home: string): string | undefined {
  const parsed = parseCursorRule(rule);
  if (!parsed || (parsed.tool !== 'read' && parsed.tool !== 'write') || !parsed.arg) return undefined;
  const root = globRoot(parsed.arg);
  if (root === '' || root === '.') return 'covers every file in the workspace';
  return isBroadPath(root, buildBroadPaths(home), home)?.reason;
}
