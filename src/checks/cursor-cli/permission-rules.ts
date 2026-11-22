import { buildBroadPaths, expandHome, isBroadPath } from '../../analyzers/broad-paths.js';
import { commandStem, INTERPRETER_COMMANDS, SHELL_COMMANDS, WRAPPER_COMMANDS } from '../../analyzers/command-families.js';
import { classifySensitivePath } from '../../analyzers/sensitive-paths.js';

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
const RISKY_COMMANDS = new Set(['rm', 'curl', 'wget', 'nc', 'ncat', 'netcat', 'telnet', 'ssh', 'scp']);

/** The command base of a Shell rule argument — `curl` for `curl:*` and `curl`. */
function shellBase(arg: string): string {
  const colon = arg.indexOf(':');
  return (colon === -1 ? arg : arg.slice(0, colon)).trim().toLowerCase();
}

/**
 * Why a Shell rule allows far more than one command, or undefined: any
 * command, a shell / interpreter / wrapper (which runs whatever it is
 * given), or a risky command — with any arguments, and however the base is
 * spelled (`python3`, `/usr/bin/curl`).
 */
export function overbroadShellReason(rule: string): string | undefined {
  const parsed = parseCursorRule(rule);
  if (!parsed || parsed.tool !== 'shell') return undefined;
  if (parsed.arg === undefined || parsed.arg === '') return 'allows every shell command';
  const base = shellBase(parsed.arg);
  if (WILDCARD.test(base)) return 'allows every shell command';
  const stem = commandStem(base);
  if (SHELL_COMMANDS.has(stem) || WRAPPER_COMMANDS.has(stem)) return `allows ${base}, which runs any command it is given`;
  if (INTERPRETER_COMMANDS.has(stem)) return `allows the ${base} interpreter, which runs any code it is given`;
  if (RISKY_COMMANDS.has(stem)) return `allows any ${base} command (network transfer or deletion)`;
  return undefined;
}

/**
 * Whether a deny rule cancels a Shell allow rule (deny wins): the same rule,
 * or a deny on the whole command (`Shell(curl)` / `Shell(curl:*)`).
 */
export function shellDenied(rule: string, deny: readonly string[]): boolean {
  const allow = parseCursorRule(rule);
  if (!allow?.arg) return deny.some(d => d.trim().toLowerCase() === rule.trim().toLowerCase());
  const base = shellBase(allow.arg);
  return deny.some(d => {
    const parsed = parseCursorRule(d);
    if (!parsed?.arg || parsed.tool !== 'shell') return false;
    if (parsed.arg.toLowerCase() === allow.arg!.toLowerCase()) return true;
    const colon = parsed.arg.indexOf(':');
    const args = colon === -1 ? '' : parsed.arg.slice(colon + 1).trim();
    return shellBase(parsed.arg) === base && (args === '' || WILDCARD.test(args));
  });
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
 * A Read/Write rule over the whole workspace (`*`, `**`), outside it
 * (`../**`), rooted at `/`, the home directory or a directory above it
 * (`/Users/**`), /tmp or /etc, or reaching a credential store or shell
 * startup file (`Read(~/.ssh/**)`, `Write(~/.zshrc)` — the shared
 * sensitive-path catalogue).
 */
export function overbroadPathRule(rule: string, home: string): string | undefined {
  const parsed = parseCursorRule(rule);
  if (!parsed || (parsed.tool !== 'read' && parsed.tool !== 'write') || !parsed.arg) return undefined;
  const root = globRoot(parsed.arg);
  if (root === '' || root === '.' || root === './') return 'covers every file in the workspace';
  if (root === '..' || root.startsWith('../')) return 'reaches outside the workspace (parent directory)';
  // the home, a directory above it (`/Users/**`), /, /tmp, /etc
  const broad = isBroadPath(root, buildBroadPaths(home), home)?.reason;
  if (broad) return broad;
  const abs = expandHome(root, home);
  // reading one /etc file (`/etc/hosts`) exposes nothing; writing one does
  const sinks = classifySensitivePath(abs).filter(label => parsed.tool === 'write' || !label.includes('(/etc)'));
  if (sinks.length > 0) {
    return `${parsed.tool === 'write' ? 'lets the agent write' : 'lets the agent read'} ${sinks.join(', ')}`;
  }
  return undefined;
}
