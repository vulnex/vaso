import { posix } from 'node:path';
import type { FSProvider } from './fs-provider.js';
import { buildProbeManifest } from './manifest-builder.js';
import { adapterRegistry } from '../adapters/registry.js';

/**
 * Whether the remote probe was asked for a path at all. A snapshot holds only
 * what the manifest names (fixed trees and their `${VAR}`-relocated twins); a
 * path an agent's config points elsewhere (a Nanobot workspace, a
 * tirith_path, an MCP server's command) was never looked at, so its absence
 * from the snapshot says nothing. Checks and the inventory use this to report
 * such a path as "not verified" instead of "missing". Local scans always
 * answer true.
 *
 * Coverage is judged against the manifest this CLI builds from its registered
 * adapters — what `vaso probe manifest` prints and `--host` sends.
 */

interface Compiled {
  /** Matches a path the probe records when it exists (file paths, globs, metadata globs). */
  files: RegExp[];
  /** Matches a directory the probe collects recursively (`<dir>/**`). */
  recursive: RegExp[];
  /** Matches a directory the probe lists (its direct entries). */
  listed: RegExp[];
}

const cache = new WeakMap<FSProvider, { key: string; compiled: Compiled }>();

/** Glob → regex source, as the probe matches: `**` any depth, `*`/`?` within a segment, `[..]`, `{a,b}`. */
export function globToRegexSource(glob: string): string {
  let out = '';
  let braces = 0;
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else {
        out += '[^/]*';
      }
    } else if (c === '?') {
      out += '[^/]';
    } else if (c === '[') {
      const end = glob.indexOf(']', i + 1);
      if (end === -1) {
        out += '\\[';
      } else {
        out += `[${glob.slice(i + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\')}]`;
        i = end;
      }
    } else if (c === '{') {
      braces++;
      out += '(?:';
    } else if (c === '}' && braces > 0) {
      braces--;
      out += ')';
    } else if (c === ',' && braces > 0) {
      out += '|';
    } else {
      out += escapeRegex(c);
    }
  }
  return out;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/**
 * A manifest pattern as an anchored regex for the scanned host: a leading `~`
 * is the scanned home (or any user home an --all-users probe expands it to),
 * `${VAR}` the value the probe collected (unset → the pattern expands to
 * nothing, as on the probe).
 */
function patternRegex(pattern: string, fs: FSProvider): RegExp | undefined {
  let source: string;
  if (pattern === '~' || pattern.startsWith('~/')) {
    source = `(?:${escapeRegex(fs.homedir())}|/home/[^/]+|/Users/[^/]+|/root|/var/root)${globToRegexSource(pattern.slice(1))}`;
  } else if (pattern.startsWith('${')) {
    const env = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(\/.*)?$/.exec(pattern);
    if (!env) return undefined;
    let value = fs.getEnv(env[1])?.trim();
    if (!value) return undefined;
    if (value === '~' || value.startsWith('~/')) value = fs.homedir() + value.slice(1);
    if (!value.startsWith('/')) return undefined;
    const rest = env[2] ?? '';
    // `..` steps out of the variable's directory (ZeroClaw twins) — the probe cleans the path
    const up = /^(?:\/\.\.)*/.exec(rest)![0];
    const base = posix.normalize(value + up).replace(/\/$/, '');
    source = escapeRegex(base) + globToRegexSource(rest.slice(up.length));
  } else if (pattern.startsWith('/')) {
    source = globToRegexSource(pattern);
  } else {
    return undefined;
  }
  try {
    return new RegExp(`^${source.replace(/\\\/$/, '')}$`);
  } catch {
    return undefined;
  }
}

function compiled(fs: FSProvider): Compiled | undefined {
  const adapters = adapterRegistry.getAdapters();
  // No adapters registered (an embedding that builds its own): no manifest to
  // judge by — treat everything as collected, as before coverage was known
  if (adapters.length === 0) return undefined;
  const key = adapters.map(a => a.agent).join(',');
  const hit = cache.get(fs);
  if (hit && hit.key === key) return hit.compiled;
  const m = buildProbeManifest(adapters);
  const re = (patterns: readonly string[]) => patterns
    .map(p => patternRegex(p, fs))
    .filter((r): r is RegExp => r !== undefined);
  const globs = [...m.globPatterns, ...(m.metadataGlobPatterns ?? [])];
  const result: Compiled = {
    files: re([...m.filePaths, ...globs, ...(m.systemPaths ?? [])]),
    recursive: re(globs.filter(g => g.endsWith('/**')).map(g => g.slice(0, -3))),
    listed: re([...m.directoryListings, ...(m.systemDirListings ?? [])]),
  };
  cache.set(fs, { key, compiled: result });
  return result;
}

/** `path` and every directory above it (normalized, no trailing slash). */
function selfAndAncestors(path: string): string[] {
  const out: string[] = [];
  for (let p = posix.normalize(path).replace(/(.)\/$/, '$1'); p !== '/' && p !== '.'; p = posix.dirname(p)) out.push(p);
  return out;
}

/**
 * The probe collects this directory's contents: it is a listed directory of
 * the manifest, or it or a directory above it is collected recursively
 * (`<dir>/**`). Always true off snapshots.
 */
export function probeCoversTree(fs: FSProvider, dir: string): boolean {
  if (fs.kind !== 'snapshot') return true;
  const c = compiled(fs);
  if (!c) return true;
  const chain = selfAndAncestors(dir);
  if (chain.length > 0 && c.listed.some(r => r.test(chain[0]))) return true;
  return chain.some(d => c.recursive.some(r => r.test(d)));
}

/**
 * The probe records this path (content or metadata) when it exists: a
 * manifest path or glob matches it, or a directory above it is collected
 * recursively. Always true off snapshots.
 */
export function probeCoversFile(fs: FSProvider, path: string): boolean {
  if (fs.kind !== 'snapshot') return true;
  const c = compiled(fs);
  if (!c) return true;
  const p = posix.normalize(path);
  if (c.files.some(r => r.test(p))) return true;
  return selfAndAncestors(posix.dirname(p)).some(d => c.recursive.some(r => r.test(d)));
}

/**
 * A snapshot scan can't judge this path: the probe wasn't asked for it and
 * the snapshot has nothing there (an MCP server's command, a binary a config
 * names). False on local scans and for anything the snapshot holds.
 */
export async function uncollectedPath(fs: FSProvider, path: string): Promise<boolean> {
  if (fs.kind !== 'snapshot' || probeCoversFile(fs, path)) return false;
  return !(await fs.access(path).catch(() => false));
}

/** The "not verified" sentence for paths a remote probe didn't collect. */
export function notCollectedNote(what: string, paths: readonly string[]): string {
  return `${what} ${paths.join(', ')} not verified — the remote probe doesn't collect ${paths.length === 1 ? 'it' : 'them'} (checked on local scans)`;
}

/**
 * Keep a config-derived directory (a workspace's skills/, extra skill dirs):
 * it exists, or a snapshot can't tell because the probe never looked there —
 * then dropping it would hide it; keeping it reports it as not verified.
 */
export async function dirExistsOrUncollected(fs: FSProvider, dir: string): Promise<boolean> {
  return (await fs.access(dir).catch(() => false)) || !probeCoversTree(fs, dir);
}
