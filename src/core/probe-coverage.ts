import { posix } from 'node:path';
import type { FSProvider } from './fs-provider.js';
import { buildProbeManifest } from './manifest-builder.js';
import { adapterRegistry } from '../adapters/registry.js';
import type { ConfigTreeStatus } from './snapshot-types.js';

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
 * adapters — what `vaso probe manifest` prints and `--host` sends — and, from
 * probes newer than 1.4.1, against what the snapshot says the probe did with
 * config-set paths (`configRoots`): a path it recorded (an MCP server's
 * command, found or not) and the config-derived trees it walked. A snapshot
 * from an older probe has neither, so those paths stay not verified.
 */

/** What a snapshot provider tells about config-set paths (SnapshotFSProvider). */
interface SnapshotRecords {
  collected?(path: string): boolean;
  holdsUnder?(dir: string): boolean;
  holdsContentUnder?(dir: string): boolean;
  configTrees?(): Readonly<Record<string, ConfigTreeStatus>>;
  listing?(dir: string): readonly string[] | undefined;
  wildcardNames?(): Readonly<Record<string, readonly string[]>>;
}

interface Compiled {
  /** Matches a path the probe records when it exists (file paths, globs, metadata globs). */
  files: RegExp[];
  /** Matches a directory the probe collects recursively (`<dir>/**`). */
  recursive: RegExp[];
  /** Matches a directory the probe lists (its direct entries). */
  listed: RegExp[];
  /** Config-derived trees by literal directory path (`configTrees`), with
   *  what the probe did. Snapshot data: compared as plain strings, never
   *  compiled into a pattern. */
  trees: ReadonlyMap<string, ConfigTreeStatus>;
  // The wildcard segments of this manifest's config-tree globs (the
  // `workspace-*` of `../workspace-*/skills/**`), compiled from the manifest:
  // the only segments a snapshot's wildcardNames is read for

  segments: ReadonlyArray<{ seg: string; re: RegExp }>;
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
    trees: new Map(Object.entries((fs as SnapshotRecords).configTrees?.() ?? {})),
    segments: wildcardSegments(m.configRoots ?? []),
  };
  cache.set(fs, { key, compiled: result });
  return result;
}

/** Every wildcard segment (not `**`) of the config-tree globs, compiled. */
function wildcardSegments(requests: ReadonlyArray<{ globs?: string[] }>): Array<{ seg: string; re: RegExp }> {
  const segs = new Set<string>();
  for (const r of requests) {
    for (const g of r.globs ?? []) {
      for (const seg of g.split('/')) if (seg !== '**' && /[*?[{]/.test(seg)) segs.add(seg);
    }
  }
  return [...segs].map(seg => ({ seg, re: new RegExp(`^${globToRegexSource(seg)}$`) }));
}

/**
 * What the snapshot's wildcardNames says of `child` in `parent`: the probe
 * recorded the names a manifest wildcard matches there (a home it never
 * lists) — present, absent, or undefined when it didn't.
 */
function wildcardPresence(fs: FSProvider, c: Compiled, parent: string, child: string): boolean | undefined {
  const names = (fs as SnapshotRecords).wildcardNames?.call(fs);
  if (!names) return undefined;
  for (const { seg, re } of c.segments) {
    if (!re.test(child)) continue;
    const key = posix.join(parent, seg);
    const list = Object.hasOwn(names, key) ? names[key] : undefined;
    if (list) return list.includes(child);
  }
  return undefined;
}

/** `path` and every directory above it (normalized, no trailing slash). */
function selfAndAncestors(path: string): string[] {
  const out: string[] = [];
  for (let p = posix.normalize(path).replace(/(.)\/$/, '$1'); p !== '/' && p !== '.'; p = posix.dirname(p)) out.push(p);
  return out;
}

/**
 * What the probe did with the config-derived tree nearest above (or at) one
 * of `chain`'s directories: the deepest recorded base wins.
 */
function treeStatus(c: Compiled, chain: readonly string[]): ConfigTreeStatus | undefined {
  for (const d of chain) {
    const status = c.trees.get(d);
    if (status !== undefined) return status;
  }
  return undefined;
}

/**
 * The snapshot proves the first directory of `chain` absent: the nearest
 * directory above it that the probe listed has no entry on the way down.
 */
function listedAbsent(fs: FSProvider, c: Compiled, chain: readonly string[]): boolean {
  const listing = (fs as SnapshotRecords).listing;
  if (!listing) return false;
  for (let i = 1; i <= chain.length; i++) {
    const parent = i < chain.length ? chain[i] : '/';
    const child = posix.basename(chain[i - 1]);
    const names = listing.call(fs, parent);
    if (names === undefined) {
      // a home the probe never lists: the names a wildcard of the manifest matched there
      const present = wildcardPresence(fs, c, parent, child);
      if (present === undefined) continue;
      return !present;
    }
    return !names.includes(child) && !names.includes(`${child}/`);
  }
  return false;
}

/**
 * The manifest's own recursive trees (`<dir>/**`) contain `dir`: the probe
 * walks it whatever a config says, and so do local scans. Judged the same
 * way for local and snapshot providers.
 */
export function manifestCoversTree(fs: FSProvider, dir: string): boolean {
  const c = compiled(fs);
  if (!c) return false;
  return selfAndAncestors(dir).some(d => c.recursive.some(r => r.test(d)));
}

/** probe/collector.go skillSegment: a directory name a skills tree is kept under. */
const SKILL_SEGMENT = /^(?:.*[-_.])?skills?(?:[-_.].*)?$/i;

let skillGlobCache: { key: string; globs: string[] } | undefined;

/**
 * The manifest's recursive skills globs (`~/.claude/skills/**`,
 * `~/.picoclaw/workspace-*\/skills/**`), as written: those the probe walks as
 * skills trees (isSkillPattern in probe/collector.go).
 */
export function manifestSkillGlobs(): string[] {
  const adapters = adapterRegistry.getAdapters();
  if (adapters.length === 0) return [];
  const key = adapters.map(a => a.agent).join(',');
  if (skillGlobCache?.key === key) return skillGlobCache.globs;
  const globs = buildProbeManifest(adapters).globPatterns
    .filter(g => g.endsWith('/**') && g.split('/').slice(0, -1).some(s => SKILL_SEGMENT.test(s)));
  skillGlobCache = { key, globs };
  return globs;
}

/**
 * doublestar.SplitPattern: everything up to the last `/` before the first
 * unescaped metacharacter (unescaped), and the rest; `.` and the pattern
 * when there is no such `/`.
 */
export function splitGlob(p: string): { base: string; rest: string } {
  let split = -1;
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '\\') i++;
    else if (c === '/') split = i;
    else if (c === '*' || c === '?' || c === '[' || c === '{') break;
  }
  if (split === 0) return { base: '/', rest: p.slice(1) };
  if (split > 0) return { base: p.slice(0, split).replace(/\\(.)/g, '$1'), rest: p.slice(split + 1) };
  return { base: '.', rest: p };
}

/**
 * A manifest glob (`~/…`, `${VAR}/…`, `/…`) for the user whose home is
 * `home`: the literal directory it starts from and the glob after it, as the
 * probe expands it; undefined when it expands to nothing.
 */
export function expandManifestGlob(fs: FSProvider, pattern: string, home: string): { prefix: string; tail: string } | undefined {
  if (pattern === '~' || pattern.startsWith('~/')) return { prefix: home, tail: pattern.slice(1) };
  if (pattern.startsWith('${')) {
    const env = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}(\/.*)?$/.exec(pattern);
    if (!env) return undefined;
    let value = fs.getEnv(env[1])?.trim();
    if (!value) return undefined;
    if (value === '~' || value.startsWith('~/')) value = fs.homedir() + value.slice(1);
    if (!value.startsWith('/')) return undefined;
    const rest = env[2] ?? '';
    const up = /^(?:\/\.\.)*/.exec(rest)![0];
    return { prefix: posix.normalize(value + up).replace(/(.)\/$/, '$1'), tail: rest.slice(up.length) };
  }
  if (pattern.startsWith('/')) return { prefix: '', tail: pattern };
  return undefined;
}

/** `prefix` + `tail` as an anchored regex: the prefix literal, the tail a glob. */
export function expandedGlobRegex(prefix: string, tail: string): RegExp | undefined {
  try {
    return new RegExp(`^${escapeRegex(prefix)}${globToRegexSource(tail).replace(/\\\/$/, '')}$`);
  } catch {
    return undefined;
  }
}

/** `path` and every directory above it (normalized, no trailing slash). */
export function pathChain(path: string): string[] {
  return selfAndAncestors(path);
}

/**
 * A config-derived skills directory the remote probe didn't walk because it
 * refused the tree (an OS directory, another user's home, a credential store) or found it
 * over its entry limit — though the directory may well be in the snapshot for
 * another reason. Undefined off snapshots, and when the manifest's own trees
 * cover it.
 */
export function configTreeGap(fs: FSProvider, dir: string): 'refused' | 'limit' | undefined {
  if (fs.kind !== 'snapshot') return undefined;
  const c = compiled(fs);
  if (!c) return undefined;
  const chain = selfAndAncestors(dir);
  if (chain.some(d => c.recursive.some(r => r.test(d)))) return linkedGap(fs, c, chain);
  const status = treeStatus(c, chain);
  return status === 'refused' || status === 'limit' ? status : undefined;
}

/**
 * What the probe recorded for the config-derived tree at `dir` or the
 * nearest one above it — collected, refused or over its limit — or
 * undefined (off snapshots, older probes, a tree it never looked at).
 */
export function configTreeStatus(fs: FSProvider, dir: string): ConfigTreeStatus | undefined {
  if (fs.kind !== 'snapshot') return undefined;
  const c = compiled(fs);
  if (!c) return undefined;
  return treeStatus(c, selfAndAncestors(dir));
}

/**
 * A manifest tree whose wildcard directory is a link (a PicoClaw
 * `workspace-<id>` linked elsewhere): the probe's glob can't enter it, so it
 * walks it as a config-derived tree (probes newer than 1.4.1). A refusal or
 * cap the probe recorded there — at a base inside the manifest's tree, not a
 * config-set directory above it — with nothing of the tree in the snapshot,
 * means not scanned, not empty.
 */
function linkedGap(fs: FSProvider, c: Compiled, chain: readonly string[]): 'refused' | 'limit' | undefined {
  const holds = (fs as SnapshotRecords).holdsUnder;
  if (!holds || chain.length === 0) return undefined;
  for (let i = 0; i < chain.length; i++) {
    const status = c.trees.get(chain[i]);
    if (status === undefined) continue;
    if (status === 'collected') return undefined;
    if (!chain.slice(i).some(d => c.recursive.some(r => r.test(d)))) return undefined;
    // Recorded for the directory itself (a default skills directory linked
    // out of the home): a listing of it — names and link targets, which the
    // manifest asks for — is not its tree
    const exact = i === 0 ? (fs as SnapshotRecords).holdsContentUnder : undefined;
    return (exact ?? holds).call(fs, chain[0]) ? undefined : status;
  }
  return undefined;
}

/**
 * The probe collects this directory's contents: it is a listed directory of
 * the manifest, or it or a directory above it is collected recursively
 * (`<dir>/**`) or as a config-derived tree, or the snapshot shows it doesn't
 * exist. A tree the probe refused or capped is not covered. Always true off
 * snapshots.
 */
export function probeCoversTree(fs: FSProvider, dir: string): boolean {
  if (fs.kind !== 'snapshot') return true;
  const c = compiled(fs);
  if (!c) return true;
  const chain = selfAndAncestors(dir);
  if (chain.some(d => c.recursive.some(r => r.test(d)))) return linkedGap(fs, c, chain) === undefined;
  const status = treeStatus(c, chain);
  if (status === 'refused' || status === 'limit') return false;
  if (status === 'collected') return true;
  if (chain.length > 0 && c.listed.some(r => r.test(chain[0]))) return true;
  return listedAbsent(fs, c, chain);
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
  // Recorded by the probe — a config-named path it looked for, found or not
  if ((fs as SnapshotRecords).collected?.(path)) return true;
  const p = posix.normalize(path);
  if (c.files.some(r => r.test(p))) return true;
  const chain = selfAndAncestors(posix.dirname(p));
  if (chain.some(d => c.recursive.some(r => r.test(d)))) return true;
  return treeStatus(c, chain) === 'collected';
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
