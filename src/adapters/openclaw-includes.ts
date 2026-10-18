import { delimiter, dirname, isAbsolute, join, normalize, resolve } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig } from '../core/types.js';
import { loadConfig, recordLoadError } from '../core/config-loader.js';
import { pathPresent } from './load-if-present.js';

/**
 * OpenClaw `$include` directives (src/config/includes.ts, verified on 2026.9.4):
 *
 *   { gateway: { $include: "./gateway.json5" },
 *     broadcast: { $include: ["./a.json5", "./b.json5"], extra: 1 } }
 *
 * - a single file replaces the object holding the directive; an array of
 *   files is deep-merged in order (later wins; arrays concatenate)
 * - sibling keys are merged over the included content (and then require it to
 *   be an object)
 * - paths resolve relative to the including file and must stay — lexically
 *   and after symlinks — inside the top-level config's directory or an
 *   OPENCLAW_INCLUDE_ROOTS root; nesting stops at 10 levels; a file already
 *   on the include chain is a circular include
 * - directives inside arrays are resolved too
 *
 * Any violation makes OpenClaw reject the whole config. Here it becomes a
 * CONFIG-LOAD finding and the offending include contributes nothing; the
 * rest of the config is still checked. The confinement is also what keeps a
 * hostile config from making VASO read files elsewhere on the host.
 */

const INCLUDE_KEY = '$include';
const MAX_DEPTH = 10;
const MAX_PATH_LENGTH = 4096;
/** Upper bound on include loads per config: a fan-out (each file including
 *  the next one several times) is not circular but grows exponentially. */
const MAX_LOADS = 200;
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

class IncludeError extends Error {
  constructor(message: string, readonly filePath: string, readonly stage: 'read' | 'parse' = 'parse') {
    super(message);
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** OpenClaw's include merge: objects recursively, arrays concatenated, otherwise the later value wins. */
export function mergeIncluded(target: unknown, source: unknown): unknown {
  if (Array.isArray(target) && Array.isArray(source)) return [...target, ...source];
  if (!isPlainObject(target) || !isPlainObject(source)) return source;
  const out: Record<string, unknown> = { ...target };
  for (const [key, value] of Object.entries(source)) {
    if (UNSAFE_KEYS.has(key)) continue;
    out[key] = key in out ? mergeIncluded(out[key], value) : value;
  }
  return out;
}

function inside(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root.endsWith('/') ? root : `${root}/`);
}

interface Root { dir: string; real: string }

interface Session {
  fs: FSProvider;
  roots: Root[];
  /** Files read so far, by resolved path (a file shared by several logical
   *  paths is read once). */
  cache: Map<string, ParsedConfig>;
  loads: number;
  files: Set<string>;
}

async function realOrSelf(fs: FSProvider, p: string): Promise<string> {
  try {
    return normalize(await fs.realpath(p));
  } catch {
    return p;
  }
}

/** OPENCLAW_INCLUDE_ROOTS: extra roots, `:`-separated, `~` = the effective home. */
export function includeRootsFromEnv(raw: string | undefined, home: string): string[] {
  if (!raw?.trim()) return [];
  const roots: string[] = [];
  for (const entry of raw.split(delimiter)) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const expanded = trimmed === '~' || trimmed.startsWith('~/') ? join(home, trimmed.slice(1)) : trimmed;
    if (isAbsolute(expanded) && !roots.includes(normalize(expanded))) roots.push(normalize(expanded));
  }
  return roots;
}

async function loadInclude(s: Session, includePath: string, base: string, chain: string[]): Promise<unknown> {
  if (includePath.includes('\0')) throw new IncludeError('include path contains a null byte', base);
  if (includePath.length >= MAX_PATH_LENGTH) throw new IncludeError('include path too long', base);
  const resolved = normalize(isAbsolute(includePath) ? includePath : resolve(dirname(base), includePath));
  if (resolved.length >= MAX_PATH_LENGTH) throw new IncludeError('resolved include path too long', base);
  if (!s.roots.some(r => inside(r.dir, resolved))) {
    throw new IncludeError(`$include "${includePath}" escapes the config directory (${s.roots[0].dir}) — OpenClaw rejects this config`, base);
  }
  // A symlink inside the directory may point anywhere: judge where it lands.
  // A path that doesn't resolve is reported as missing below.
  let real: string | undefined;
  try {
    real = normalize(await s.fs.realpath(resolved));
  } catch {
    real = undefined;
  }
  if (real !== undefined && !s.roots.some(r => inside(r.real, real!))) {
    throw new IncludeError(`$include "${includePath}" resolves outside the config directory through a symlink — OpenClaw rejects this config`, base);
  }
  if (chain.includes(resolved)) {
    throw new IncludeError(`circular $include: ${[...chain, resolved].join(' -> ')}`, base);
  }
  if (chain.length > MAX_DEPTH) throw new IncludeError(`$include nesting deeper than ${MAX_DEPTH} levels at "${includePath}"`, base);
  if (++s.loads > MAX_LOADS) throw new IncludeError(`more than ${MAX_LOADS} $include loads — not resolved further`, base);

  let config = s.cache.get(resolved);
  if (!config) {
    if (!(await pathPresent(resolved, s.fs))) {
      // On a snapshot only the include locations the probe knows of are collected
      const why = s.fs.kind === 'snapshot'
        ? 'not collected by the remote probe (it collects the *.json5 files under the config directory) — scan the host locally to resolve it'
        : 'file not found — OpenClaw rejects this config';
      throw new IncludeError(`$include "${includePath}" from ${base}: ${why}`, resolved, 'read');
    }
    try {
      // The shared loader records an unreadable or unparseable file as CONFIG-LOAD
      config = await loadConfig(resolved, s.fs);
    } catch {
      return {};
    }
    s.cache.set(resolved, config);
  }
  s.files.add(resolved);
  return resolveNode(s, config.data, resolved, [...chain, resolved]);
}

async function resolveNode(s: Session, value: unknown, base: string, chain: string[]): Promise<unknown> {
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) out.push(await resolveNode(s, item, base, chain));
    return out;
  }
  if (!isPlainObject(value)) return value;
  if (!(INCLUDE_KEY in value)) {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value)) {
      if (UNSAFE_KEYS.has(key)) continue;
      out[key] = await resolveNode(s, v, base, chain);
    }
    return out;
  }

  const directive = value[INCLUDE_KEY];
  let included: unknown = {};
  try {
    if (typeof directive === 'string') {
      included = await loadInclude(s, directive, base, chain);
    } else if (Array.isArray(directive)) {
      for (const item of directive) {
        if (typeof item !== 'string') throw new IncludeError(`invalid $include array item (${typeof item})`, base);
        included = mergeIncluded(included, await loadInclude(s, item, base, chain));
      }
    } else {
      throw new IncludeError(`invalid $include value (${typeof directive}) — expected a path or a list of paths`, base);
    }
  } catch (err) {
    if (!(err instanceof IncludeError)) throw err;
    recordLoadError({ filePath: err.filePath, stage: err.stage, message: err.message });
    included = {};
  }

  const siblings = Object.keys(value).filter(k => k !== INCLUDE_KEY && !UNSAFE_KEYS.has(k));
  if (siblings.length === 0) return included;
  const rest: Record<string, unknown> = {};
  for (const key of siblings) rest[key] = await resolveNode(s, value[key], base, chain);
  if (!isPlainObject(included)) {
    recordLoadError({ filePath: base, stage: 'parse', message: 'keys beside $include need the included content to be an object — OpenClaw rejects this config' });
    return rest;
  }
  return mergeIncluded(included, rest);
}

/**
 * The config OpenClaw sees once `$include` directives in `config` (the
 * top-level openclaw.json) are resolved. Returns the config unchanged when it
 * has none; otherwise a copy whose `data` is the resolved tree (`raw` stays
 * the file's own text) and the included files' paths.
 */
export async function resolveOpenclawIncludes(
  config: ParsedConfig,
  fs: FSProvider,
  extraRoots: string[] = [],
): Promise<{ config: ParsedConfig; includedFiles: string[] }> {
  if (!JSON.stringify(config.data).includes(`"${INCLUDE_KEY}"`)) return { config, includedFiles: [] };
  const configDir = dirname(normalize(config.filePath));
  const roots: Root[] = [];
  for (const dir of [configDir, ...extraRoots]) roots.push({ dir, real: await realOrSelf(fs, dir) });
  const session: Session = { fs, roots, cache: new Map(), loads: 0, files: new Set() };
  const data = await resolveNode(session, config.data, normalize(config.filePath), [normalize(config.filePath)]);
  return {
    config: { ...config, data: isPlainObject(data) ? data : {} },
    includedFiles: [...session.files],
  };
}

/** loadConfig for an OpenClaw top-level config file, `$include`s resolved. */
export async function loadOpenclawConfig(filePath: string, fs: FSProvider, includeRoots: string[] = []): Promise<ParsedConfig> {
  return (await resolveOpenclawIncludes(await loadConfig(filePath, fs), fs, includeRoots)).config;
}
