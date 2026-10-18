import type { FSProvider } from '../core/fs-provider.js';
import { keySegments, type KeyPath } from '../core/utils.js';

/**
 * Overlay of an agent's documented env-var config overrides onto its parsed
 * config file, so checks judge the settings the daemon actually runs with.
 * Values come from `fs.getEnv` (the scanned host's environment — the probe
 * ships the names listed in each adapter's `envPrefixes`). The file's `raw`
 * text is untouched and fixes re-read the file from disk, so an overlay never
 * leaks into a written config.
 */

export type EnvValueType = 'bool' | 'int' | 'string';

export interface EnvOverrideSpec {
  env: string;
  /** Config path the variable overrides. */
  path: string[];
  type: EnvValueType;
}

export interface AppliedEnvOverride {
  env: string;
  path: string;
  /** `path` as segments (a key may contain a dot). */
  segments: string[];
  value: unknown;
}

const overlays = new WeakMap<object, AppliedEnvOverride[]>();

/** Go strconv.ParseBool (PicoClaw's caarlos0/env); also covers Rust's "true"/"false". */
function parseBool(v: string): boolean | undefined {
  if (['1', 't', 'T', 'TRUE', 'true', 'True'].includes(v)) return true;
  if (['0', 'f', 'F', 'FALSE', 'false', 'False'].includes(v)) return false;
  return undefined;
}

function parseValue(raw: string, type: EnvValueType): unknown {
  if (type === 'bool') return parseBool(raw);
  if (type === 'int') return /^-?\d+$/.test(raw) ? Number(raw) : undefined;
  return raw;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/** Copy-on-write set of a nested path (tables along it are cloned, not mutated). */
function setPath(data: Record<string, unknown>, path: string[], value: unknown): Record<string, unknown> {
  const [head, ...rest] = path;
  const out = { ...data };
  out[head] = rest.length === 0 ? value : setPath(asRecord(data[head]) ?? {}, rest, value);
  return out;
}

/**
 * Apply every set override in `specs` to `data` (later specs win). Empty and
 * unparseable values are ignored, as upstream does. Returns `data` itself
 * when nothing applies.
 */
export function applyEnvOverrides(
  data: Record<string, unknown>,
  specs: EnvOverrideSpec[],
  fs: FSProvider,
): Record<string, unknown> {
  let out = data;
  const applied: AppliedEnvOverride[] = [];
  for (const spec of specs) {
    const raw = fs.getEnv(spec.env)?.trim();
    if (!raw) continue;
    const value = parseValue(raw, spec.type);
    if (value === undefined) continue;
    out = setPath(out, spec.path, value);
    applied.push({ env: spec.env, path: spec.path.join('.'), segments: [...spec.path], value });
  }
  if (applied.length > 0) overlays.set(out, applied);
  return out;
}

/** The env overrides that shaped this parsed config object, if any. */
export function envOverridesOf(data: unknown): AppliedEnvOverride[] {
  return (data && typeof data === 'object' ? overlays.get(data) : undefined) ?? [];
}

/** The env var that set `path` in this config, if one did. */
export function envOverrideFor(data: unknown, path: KeyPath): string | undefined {
  const want = keySegments(path).join('\u0000');
  return envOverridesOf(data).find(o => o.segments.join('\u0000') === want)?.env;
}

/** " (set by $VAR)" suffix for evidence when an env var set `path`. */
export function envNote(data: unknown, path: KeyPath): string {
  const env = envOverrideFor(data, path);
  return env ? ` (set by $${env}, overriding the config file)` : '';
}
