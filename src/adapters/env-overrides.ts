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

/** `bool`: Go strconv.ParseBool (PicoClaw); `rust-bool`: Rust's
 *  `bool::from_str`, exactly `true`/`false` (ZeroClaw refuses to load on any
 *  other spelling, so such a value sets nothing); `list`: caarlos0/env slices
 *  (PicoClaw), split on "," with entries kept as written; `zeroclaw-list`: a
 *  JSON array of strings or a trimmed comma-separated list (ZeroClaw's
 *  Vec<String> overrides). */
export type EnvValueType = 'bool' | 'rust-bool' | 'int' | 'string' | 'list' | 'zeroclaw-list';

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
  if (type === 'rust-bool') return raw === 'true' ? true : raw === 'false' ? false : undefined;
  if (type === 'zeroclaw-list') {
    if (raw.startsWith('[')) {
      try {
        const v: unknown = JSON.parse(raw);
        return Array.isArray(v) && v.every(x => typeof x === 'string') ? v : undefined;
      } catch {
        return undefined;
      }
    }
    return raw.split(',').map(s => s.trim()).filter(s => s !== '');
  }
  if (type === 'int') return /^-?\d+$/.test(raw) ? Number(raw) : undefined;
  // caarlos0/env slices: split on the default "," separator, entries kept as written
  if (type === 'list') return raw.split(',');
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

/**
 * Fill settings the file leaves unset from environment values, the way
 * pydantic-settings merges `env_prefix` variables under the file's own
 * values (`Config.model_validate(file)` on a BaseSettings model): a value the
 * file sets, at any depth, wins. `isSet(record, key)` says whether the file
 * already holds `key` (in whatever spellings the agent accepts). Recorded like
 * `applyEnvOverrides`, so `envOverridesOf` / `envNote` see these too.
 */
export function applyEnvDefaults(
  data: Record<string, unknown>,
  entries: Array<{ env: string; path: string[]; value: unknown }>,
  isSet: (record: Record<string, unknown>, key: string) => string | undefined,
): Record<string, unknown> {
  let out = data;
  const applied: AppliedEnvOverride[] = [...envOverridesOf(data)];
  const before = applied.length;
  for (const entry of entries) {
    // walk down the file's own tables; stop where the file sets the value
    let rec: Record<string, unknown> | undefined = out;
    const segments: string[] = [];
    let blocked = false;
    for (let i = 0; i < entry.path.length; i++) {
      const key = entry.path[i];
      const existing = rec ? isSet(rec, key) : undefined;
      if (existing === undefined) {
        segments.push(key, ...entry.path.slice(i + 1));
        break;
      }
      segments.push(existing);
      const next: Record<string, unknown> | undefined = asRecord(rec![existing]);
      if (i === entry.path.length - 1 || !next) {
        blocked = true;
        break;
      }
      rec = next;
    }
    if (blocked) continue;
    out = setPath(out, segments, entry.value);
    applied.push({ env: entry.env, path: segments.join('.'), segments, value: entry.value });
  }
  if (applied.length > before) overlays.set(out, applied);
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
