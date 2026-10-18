import type { ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { compareVersions } from '../core/semver.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import { recordLoadError } from '../core/config-loader.js';

/**
 * Hermes' config.yaml as the agent loads it (hermes_cli/config_effective.py
 * `load_user_config_effective`, hermes_cli/managed_scope.py
 * `apply_managed_overlay`): the user's file and the administrator-managed one
 * are parsed (duplicate keys rejected from 0.21.6), `${VAR}` references in
 * their string values are expanded from the environment Hermes runs with
 * (the process environment, the user's `.env` over it, the managed `.env`
 * over both), and the managed layer's model keys are canonicalized before
 * it is merged over the user's config.
 */

/** v0.21.6 (hermes-agent 284dbaf): YAML is read with ruamel, which rejects a repeated key. */
export const HERMES_UNIQUE_KEYS = '0.21.6';
/** v2026.7.30 (0.19.1, 8d811f5): `${env:VAR}` refs, trimmed names, other `${source:…}` refs kept. */
export const HERMES_ENV_REF_SOURCES = '0.19.1';

/** undefined when the version is unknown (or not a release number). */
function atLeast(version: string | undefined, guard: string): boolean | undefined {
  if (!version || !/^v?\d+\.\d+\.\d+/.test(version)) return undefined;
  return compareVersions(version.replace(/^v/, ''), guard) >= 0;
}

/** The data each config held before expansion — what is written in the file. */
const asWritten = new WeakMap<ParsedConfig, Record<string, unknown>>();

/**
 * A Hermes config's values as written, before `${VAR}` expansion: for checks
 * about the file itself (a plaintext secret), not the value Hermes uses.
 */
export function hermesConfigAsWritten(config: ParsedConfig): Record<string, unknown> {
  return asWritten.get(config) ?? config.data;
}

const ENV_REF = /\$\{([^}]+)\}/g;
const NON_ENV_SOURCE = /^[a-z][a-z0-9_-]*:/;

/**
 * `_expand_env_vars`: `${VAR}` in string values (keys and other types
 * untouched); a reference with no value stays as written. 0.19.1+ also reads
 * `${env:VAR}` and keeps other sources (`${vault:…}`) literal; earlier
 * releases looked the text between the braces up as is. `${VAR:-x}` has no
 * default syntax there: it stays literal.
 */
export function expandHermesEnvRefs(value: unknown, lookup: (name: string) => string | undefined, version?: string): unknown {
  if (typeof value === 'string') {
    if (!value.includes('${')) return value;
    const sources = atLeast(version, HERMES_ENV_REF_SOURCES) !== false;
    return value.replace(ENV_REF, (raw, group: string) => {
      let name: string | undefined = group;
      if (sources) {
        const inner = group.trim();
        name = inner.startsWith('env:') ? inner.slice(4).trim() || undefined : NON_ENV_SOURCE.test(inner) ? undefined : inner;
      }
      return (name !== undefined ? lookup(name) : undefined) ?? raw;
    });
  }
  if (Array.isArray(value)) return value.map(v => expandHermesEnvRefs(v, lookup, version));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = expandHermesEnvRefs(v, lookup, version);
    return out;
  }
  return value;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Python truthiness of a loaded YAML value. */
function truthy(v: unknown): boolean {
  if (v === null || v === undefined || v === false || v === 0 || v === '') return false;
  if (Array.isArray(v)) return v.length > 0;
  if (isRecord(v)) return Object.keys(v).length > 0;
  return true;
}

/**
 * `_normalize_root_model_keys` (hermes_cli/config.py): root `provider` /
 * `base_url` / `context_length` move under `model` where it has none, the
 * `api_base` alias becomes `base_url`, a nested `{model, provider}` id is
 * flattened, the provider becomes a string and `model.model` / `model.name`
 * become `model.default`.
 */
export function normalizeHermesModelKeys(config: Record<string, unknown>): Record<string, unknown> {
  const modelIn = config.model;
  const provider = isRecord(modelIn) ? modelIn.provider : undefined;
  const needsModelWork = (provider !== undefined && provider !== null && typeof provider !== 'string') || (isRecord(modelIn) && (
    truthy(modelIn.api_base) || truthy(modelIn.model) || truthy(modelIn.name)
    || ['default', 'model', 'name'].some(k => isRecord(modelIn[k]))));
  const hasRoot = ['provider', 'base_url', 'context_length', 'api_base'].some(k => truthy(config[k]));
  if (!hasRoot && !needsModelWork) return config;

  const out: Record<string, unknown> = { ...config };
  const model: Record<string, unknown> = isRecord(modelIn) ? { ...modelIn } : truthy(modelIn) ? { default: modelIn } : {};
  out.model = model;
  for (const key of ['default', 'model', 'name']) {
    const v = model[key];
    if (!isRecord(v)) continue;
    const nestedModel = truthy(v.model) ? v.model : v.default;
    const nestedProvider = truthy(v.provider) ? String(v.provider).trim() : '';
    model[key] = truthy(nestedModel) ? String(nestedModel).trim() : '';
    if (nestedProvider) {
      const outer = truthy(model.provider) ? String(model.provider).trim() : '';
      if (!outer || outer === 'auto') model.provider = nestedProvider;
    }
  }
  for (const key of ['provider', 'base_url', 'context_length']) {
    if (truthy(out[key]) && !truthy(model[key])) model[key] = out[key];
    delete out[key];
  }
  if (model.provider !== undefined && model.provider !== null) model.provider = String(model.provider).trim();
  for (const alias of [out.api_base, model.api_base]) {
    if (truthy(alias) && !truthy(model.base_url)) model.base_url = alias;
  }
  delete out.api_base;
  delete model.api_base;
  const alias = truthy(model.model) ? model.model : model.name;
  if (!truthy(model.default) && truthy(alias)) model.default = alias;
  if (truthy(model.default)) {
    delete model.model;
    delete model.name;
  }
  return out;
}

/**
 * The managed layer as `apply_managed_overlay` merges it: model keys
 * canonicalized, and a bare `model: <id>` promoted to `model.default` so it
 * replaces only the id, not the user's provider and endpoint.
 */
export function hermesManagedOverlay(managed: Record<string, unknown>): Record<string, unknown> {
  const out = normalizeHermesModelKeys(managed);
  return typeof out.model === 'string' ? { ...out, model: { default: out.model } } : out;
}

/**
 * Re-read the config.yaml files with the installed release's rules and
 * expand their `${VAR}` references (after the `.env` files are read). A file
 * the release rejects is reported as CONFIG-LOAD and contributes nothing:
 * Hermes runs on defaults (the user's file) or ignores it (a managed file).
 */
export function prepareHermesYaml(configs: ParsedConfig[], fs: FSProvider, version?: string): void {
  const envs = [...configs.filter(c => c.format === 'env' && c.managed), ...configs.filter(c => c.format === 'env' && !c.managed)];
  const lookup = (name: string): string | undefined => {
    for (const c of envs) {
      const v = c.data[name];
      if (typeof v === 'string') return v;
    }
    return fs.getEnv(name);
  };
  for (const config of configs) {
    if (config.format !== 'yaml') continue;
    if (atLeast(version, HERMES_UNIQUE_KEYS) !== false) {
      try {
        parseYamlSafe(config.raw, { duplicateKeys: 'reject' });
      } catch (err) {
        const release = version ? `Hermes ${version}` : `Hermes ${HERMES_UNIQUE_KEYS}+`;
        recordLoadError({
          filePath: config.filePath,
          stage: 'parse',
          message: `${(err as Error).message} — ${release} rejects the file and ${config.managed ? 'ignores this administrator-managed config' : 'runs on its default settings'}`,
        });
        asWritten.set(config, config.data);
        config.data = {};
        continue;
      }
    }
    const expanded = expandHermesEnvRefs(config.data, lookup, version) as Record<string, unknown>;
    asWritten.set(config, config.data);
    config.data = config.managed ? hermesManagedOverlay(expanded) : expanded;
  }
}
