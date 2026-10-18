import type { ParsedConfig } from '../core/types.js';
import { compareVersions } from '../core/semver.js';
import { byHermesPrecedence, hermesYamlSetting } from './hermes-managed.js';

/**
 * Hermes API server settings, resolved the way Hermes does. Documented
 * sources (hermes-agent docs, "API Server"): `API_SERVER_*` environment
 * variables (`~/.hermes/.env`) and `gateway.api_server` in `config.yaml`
 * (also accepted under `gateway.platforms.api_server`; the gateway bridges
 * these into `platforms.api_server.extra`, so that form is read too; the
 * bare `platforms.api_server.host` older VASO read is kept last).
 * The docs say the environment wins, but the gateway applies the
 * `API_SERVER_*` block only alongside a usable `API_SERVER_KEY` (0.19.1+;
 * earlier releases alongside `API_SERVER_ENABLED` or any key). Otherwise
 * config.yaml wins and the env values are fallbacks (`listen_address()`:
 * `extra.get("host", os.getenv("API_SERVER_HOST"))`).
 * Defaults: disabled, 127.0.0.1:8642, no CORS (browser cross-origin calls are
 * refused unless origins are listed). The server runs only when enabled
 * (`hermesApiServerEnabled`): a host or key alone starts nothing.
 */
export interface HermesSetting {
  value: string;
  /** File the value came from. */
  file?: string;
  /** How it was set, for evidence (`API_SERVER_HOST=…`, `gateway.api_server.host`). */
  source: string;
}

export interface HermesApiServer {
  /** Whether the installed release starts the server (see `active`): the
   *  setting that decided it, when one did. */
  enabled?: HermesSetting;
  /** Hermes enables the API server with these settings. */
  active: boolean;
  host?: HermesSetting;
  port?: HermesSetting;
  key?: HermesSetting;
  corsOrigins?: HermesSetting;
}

const FIELDS: Array<[Exclude<keyof HermesApiServer, 'enabled' | 'active'>, string, string]> = [
  ['host', 'API_SERVER_HOST', 'host'],
  ['port', 'API_SERVER_PORT', 'port'],
  ['key', 'API_SERVER_KEY', 'key'],
  ['corsOrigins', 'API_SERVER_CORS_ORIGINS', 'cors_origins'],
];

function record(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

function scalar(v: unknown): string | undefined {
  if (typeof v === 'string') return v.trim() || undefined;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v) && v.every(x => typeof x === 'string')) return v.join(',') || undefined;
  return undefined;
}

/**
 * Hermes releases (`hermes_cli.__version__`, from the hermes-agent history)
 * where the API server's start-up rules changed.
 */
export const HERMES_API_GUARDS = {
  /** v2026.4.13: refuses a non-loopback bind without API_SERVER_KEY. */
  nonLoopbackKey: '0.9.0',
  /** v2026.4.30: a platform's config `enabled` is coerced (`"false"`, `off` are false; an unknown word is false). */
  coercedEnabled: '0.12.0',
  /** v2026.5.28: refuses to start without API_SERVER_KEY, loopback included. */
  anyKey: '0.15.0',
  /** v2026.7.1: also refuses a placeholder key or one shorter than 16 characters. */
  strongKey: '0.18.0',
  /** v2026.7.20: API_SERVER_ENABLED is read with the shared truthy set (also `on`, surrounding spaces). */
  envTruthy: '0.19.0',
  /** v2026.7.30: the API_SERVER_* env block applies only alongside a usable env key,
   *  API_SERVER_ENABLED is no longer read, and a config `enabled` key beats the env key. */
  envNeedsKey: '0.19.1',
} as const;

/** undefined when the version is unknown (or not a release number). */
function atLeast(version: string | undefined, guard: string): boolean | undefined {
  if (!version || !/^v?\d+\.\d+\.\d+/.test(version)) return undefined;
  return compareVersions(version.replace(/^v/, ''), guard) >= 0;
}

/** Placeholder values `hermes_cli.auth.has_usable_secret` rejects. */
const PLACEHOLDER_SECRETS = new Set([
  '*', '**', '***', 'changeme', 'your_api_key', 'your_api_key_here', 'your-api-key',
  'placeholder', 'example', 'dummy', 'null', 'none',
]);

/** `has_usable_secret(key, min_length=16)`: a key Hermes 0.18.0+ starts with. */
export function isUsableHermesKey(key: string | undefined): boolean {
  const k = key?.trim().toLowerCase() ?? '';
  if (k.length < 16 || PLACEHOLDER_SECRETS.has(k)) return false;
  if (k.startsWith('your_') && k.endsWith('_here')) return false;
  for (const prefix of ['sk-', 'ghp_', 'hf_']) {
    if (k.startsWith(prefix) && /^x+$/.test(k.slice(prefix.length))) return false;
  }
  return !/^x+$/.test(k.replace(/[ _-]/g, ''));
}

/**
 * @param version the installed Hermes version; env precedence follows the
 *   current release when it is unknown.
 */
type HermesConfigLike = Pick<ParsedConfig, 'format' | 'data' | 'managed'> & { filePath?: string };

export function hermesApiServer(
  configs: HermesConfigLike[],
  version?: string,
): HermesApiServer {
  // The administrator-managed layer (/etc/hermes) wins over the user's files
  const ordered = byHermesPrecedence(configs);
  const env = ordered.filter(c => c.format === 'env');
  const yaml = ordered.filter(c => c.format !== 'env');

  const fromEnv = (field: keyof HermesApiServer, envKey: string): HermesSetting | undefined => {
    for (const c of env) {
      const v = scalar(c.data[envKey]);
      if (v !== undefined) return { value: v, file: c.filePath, source: `${envKey}=${field === 'key' ? '<set>' : v}` };
    }
    return undefined;
  };
  const fromYaml = (field: keyof HermesApiServer, yamlKey: string): HermesSetting | undefined => {
    for (const c of yaml) {
      const gateway = record(c.data.gateway);
      const candidates: Array<[unknown, string]> = [
        [record(gateway?.api_server)?.[yamlKey], `gateway.api_server.${yamlKey}`],
        [record(record(gateway?.platforms)?.api_server)?.[yamlKey], `gateway.platforms.api_server.${yamlKey}`],
        [record(record(record(c.data.platforms)?.api_server)?.extra)?.[yamlKey], `platforms.api_server.extra.${yamlKey}`],
        [record(record(c.data.platforms)?.api_server)?.[yamlKey], `platforms.api_server.${yamlKey}`],
      ];
      const hit = candidates.find(([v]) => scalar(v) !== undefined);
      if (hit) {
        const v = scalar(hit[0])!;
        return { value: v, file: c.filePath, source: `${hit[1]}: ${field === 'key' ? '<set>' : v}` };
      }
    }
    return undefined;
  };

  // Whether the gateway applies the API_SERVER_* block
  const envKey = fromEnv('key', 'API_SERVER_KEY');
  const envApplies = atLeast(version, HERMES_API_GUARDS.envNeedsKey) === false
    ? !!envKey || envEnablesLegacy(env, version)
    : isUsableHermesKey(envKey?.value);

  const out: HermesApiServer = { active: false };
  for (const [field, envName, yamlKey] of FIELDS) {
    const setting = envApplies
      ? fromEnv(field, envName) ?? fromYaml(field, yamlKey)
      : fromYaml(field, yamlKey) ?? fromEnv(field, envName);
    if (setting) out[field] = setting;
  }

  // Enabled by the installed release's rules (the current ones when it is unknown)
  const yamlEnabled = hermesYamlEnabled(yaml);
  const release = atLeast(version, '0.0.0') === undefined ? HERMES_API_GUARDS.envNeedsKey : version!;
  const enabled = enabledUnder(release, yamlEnabled, env, envKey);
  out.active = !!enabled;
  out.enabled = enabled ?? yamlEnabled?.setting;
  return out;
}

/** `enabled` keys of the platform blocks the gateway merges, highest precedence first. */
const ENABLED_PATHS = ['gateway.api_server.enabled', 'platforms.api_server.enabled', 'gateway.platforms.api_server.enabled'];

interface YamlEnabled { value: unknown; setting: HermesSetting }

/**
 * The config `enabled` the gateway reads: the later platform block wins
 * (`merge_platform_sections`), the managed layer per leaf. Its presence —
 * even `enabled: null` — makes the choice explicit (`_enabled_explicit`).
 */
function hermesYamlEnabled(yaml: HermesConfigLike[]): YamlEnabled | undefined {
  for (const path of ENABLED_PATHS) {
    // (a managed scalar above the key replaces the user's block: no key there)
    const hit = hermesYamlSetting(yaml, path);
    if (hit && hit.value !== undefined) return { value: hit.value, setting: { value: String(hit.value), file: hit.file, source: `${path}: ${String(hit.value)}` } };
  }
  return undefined;
}

/** PyYAML (YAML 1.1) booleans that VASO's YAML 1.2 parser keeps as strings. */
const YAML11_TRUE = new Set(['yes', 'Yes', 'YES', 'on', 'On', 'ON']);
const YAML11_FALSE = new Set(['no', 'No', 'NO', 'off', 'Off', 'OFF']);

/** Whether the release turns the server on for this config `enabled` value. */
function yamlEnables(value: unknown, release: string): boolean {
  if (atLeast(release, HERMES_API_GUARDS.coercedEnabled)) {
    // `_coerce_bool(value, False)`
    if (value === null || value === undefined) return false;
    if (typeof value === 'string') return /^(?:1|true|yes|on)$/.test(value.trim().toLowerCase());
    return pythonTruthy(value);
  }
  // `data.get("enabled", False)` as loaded: Python truthiness (a quoted "false" is on)
  if (typeof value === 'string' && YAML11_TRUE.has(value)) return true;
  if (typeof value === 'string' && YAML11_FALSE.has(value)) return false;
  return pythonTruthy(value);
}

function pythonTruthy(value: unknown): boolean {
  if (value === null || value === undefined || value === false || value === 0 || value === '') return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}

/** An API_SERVER_* value as written in the env files (managed layer first). */
function rawEnv(env: HermesConfigLike[], name: string): { value: string; file?: string } | undefined {
  for (const c of env) {
    const v = c.data[name];
    if (typeof v === 'string') return { value: v, file: c.filePath };
  }
  return undefined;
}

/** Before 0.19.1: a truthy API_SERVER_ENABLED enables the server (as does any key). */
function envEnablesLegacy(env: HermesConfigLike[], release: string | undefined): boolean {
  const raw = rawEnv(env, 'API_SERVER_ENABLED')?.value ?? '';
  return atLeast(release, HERMES_API_GUARDS.envTruthy)
    ? /^(?:1|true|yes|on)$/.test(raw.trim().toLowerCase())
    : ['true', '1', 'yes'].includes(raw.toLowerCase());
}

/**
 * The setting that makes `release` enable the API server
 * (`PlatformConfig.from_dict`, then the env pass `_apply_env_overrides` /
 * `gateway/config_env._api_server`); undefined when it stays off.
 */
function enabledUnder(
  release: string,
  yamlEnabled: YamlEnabled | undefined,
  env: HermesConfigLike[],
  envKey: HermesSetting | undefined,
): HermesSetting | undefined {
  if (yamlEnabled && yamlEnables(yamlEnabled.value, release)) return yamlEnabled.setting;
  const set = (name: string): HermesSetting | undefined => {
    const hit = rawEnv(env, name);
    if (!hit) return undefined;
    return { value: 'true', file: hit.file, source: name === 'API_SERVER_KEY' ? 'API_SERVER_KEY=<set>' : `${name}=${hit.value}` };
  };
  if (!atLeast(release, HERMES_API_GUARDS.envNeedsKey)) {
    // The env force-enables it, over a config `enabled: false` too
    if (envEnablesLegacy(env, release)) return set('API_SERVER_ENABLED');
    return rawEnv(env, 'API_SERVER_KEY')?.value ? set('API_SERVER_KEY') : undefined;
  }
  // A usable key enables it, unless the config sets `enabled` at all
  return isUsableHermesKey(envKey?.value) && !yamlEnabled ? set('API_SERVER_KEY') : undefined;
}

export type HermesApiServerState =
  /** Not enabled: Hermes never starts it. */
  | 'disabled'
  /** Starts with a bearer key. */
  | 'authenticated'
  /** Hermes refuses to start it with this configuration. */
  | 'refused'
  /** Starts and accepts unauthenticated requests. */
  | 'unauthenticated'
  /** No key: refused or open depending on the release, and the version is unknown. */
  | 'unknown';

/**
 * What the installed Hermes does with this API server configuration
 * (`APIServerAdapter._api_key_passes_startup_guard` and its predecessors).
 */
export function hermesApiServerState(api: HermesApiServer, version?: string): HermesApiServerState {
  if (!api.active) return 'disabled';
  const key = api.key?.value;
  if (atLeast(version, HERMES_API_GUARDS.strongKey)) return isUsableHermesKey(key) ? 'authenticated' : 'refused';
  if (key) return 'authenticated';
  if (atLeast(version, HERMES_API_GUARDS.anyKey)) return 'refused';
  const nonLoopbackGuard = atLeast(version, HERMES_API_GUARDS.nonLoopbackKey);
  if (nonLoopbackGuard === undefined) return 'unknown';
  const loopback = isLoopbackHost(api.host?.value ?? HERMES_API_DEFAULT_HOST);
  return nonLoopbackGuard && !loopback ? 'refused' : 'unauthenticated';
}

/** Pass message for an API server Hermes doesn't enable. */
export const HERMES_API_DISABLED = 'Hermes API server is not enabled — it never listens';

export const HERMES_API_DEFAULT_HOST = '127.0.0.1';
export const HERMES_API_DEFAULT_PORT = 8642;

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
export function isLoopbackHost(host: string): boolean {
  return LOOPBACK.has(host.toLowerCase()) || /^127\./.test(host);
}

export function isTruthy(v: string | undefined): boolean {
  return v !== undefined && /^(1|true|yes|on)$/i.test(v);
}
