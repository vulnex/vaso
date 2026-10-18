import type { ParsedConfig } from '../core/types.js';
import { compareVersions } from '../core/semver.js';
import { byHermesPrecedence } from './hermes-managed.js';

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
 * refused unless origins are listed).
 */
export interface HermesSetting {
  value: string;
  /** File the value came from. */
  file?: string;
  /** How it was set, for evidence (`API_SERVER_HOST=…`, `gateway.api_server.host`). */
  source: string;
}

export interface HermesApiServer {
  enabled?: HermesSetting;
  host?: HermesSetting;
  port?: HermesSetting;
  key?: HermesSetting;
  corsOrigins?: HermesSetting;
}

const FIELDS: Array<[keyof HermesApiServer, string, string]> = [
  ['enabled', 'API_SERVER_ENABLED', 'enabled'],
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
  /** v2026.5.28: refuses to start without API_SERVER_KEY, loopback included. */
  anyKey: '0.15.0',
  /** v2026.7.1: also refuses a placeholder key or one shorter than 16 characters. */
  strongKey: '0.18.0',
  /** v2026.7.30: the API_SERVER_* env block applies only alongside a usable env key. */
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
export function hermesApiServer(
  configs: Array<Pick<ParsedConfig, 'format' | 'data' | 'managed'> & { filePath?: string }>,
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

  // Whether the gateway applies the API_SERVER_* block (and enables the server from it)
  const envKey = fromEnv('key', 'API_SERVER_KEY');
  const envEnabled = fromEnv('enabled', 'API_SERVER_ENABLED');
  const envApplies = atLeast(version, HERMES_API_GUARDS.envNeedsKey) === false
    ? !!envKey || isTruthy(envEnabled?.value)
    : isUsableHermesKey(envKey?.value);

  const out: HermesApiServer = {};
  for (const [field, envName, yamlKey] of FIELDS) {
    let setting: HermesSetting | undefined;
    if (field === 'enabled') {
      // API_SERVER_ENABLED counts only when the env block applies; a usable
      // env key then enables the server on its own
      setting = envApplies
        ? envEnabled ?? (envKey && { ...envKey, value: 'true' })
        : fromYaml(field, yamlKey);
    } else {
      setting = envApplies
        ? fromEnv(field, envName) ?? fromYaml(field, yamlKey)
        : fromYaml(field, yamlKey) ?? fromEnv(field, envName);
    }
    if (setting) out[field] = setting;
  }
  return out;
}

export type HermesApiServerState =
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
  const key = api.key?.value;
  if (atLeast(version, HERMES_API_GUARDS.strongKey)) return isUsableHermesKey(key) ? 'authenticated' : 'refused';
  if (key) return 'authenticated';
  if (atLeast(version, HERMES_API_GUARDS.anyKey)) return 'refused';
  const nonLoopbackGuard = atLeast(version, HERMES_API_GUARDS.nonLoopbackKey);
  if (nonLoopbackGuard === undefined) return 'unknown';
  const loopback = isLoopbackHost(api.host?.value ?? HERMES_API_DEFAULT_HOST);
  return nonLoopbackGuard && !loopback ? 'refused' : 'unauthenticated';
}

export const HERMES_API_DEFAULT_HOST = '127.0.0.1';
export const HERMES_API_DEFAULT_PORT = 8642;

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
export function isLoopbackHost(host: string): boolean {
  return LOOPBACK.has(host.toLowerCase()) || /^127\./.test(host);
}

export function isTruthy(v: string | undefined): boolean {
  return v !== undefined && /^(1|true|yes|on)$/i.test(v);
}
