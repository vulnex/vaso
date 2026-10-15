import type { ParsedConfig } from '../core/types.js';

/**
 * Hermes API server settings, resolved the way Hermes does. Documented
 * sources (hermes-agent docs, "API Server"): `API_SERVER_*` environment
 * variables (`~/.hermes/.env`), which take precedence, and `gateway.api_server`
 * in `config.yaml`. The gateway also bridges these into
 * `platforms.api_server.extra`, so that form is read too; the bare
 * `platforms.api_server.host` older VASO read is kept last.
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

export function hermesApiServer(configs: Array<Pick<ParsedConfig, 'format' | 'data'> & { filePath?: string }>): HermesApiServer {
  const out: HermesApiServer = {};
  const env = configs.filter(c => c.format === 'env');
  const yaml = configs.filter(c => c.format !== 'env');
  for (const [field, envKey, yamlKey] of FIELDS) {
    for (const c of env) {
      const v = scalar(c.data[envKey]);
      if (v !== undefined) { out[field] = { value: v, file: c.filePath, source: `${envKey}=${field === 'key' ? '<set>' : v}` }; break; }
    }
    if (out[field]) continue;
    for (const c of yaml) {
      const candidates: Array<[unknown, string]> = [
        [record(record(c.data.gateway)?.api_server)?.[yamlKey], `gateway.api_server.${yamlKey}`],
        [record(record(record(c.data.platforms)?.api_server)?.extra)?.[yamlKey], `platforms.api_server.extra.${yamlKey}`],
        [record(record(c.data.platforms)?.api_server)?.[yamlKey], `platforms.api_server.${yamlKey}`],
      ];
      const hit = candidates.find(([v]) => scalar(v) !== undefined);
      if (hit) {
        const v = scalar(hit[0])!;
        out[field] = { value: v, file: c.filePath, source: `${hit[1]}: ${field === 'key' ? '<set>' : v}` };
        break;
      }
    }
  }
  return out;
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
