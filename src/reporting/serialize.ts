/**
 * JSON serialization for everything VASO writes out (reports, `detect` /
 * `mcp list` JSON, baselines). Scan results carry each installation's parsed
 * config files — raw text and data, plaintext secrets included — because
 * checks need them in memory. None of that may leave the process: config
 * files keep their path and format, and MCP server env/headers values are
 * masked, so a report or a baseline never becomes a copy of the user's
 * credentials (a remote scan would otherwise move the host's secrets onto
 * the scanning machine).
 */

const MASKED_MAPS = new Set(['env', 'headers']);

function maskValue(value: string): string {
  return value.length > 8 ? `${value.slice(0, 4)}…(${value.length} chars)` : '***';
}

/** `scheme://user:password@` — the password part. */
const URL_PASSWORD = /\b([a-z][a-z0-9+.-]*:\/\/[^\s/:@"'<>]*):([^\s@/"'<>]+)@/gi;
/** `scheme://<long token>@` — a credential used as the whole userinfo (`https://ghp_…@github.com`). */
const URL_TOKEN_USER = /\b([a-z][a-z0-9+.-]*:\/\/)([A-Za-z0-9_\-.~%]{16,})@/gi;
/** `?access_token=…` and similar query parameters. */
const SECRET_QUERY = /([?&;](?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|key|secret|client[_-]?secret|password|passwd|pwd|pass|auth|sig|signature|code)=)([^&#\s"'<>]+)/gi;
/** `--token=…` / `--api-key …` style command-line arguments. */
const SECRET_ARG = /(--?(?:access[_-]?token|auth[_-]?token|token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|pass)(?:=|\s+))([^\s"'<>]+)/gi;

/**
 * Credentials that ride along inside text a finding quotes — an MCP server
 * URL with a password or `?access_token=`, a `--token=` argument — masked so
 * reports and baselines don't carry them. Only the secret part is replaced;
 * the host, path and parameter names stay readable.
 */
export function maskCredentialsInText(text: string): string {
  if (!/[:=@]/.test(text)) return text;
  return text
    .replace(URL_PASSWORD, (_m, pre: string) => `${pre}:***@`)
    .replace(URL_TOKEN_USER, (_m, scheme: string) => `${scheme}***@`)
    .replace(SECRET_QUERY, (_m, name: string) => `${name}***`)
    .replace(SECRET_ARG, (_m, flag: string) => `${flag}***`);
}

/**
 * A copy of a scan result (or any report value) with credentials masked in
 * every string; parsed config files are passed through untouched (reporters
 * never print them).
 */
export function maskCredentialsDeep<T>(value: T): T {
  if (typeof value === 'string') return maskCredentialsInText(value) as T;
  if (Array.isArray(value)) return value.map(v => maskCredentialsDeep(v)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = k === 'configFiles' ? v : maskCredentialsDeep(v);
    return out as T;
  }
  return value;
}

export function reportReplacer(this: unknown, key: string, value: unknown): unknown {
  if (typeof value === 'string') return maskCredentialsInText(value);
  if (key === 'configFiles' && Array.isArray(value)) {
    return value.map(c => (c && typeof c === 'object'
      ? { filePath: (c as { filePath?: unknown }).filePath, format: (c as { format?: unknown }).format }
      : c));
  }
  if (MASKED_MAPS.has(key) && value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(
      ([k, v]) => [k, typeof v === 'string' ? maskValue(v) : v],
    ));
  }
  return value;
}

/** Pretty-printed JSON with config contents stripped and MCP secrets masked. */
export function toReportJson(value: unknown): string {
  return JSON.stringify(value, reportReplacer, 2);
}
