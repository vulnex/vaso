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

export function reportReplacer(this: unknown, key: string, value: unknown): unknown {
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
