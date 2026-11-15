/**
 * A server entry switched off in its own config — `enabled: false` (Codex,
 * OpenCode, Hermes, Atomic Agent, PicoClaw) or `disabled: true` (Windsurf,
 * Devin, Abacus.AI). It is never launched, so checks judging how a server is
 * launched skip it, as discovery and `vaso mcp scan` do. Checks for secrets at
 * rest in the entry still apply. `yaml11`: a Hermes entry, judged as Hermes
 * does (hermesServerEnabled).
 */
export function isDisabledServerConfig(entry: unknown, opts: { yaml11?: boolean } = {}): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const e = entry as Record<string, unknown>;
  if (opts.yaml11 === true) return !hermesServerEnabled(e);
  return e.enabled === false || e.disabled === true;
}

const TRUE_WORDS = new Set(['true', '1', 'yes', 'on']);
const FALSE_WORDS = new Set(['false', '0', 'no', 'off']);

/**
 * Hermes' `_parse_boolish` (tools/mcp_tool_common.py): a bool or number is
 * itself (`0` is off), a string is one of true/1/yes/on or false/0/no/off
 * once trimmed and lowercased — PyYAML loads `no` as false and `"no"` as that
 * string, both off — and anything else (null, unparseable) is the default.
 */
function parseBoolish(value: unknown, dflt: boolean): boolean {
  if (value === null || value === undefined) return dflt;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') {
    const w = value.trim().toLowerCase();
    if (TRUE_WORDS.has(w)) return true;
    if (FALSE_WORDS.has(w)) return false;
  }
  return dflt;
}

/**
 * Whether Hermes launches a `mcp_servers.<name>` entry — its
 * `mcp_server_enabled`: `enabled` on (absent, null or unparseable = on) and
 * a legacy `disabled` not on (it wins over `enabled`).
 */
export function hermesServerEnabled(e: Record<string, unknown>): boolean {
  return parseBoolish(e.enabled, true) && !parseBoolish(e.disabled, false);
}

/** A Hermes `mcp_servers` map with the entries Hermes doesn't launch marked `enabled: false`. */
export function hermesServerMap(map: unknown): unknown {
  if (!map || typeof map !== 'object' || Array.isArray(map)) return map;
  return Object.fromEntries(Object.entries(map as Record<string, unknown>).map(([name, raw]) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [name, raw];
    const e = raw as Record<string, unknown>;
    return [name, hermesServerEnabled(e) ? e : { ...e, enabled: false }];
  }));
}
