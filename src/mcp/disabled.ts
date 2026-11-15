/**
 * A server entry switched off in its own config — `enabled: false` (Codex,
 * OpenCode, Hermes, Atomic Agent, PicoClaw) or `disabled: true` (Windsurf,
 * Devin, Abacus.AI). It is never launched, so checks judging how a server is
 * launched skip it, as discovery and `vaso mcp scan` do. Checks for secrets at
 * rest in the entry still apply.
 */
export function isDisabledServerConfig(entry: unknown, opts: { yaml11?: boolean } = {}): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const e = entry as Record<string, unknown>;
  return e.enabled === false || e.disabled === true || (opts.yaml11 === true && isYaml11False(e.enabled));
}

/**
 * A YAML 1.1 false (`no`, `off`, `false` in any of PyYAML's spellings). Our
 * YAML parser reads 1.2, where those are strings; a Python agent (Hermes)
 * loads its config with PyYAML, which reads them as false.
 */
export function isYaml11False(value: unknown): boolean {
  return value === false || (typeof value === 'string' && /^(?:no|No|NO|off|Off|OFF|false|False|FALSE)$/.test(value));
}

/** A Hermes `mcp_servers` map with YAML 1.1 `enabled` falsy spellings read as false. */
export function hermesServerMap(map: unknown): unknown {
  if (!map || typeof map !== 'object' || Array.isArray(map)) return map;
  return Object.fromEntries(Object.entries(map as Record<string, unknown>).map(([name, raw]) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [name, raw];
    const e = raw as Record<string, unknown>;
    return [name, isYaml11False(e.enabled) ? { ...e, enabled: false } : e];
  }));
}
