/**
 * A server entry switched off in its own config — `enabled: false` (Codex,
 * OpenCode, Hermes, Atomic Agent, PicoClaw) or `disabled: true` (Windsurf,
 * Devin, Abacus.AI). It is never launched, so checks judging how a server is
 * launched skip it, as discovery and `vaso mcp scan` do. Checks for secrets at
 * rest in the entry still apply.
 */
export function isDisabledServerConfig(entry: unknown): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const e = entry as Record<string, unknown>;
  return e.enabled === false || e.disabled === true;
}
