import YAML from 'yaml';

/**
 * Parse YAML from a scanned file. Two hazards of plain `YAML.parse`:
 * an alias that references its own anchor (`a: &x [*x]`) yields a circular
 * object that sends every recursive config walker into a stack overflow, and
 * warnings about unknown tags go straight to stderr, past `--silent`.
 */
export function parseYamlSafe(raw: string): unknown {
  const value = YAML.parse(raw, { logLevel: 'error' });
  if (isCyclic(value)) throw new Error('YAML contains a self-referencing alias');
  return value;
}

function isCyclic(value: unknown, ancestors = new Set<object>()): boolean {
  if (!value || typeof value !== 'object') return false;
  if (ancestors.has(value)) return true;
  ancestors.add(value);
  for (const child of Object.values(value)) {
    if (isCyclic(child, ancestors)) return true;
  }
  ancestors.delete(value);
  return false;
}
