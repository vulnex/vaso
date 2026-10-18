import YAML from 'yaml';

/**
 * Parse YAML from a scanned file. Two hazards of plain `YAML.parse`:
 * an alias that references its own anchor (`a: &x [*x]`) yields a circular
 * object that sends every recursive config walker into a stack overflow, and
 * warnings about unknown tags go straight to stderr, past `--silent`.
 * Merge keys (`<<: *defaults`) are resolved, as PyYAML (Hermes) and Go's
 * yaml.v3 do; a `<<` whose value isn't a map stays a plain key, as before.
 */
export function parseYamlSafe(raw: string): unknown {
  let value: unknown;
  try {
    value = YAML.parse(raw, { logLevel: 'error', merge: true });
  } catch (err) {
    if (!/Merge sources must be/.test((err as Error).message)) throw err;
    value = YAML.parse(raw, { logLevel: 'error' });
  }
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
