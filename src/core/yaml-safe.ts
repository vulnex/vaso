import YAML from 'yaml';

export interface YamlSafeOptions {
  /**
   * A key repeated in one mapping: `last` (default) resolves it to its last
   * value, as PyYAML's safe_load does; `reject` throws, as ruamel.yaml does
   * (Hermes 0.21.6+).
   */
  duplicateKeys?: 'last' | 'reject';
}

/**
 * Parse YAML from a scanned file. Two hazards of plain `YAML.parse`:
 * an alias that references its own anchor (`a: &x [*x]`) yields a circular
 * object that sends every recursive config walker into a stack overflow, and
 * warnings about unknown tags go straight to stderr, past `--silent`.
 * Merge keys (`<<: *defaults`) are resolved, as PyYAML (Hermes) and Go's
 * yaml.v3 do; a `<<` whose value isn't a map stays a plain key, as before.
 */
export function parseYamlSafe(raw: string, opts: YamlSafeOptions = {}): unknown {
  // The library's own uniqueness check compares every key with every other
  // (80,000 keys: 2 minutes); duplicates are found in one pass instead
  const options = { logLevel: 'error', uniqueKeys: false } as const;
  if (opts.duplicateKeys === 'reject') assertUniqueKeys(raw);
  let value: unknown;
  try {
    value = YAML.parse(raw, { ...options, merge: true });
  } catch (err) {
    if (!/Merge sources must be/.test((err as Error).message)) throw err;
    value = YAML.parse(raw, options);
  }
  if (isCyclic(value)) throw new Error('YAML contains a self-referencing alias');
  return value;
}

/** Throw on the first key a mapping repeats (scalar keys; merge keys `<<` excepted). */
function assertUniqueKeys(raw: string): void {
  const lineCounter = new YAML.LineCounter();
  const docs = YAML.parseAllDocuments(raw, { logLevel: 'error', uniqueKeys: false, lineCounter });
  for (const doc of Array.isArray(docs) ? docs : [docs]) {
    YAML.visit(doc, {
      Map(_, map) {
        const seen = new Set<string>();
        for (const pair of map.items) {
          if (!YAML.isScalar(pair.key) || pair.key.value === '<<') continue;
          const id = `${typeof pair.key.value}:${String(pair.key.value)}`;
          if (seen.has(id)) {
            const line = pair.key.range ? lineCounter.linePos(pair.key.range[0]).line : undefined;
            throw new Error(`found duplicate key "${String(pair.key.value)}"${line ? ` at line ${line}` : ''}`);
          }
          seen.add(id);
        }
      },
    });
  }
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
