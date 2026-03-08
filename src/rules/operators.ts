export type Operator =
  | 'eq'
  | 'neq'
  | 'in'
  | 'not-in'
  | 'exists'
  | 'not-exists'
  | 'gt'
  | 'lt'
  | 'matches'
  | 'contains';

export const VALID_OPERATORS: readonly Operator[] = [
  'eq', 'neq', 'in', 'not-in', 'exists', 'not-exists', 'gt', 'lt', 'matches', 'contains',
];

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const aKeys = Object.keys(a as Record<string, unknown>);
    const bKeys = Object.keys(b as Record<string, unknown>);
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every(k =>
      deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}

/**
 * Evaluate an operator against an actual value and an expected value.
 * For 'exists' / 'not-exists', expected is ignored.
 */
export function evaluateOperator(actual: unknown, operator: Operator, expected?: unknown): boolean {
  switch (operator) {
    case 'eq':
      return deepEqual(actual, expected);
    case 'neq':
      return !deepEqual(actual, expected);
    case 'in':
      if (!Array.isArray(expected)) return false;
      return expected.some(item => deepEqual(actual, item));
    case 'not-in':
      if (!Array.isArray(expected)) return true;
      return !expected.some(item => deepEqual(actual, item));
    case 'exists':
      return actual !== undefined;
    case 'not-exists':
      return actual === undefined;
    case 'gt':
      return typeof actual === 'number' && typeof expected === 'number' && actual > expected;
    case 'lt':
      return typeof actual === 'number' && typeof expected === 'number' && actual < expected;
    case 'matches':
      if (typeof actual !== 'string' || typeof expected !== 'string') return false;
      try {
        return new RegExp(expected).test(actual);
      } catch {
        return false;
      }
    case 'contains':
      if (Array.isArray(actual)) return actual.some(item => deepEqual(item, expected));
      if (typeof actual === 'string' && typeof expected === 'string') return actual.includes(expected);
      return false;
    default:
      return false;
  }
}
