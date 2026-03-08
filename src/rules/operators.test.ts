import { describe, it, expect } from 'vitest';
import { evaluateOperator, VALID_OPERATORS } from './operators.js';

describe('operators', () => {
  describe('eq', () => {
    it('matches equal primitives', () => {
      expect(evaluateOperator(true, 'eq', true)).toBe(true);
      expect(evaluateOperator('hello', 'eq', 'hello')).toBe(true);
      expect(evaluateOperator(42, 'eq', 42)).toBe(true);
    });

    it('rejects unequal primitives', () => {
      expect(evaluateOperator(true, 'eq', false)).toBe(false);
      expect(evaluateOperator('a', 'eq', 'b')).toBe(false);
    });

    it('deep-compares objects', () => {
      expect(evaluateOperator({ a: 1 }, 'eq', { a: 1 })).toBe(true);
      expect(evaluateOperator({ a: 1 }, 'eq', { a: 2 })).toBe(false);
    });

    it('deep-compares arrays', () => {
      expect(evaluateOperator([1, 2], 'eq', [1, 2])).toBe(true);
      expect(evaluateOperator([1, 2], 'eq', [2, 1])).toBe(false);
    });

    it('handles null and undefined', () => {
      expect(evaluateOperator(null, 'eq', null)).toBe(true);
      expect(evaluateOperator(undefined, 'eq', undefined)).toBe(true);
      expect(evaluateOperator(null, 'eq', undefined)).toBe(false);
    });
  });

  describe('neq', () => {
    it('matches unequal values', () => {
      expect(evaluateOperator(1, 'neq', 2)).toBe(true);
      expect(evaluateOperator(1, 'neq', 1)).toBe(false);
    });
  });

  describe('in', () => {
    it('matches value in array', () => {
      expect(evaluateOperator('a', 'in', ['a', 'b', 'c'])).toBe(true);
      expect(evaluateOperator('d', 'in', ['a', 'b', 'c'])).toBe(false);
    });

    it('returns false for non-array expected', () => {
      expect(evaluateOperator('a', 'in', 'a')).toBe(false);
    });
  });

  describe('not-in', () => {
    it('matches value not in array', () => {
      expect(evaluateOperator('d', 'not-in', ['a', 'b'])).toBe(true);
      expect(evaluateOperator('a', 'not-in', ['a', 'b'])).toBe(false);
    });

    it('returns true for non-array expected', () => {
      expect(evaluateOperator('a', 'not-in', 'x')).toBe(true);
    });
  });

  describe('exists / not-exists', () => {
    it('detects existing values', () => {
      expect(evaluateOperator('hello', 'exists')).toBe(true);
      expect(evaluateOperator(0, 'exists')).toBe(true);
      expect(evaluateOperator(null, 'exists')).toBe(true);
      expect(evaluateOperator(false, 'exists')).toBe(true);
    });

    it('detects undefined as not existing', () => {
      expect(evaluateOperator(undefined, 'exists')).toBe(false);
      expect(evaluateOperator(undefined, 'not-exists')).toBe(true);
    });
  });

  describe('gt / lt', () => {
    it('compares numbers', () => {
      expect(evaluateOperator(10, 'gt', 5)).toBe(true);
      expect(evaluateOperator(5, 'gt', 10)).toBe(false);
      expect(evaluateOperator(3, 'lt', 10)).toBe(true);
      expect(evaluateOperator(10, 'lt', 3)).toBe(false);
    });

    it('returns false for non-numbers', () => {
      expect(evaluateOperator('10', 'gt', 5)).toBe(false);
      expect(evaluateOperator(10, 'lt', 'abc')).toBe(false);
    });
  });

  describe('matches', () => {
    it('matches regex pattern', () => {
      expect(evaluateOperator('hello-world', 'matches', '^hello')).toBe(true);
      expect(evaluateOperator('goodbye', 'matches', '^hello')).toBe(false);
    });

    it('returns false for non-string inputs', () => {
      expect(evaluateOperator(42, 'matches', '42')).toBe(false);
      expect(evaluateOperator('hello', 'matches', 42)).toBe(false);
    });

    it('returns false for invalid regex', () => {
      expect(evaluateOperator('test', 'matches', '[invalid')).toBe(false);
    });
  });

  describe('contains', () => {
    it('checks string containment', () => {
      expect(evaluateOperator('hello world', 'contains', 'world')).toBe(true);
      expect(evaluateOperator('hello', 'contains', 'xyz')).toBe(false);
    });

    it('checks array containment', () => {
      expect(evaluateOperator(['a', 'b', 'c'], 'contains', 'b')).toBe(true);
      expect(evaluateOperator(['a', 'b'], 'contains', 'z')).toBe(false);
    });

    it('returns false for non-string/array actual', () => {
      expect(evaluateOperator(42, 'contains', '4')).toBe(false);
    });
  });

  describe('unknown operator', () => {
    it('returns false', () => {
      expect(evaluateOperator(1, 'bogus' as never, 1)).toBe(false);
    });
  });

  it('exports all valid operators', () => {
    expect(VALID_OPERATORS).toHaveLength(10);
  });
});
