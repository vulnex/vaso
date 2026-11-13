import { describe, expect, it } from 'vitest';
import { relative } from 'node:path';
import { relEscapes } from './path-rel.js';

describe('relEscapes', () => {
  it('treats ..x names as inside and ../x as outside', () => {
    expect(relEscapes(relative('/a', '/a/..x.js'))).toBe(false);
    expect(relEscapes(relative('/a', '/a/..'))).toBe(true);
    expect(relEscapes(relative('/a/b', '/a/c'))).toBe(true);
    expect(relEscapes(relative('/a', '/a/b/..c/d'))).toBe(false);
    expect(relEscapes('')).toBe(false);
  });
});
