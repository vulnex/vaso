import { describe, it, expect } from 'vitest';
import { pathGlobMatch, wildcardMatch } from './wildcard.js';

describe('pathGlobMatch', () => {
  it('matches *, ? and classes within one segment', () => {
    expect(pathGlobMatch('/home/*/.aws', '/home/test/.aws')).toBe(true);
    expect(pathGlobMatch('/home/*', '/home/test/.aws')).toBe(false);
    expect(pathGlobMatch('/e?c', '/etc')).toBe(true);
    expect(pathGlobMatch('/home/test/.[sa][sw][hs]', '/home/test/.ssh')).toBe(true);
    expect(pathGlobMatch('/home/test/.[!s]sh', '/home/test/.ssh')).toBe(false);
    expect(pathGlobMatch('/home/test/.[a-z]sh', '/home/test/.ssh')).toBe(true);
  });

  it('matches ** across any number of segments, zero included', () => {
    expect(pathGlobMatch('/home/**/.ssh', '/home/test/.ssh')).toBe(true);
    expect(pathGlobMatch('/home/**/.ssh', '/home/.ssh')).toBe(true);
    expect(pathGlobMatch('/**', '/')).toBe(true);
    expect(pathGlobMatch('/opt/**/cache', '/home/test')).toBe(false);
  });

  it('reads an invalid or unterminated class as literal text and never throws', () => {
    expect(() => pathGlobMatch('/home/test/.[z-a]sh', '/home/test/.ssh')).not.toThrow();
    expect(pathGlobMatch('/home/test/.[z-a]sh', '/home/test/.ssh')).toBe(false);
    expect(pathGlobMatch('/home/test/.[z-a]sh', '/home/test/.[z-a]sh')).toBe(true);
    expect(pathGlobMatch('/a/[bc', '/a/[bc')).toBe(true);
  });

  it('reads pattern and path by code point: astral characters in literals, ?, * and classes', () => {
    expect(pathGlobMatch('/data/😀/x', '/data/😀/x')).toBe(true);
    expect(pathGlobMatch('/data/?/x', '/data/😀/x')).toBe(true);
    expect(pathGlobMatch('/data/??/x', '/data/😀/x')).toBe(false);
    expect(pathGlobMatch('/data/*😀/x', '/data/ab😀/x')).toBe(true);
    expect(pathGlobMatch('/data/[😀😁]/x', '/data/😁/x')).toBe(true);
    expect(pathGlobMatch('/data/[!😀]/x', '/data/😀/x')).toBe(false);
    expect(pathGlobMatch('/data/[😀-😂]/x', '/data/😁/x')).toBe(true);
    expect(pathGlobMatch('/data/[a-z]/x', '/data/😁/x')).toBe(false);
    expect(pathGlobMatch('/data/e?/x', '/data/é/x')).toBe(true);
    expect(pathGlobMatch('/data/\\😀/x', '/data/😀/x')).toBe(true);
  });

  it('stays fast on star runs and long globs that backtrack as a RegExp', () => {
    const start = Date.now();
    expect(pathGlobMatch(`/home/test/${'*'.repeat(40)}x`, '/home/test/.ssh')).toBe(false);
    expect(pathGlobMatch(`/home/test/${'*a'.repeat(1000)}x`, `/home/test/${'a'.repeat(200)}`)).toBe(false);
    expect(pathGlobMatch(`${'/**'.repeat(1000)}/x`, '/home/test/.ssh')).toBe(false);
    expect(pathGlobMatch(`${'/*'.repeat(1000)}`, '/home/test/.ssh')).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe('wildcardMatch', () => {
  it('matches * across any characters, ? only when asked', () => {
    expect(wildcardMatch('mcp-*', 'mcp-github')).toBe(true);
    expect(wildcardMatch('a*b', 'a/x/b')).toBe(true);
    expect(wildcardMatch('a?c', 'abc')).toBe(false);
    expect(wildcardMatch('a?c', 'abc', { question: true })).toBe(true);
    expect(wildcardMatch('*.EXAMPLE.com', 'api.example.com', { ignoreCase: true })).toBe(true);
    expect(wildcardMatch('a.c', 'abc')).toBe(false);
  });

  it('reads pattern and text by code point: astral characters, combining marks', () => {
    // a literal equal to the name matches
    expect(wildcardMatch('srv-😀', 'srv-😀')).toBe(true);
    expect(wildcardMatch('srv-😀', 'srv-😁')).toBe(false);
    expect(wildcardMatch('*😀*', 'srv-😀-x')).toBe(true);
    expect(wildcardMatch('srv-*', 'srv-😀')).toBe(true);
    // `?` is one character, an astral one included
    expect(wildcardMatch('srv-?', 'srv-😀', { question: true })).toBe(true);
    expect(wildcardMatch('srv-??', 'srv-😀', { question: true })).toBe(false);
    expect(wildcardMatch('?', '𝒳', { question: true })).toBe(true);
    // a combining mark is its own code point
    expect(wildcardMatch('e?', 'é', { question: true })).toBe(true);
    expect(wildcardMatch('?', 'é', { question: true })).toBe(false);
    expect(wildcardMatch('café', 'café')).toBe(true);
    expect(wildcardMatch('caf*', 'café')).toBe(true);
    expect(wildcardMatch('😀*', '😀', { ignoreCase: true })).toBe(true);
  });

  it('stays fast on many stars', () => {
    const start = Date.now();
    expect(wildcardMatch(`${'a*'.repeat(30)}b`, 'a'.repeat(5000))).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
