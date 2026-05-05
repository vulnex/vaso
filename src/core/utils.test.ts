import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getNestedValue, setNestedValue, deepMerge, writeFileEnsureDir } from './utils.js';

describe('getNestedValue', () => {
  it('retrieves a nested value by dot path', () => {
    expect(getNestedValue({ a: { b: 1 } }, 'a.b')).toBe(1);
  });

  it('returns undefined for missing paths', () => {
    expect(getNestedValue({ a: 1 }, 'b.c')).toBeUndefined();
  });
});

describe('setNestedValue', () => {
  it('sets a deeply nested value', () => {
    const obj: Record<string, unknown> = {};
    setNestedValue(obj, 'a.b.c', 1);
    expect(obj).toEqual({ a: { b: { c: 1 } } });
  });
});

describe('deepMerge', () => {
  it('merges shallow properties', () => {
    const result = deepMerge({ a: 1, b: 2 }, { b: 3, c: 4 });
    expect(result).toEqual({ a: 1, b: 3, c: 4 });
  });

  it('merges deeply nested objects', () => {
    const base = { gateway: { host: '127.0.0.1', port: 8080, tls: false } };
    const override = { gateway: { tls: true, auth: 'token' } };
    const result = deepMerge(base, override);
    expect(result).toEqual({
      gateway: { host: '127.0.0.1', port: 8080, tls: true, auth: 'token' },
    });
  });

  it('override wins on conflict', () => {
    const result = deepMerge(
      { sandbox: true, permissions: { read: true } },
      { sandbox: false, permissions: { read: false, write: true } },
    );
    expect(result).toEqual({
      sandbox: false,
      permissions: { read: false, write: true },
    });
  });

  it('arrays from override replace base arrays', () => {
    const result = deepMerge(
      { tools: ['a', 'b'], nested: { list: [1, 2] } },
      { tools: ['c'], nested: { list: [3, 4, 5] } },
    );
    expect(result).toEqual({
      tools: ['c'],
      nested: { list: [3, 4, 5] },
    });
  });

  it('does not mutate base or override', () => {
    const base = { a: { b: 1 } };
    const override = { a: { c: 2 } };
    const baseCopy = JSON.parse(JSON.stringify(base));
    const overrideCopy = JSON.parse(JSON.stringify(override));
    deepMerge(base, override);
    expect(base).toEqual(baseCopy);
    expect(override).toEqual(overrideCopy);
  });

  it('handles empty objects', () => {
    expect(deepMerge({}, { a: 1 })).toEqual({ a: 1 });
    expect(deepMerge({ a: 1 }, {})).toEqual({ a: 1 });
    expect(deepMerge({}, {})).toEqual({});
  });
});

describe('writeFileEnsureDir', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs) {
      await rm(d, { recursive: true, force: true }).catch(() => {});
    }
    dirs.length = 0;
  });

  it('writes a file when the parent directory already exists', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-wfed-'));
    dirs.push(root);
    const path = join(root, 'report.json');
    await writeFileEnsureDir(path, '{"ok":true}');
    expect(await readFile(path, 'utf-8')).toBe('{"ok":true}');
  });

  it('creates missing intermediate directories', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-wfed-'));
    dirs.push(root);
    const path = join(root, 'a', 'b', 'c', 'report.json');
    await writeFileEnsureDir(path, 'hello');
    expect(await readFile(path, 'utf-8')).toBe('hello');
  });

  it('overwrites an existing file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-wfed-'));
    dirs.push(root);
    const path = join(root, 'r.txt');
    await writeFileEnsureDir(path, 'first');
    await writeFileEnsureDir(path, 'second');
    expect(await readFile(path, 'utf-8')).toBe('second');
  });

  it('does not error on a bare filename in cwd-equivalent', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-wfed-'));
    dirs.push(root);
    const path = join(root, 'plain.txt'); // parent is the temp dir, which exists
    await writeFileEnsureDir(path, 'x');
    const s = await stat(path);
    expect(s.isFile()).toBe(true);
  });
});
