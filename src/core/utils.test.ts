import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, stat, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getNestedValue, setNestedValue, deepMerge, writeFileEnsureDir, getSkillFiles, isExcludedPath, listSkillTree, writeFileOwnerOnly } from './utils.js';
import { lstat, readdir, symlink } from 'node:fs/promises';

describe.skipIf(process.platform === 'win32')('writeFileOwnerOnly', () => {
  let dir: string;
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('replaces a symlink at the target instead of writing through it, 0600 from the start', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-owneronly-'));
    const victim = join(dir, 'victim');
    await writeFile(victim, 'keep', { mode: 0o644 });
    const out = join(dir, 'host.json');
    await symlink(victim, out);
    await writeFileOwnerOnly(out, '{"snap":1}');
    expect(await readFile(victim, 'utf-8')).toBe('keep');
    expect((await lstat(out)).isSymbolicLink()).toBe(false);
    expect(await readFile(out, 'utf-8')).toBe('{"snap":1}');
    expect((await stat(out)).mode & 0o777).toBe(0o600);
    // Overwrites an existing file, and leaves no temp file behind
    await writeFileOwnerOnly(out, 'v2');
    expect(await readFile(out, 'utf-8')).toBe('v2');
    expect((await readdir(dir)).sort()).toEqual(['host.json', 'victim']);
  });
});

describe('getNestedValue', () => {
  it('retrieves a nested value by dot path', () => {
    expect(getNestedValue({ a: { b: 1 } }, 'a.b')).toBe(1);
  });

  it('returns undefined for missing paths', () => {
    expect(getNestedValue({ a: 1 }, 'b.c')).toBeUndefined();
  });

  it('reads own keys only, never Object.prototype', () => {
    expect(getNestedValue({}, 'constructor')).toBeUndefined();
    expect(getNestedValue({ a: {} }, 'a.__proto__')).toBeUndefined();
    expect(getNestedValue({ a: {} }, 'a.toString')).toBeUndefined();
    expect(getNestedValue(JSON.parse('{"constructor": 1}') as Record<string, unknown>, 'constructor')).toBe(1);
    expect(getNestedValue({ list: [1, 2] }, 'list.1')).toBe(2);
  });
});

describe('setNestedValue', () => {
  it('sets a deeply nested value', () => {
    const obj: Record<string, unknown> = {};
    setNestedValue(obj, 'a.b.c', 1);
    expect(obj).toEqual({ a: { b: { c: 1 } } });
  });

  it('refuses a path through the prototype', () => {
    for (const path of ['__proto__.polluted', 'a.__proto__.polluted', 'constructor.prototype.polluted', 'prototype']) {
      expect(() => setNestedValue({}, path, true)).toThrow(/not config keys/);
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
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

describe('getSkillFiles', () => {
  const roots: string[] = [];

  afterEach(async () => {
    for (const d of roots) {
      await rm(d, { recursive: true, force: true }).catch(() => {});
    }
    roots.length = 0;
  });

  it('returns nothing for a non-existent directory', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    const files = await getSkillFiles(join(root, 'does-not-exist'));
    expect(files).toEqual([]);
  });

  it('an executable key or token is not code; a credential-named script or binary is', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    await writeFile(join(root, 'id_ed25519'), 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2g\n', { mode: 0o755 });
    await writeFile(join(root, 'token'), 'Q7rT2mZ9kLp4Vw8NcB1dYh6Ju3Fs0GxE\n', { mode: 0o755 });
    await writeFile(join(root, 'tokens'), '#!/bin/sh\necho hi\n', { mode: 0o755 });
    await writeFile(join(root, 'secrets'), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), { mode: 0o755 });
    await writeFile(join(root, 'setup'), 'echo plain shell\n', { mode: 0o755 });
    const files = (await getSkillFiles(root)).map(f => f.slice(root.length + 1)).sort();
    expect(files).toEqual(['secrets', 'setup', 'tokens']);
  });

  it('collects every text file; skips assets, hidden extensionless files and key files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    await writeFile(join(root, 'a.js'), 'a');
    await writeFile(join(root, 'b.py'), 'b');
    await writeFile(join(root, 'README.md'), 'docs');
    await writeFile(join(root, 'data.json'), '{}');
    await writeFile(join(root, 'logo.png'), 'x');
    await writeFile(join(root, '.DS_Store'), 'x');
    await writeFile(join(root, 'server.key'), 'x');
    const files = await getSkillFiles(root);
    expect(files.map(f => f.replace(root + '/', '')).sort()).toEqual(['README.md', 'a.js', 'b.py', 'data.json']);
  });

  it('excludes node_modules subtrees', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    await writeFile(join(root, 'skill.js'), '// user code');
    await mkdir(join(root, 'node_modules', 'big-lib', 'dist'), { recursive: true });
    await writeFile(join(root, 'node_modules', 'big-lib', 'index.js'), 'vendor');
    await writeFile(join(root, 'node_modules', 'big-lib', 'dist', 'bundle.min.js'), 'vendor');
    const files = await getSkillFiles(root);
    expect(files).toHaveLength(1);
    expect(files[0]).toBe(join(root, 'skill.js'));
  });

  it('excludes .git, .venv, __pycache__, .cache, .next, venv', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    await writeFile(join(root, 'keep.ts'), 'k');
    for (const excluded of ['.git', '.venv', 'venv', '__pycache__', '.cache', '.next']) {
      await mkdir(join(root, excluded), { recursive: true });
      await writeFile(join(root, excluded, 'noisy.js'), 'x');
    }
    const files = await getSkillFiles(root);
    expect(files).toHaveLength(1);
    expect(files[0]).toBe(join(root, 'keep.ts'));
  });

  it('reads dist/ and build/ inside a skill — the code SKILL.md runs', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    await mkdir(join(root, 'ev-dist', 'dist'), { recursive: true });
    await mkdir(join(root, 'ev-build', 'build'), { recursive: true });
    await writeFile(join(root, 'ev-dist', 'dist', 'index.js'), 'x');
    await writeFile(join(root, 'ev-build', 'build', 'run.py'), 'x');
    expect((await getSkillFiles(root)).sort()).toEqual([
      join(root, 'ev-build', 'build', 'run.py'),
      join(root, 'ev-dist', 'dist', 'index.js'),
    ]);
  });

  it('keeps excluding dist/ and build/ outside skill trees (isExcludedPath default)', () => {
    expect(isExcludedPath('/opt/agent', '/opt/agent/dist')).toBe(true);
    expect(isExcludedPath('/opt/agent', '/opt/agent/dist', { keepBuildOutput: true })).toBe(false);
    expect(isExcludedPath('/opt/agent', '/opt/agent/x/node_modules/y', { keepBuildOutput: true })).toBe(true);
  });

  it('collects .mts/.cts/.zsh/.ps1, SKILL.md, binaries and extensionless executables', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    await mkdir(join(root, 's', 'scripts'), { recursive: true });
    for (const f of ['a.mts', 'b.cts', 'c.zsh', 'd.ps1', 'SKILL.md', 'tool.node', 'x.exe', 'README.md', 'LICENSE']) {
      await writeFile(join(root, 's', f), 'x');
    }
    await writeFile(join(root, 's', 'scripts', 'setup'), '#!/bin/sh\nid\n', { mode: 0o755 });
    const names = (await getSkillFiles(root)).map(f => f.slice(root.length + 3)).sort();
    expect(names).toEqual(['LICENSE', 'README.md', 'SKILL.md', 'a.mts', 'b.cts', 'c.zsh', 'd.ps1', 'scripts/setup', 'tool.node', 'x.exe']);
    // what counts as code (inventory hasCode)
    const code = (await listSkillTree(root)).codeFiles.map(f => f.slice(root.length + 3)).sort();
    expect(code).toEqual(['a.mts', 'b.cts', 'c.zsh', 'd.ps1', 'scripts/setup', 'tool.node', 'x.exe']);
  });

  it('does not exclude directories whose names merely contain an excluded segment', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    roots.push(root);
    // "distribution" and "building" should NOT be filtered (only exact segments)
    await mkdir(join(root, 'distribution'), { recursive: true });
    await mkdir(join(root, 'building'), { recursive: true });
    await writeFile(join(root, 'distribution', 'a.js'), 'a');
    await writeFile(join(root, 'building', 'b.py'), 'b');
    const files = await getSkillFiles(root);
    expect(files).toHaveLength(2);
  });
});

describe.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('unlistable skill directories', () => {
  it('still yields SKILL.md of a skill dir that can be entered but not listed', async () => {
    const { mkdtemp, mkdir, writeFile, chmod, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { getSkillFiles, unlistableSkillDirs } = await import('./utils.js');
    const root = await mkdtemp(join(tmpdir(), 'vaso-skx-'));
    const skill = join(root, 'helper');
    await mkdir(skill);
    await writeFile(join(skill, 'SKILL.md'), '# helper');
    await writeFile(join(skill, 'run.js'), 'x');
    await chmod(skill, 0o111);
    try {
      expect(await unlistableSkillDirs(root)).toEqual([skill]);
      expect(await getSkillFiles(root)).toEqual([join(skill, 'SKILL.md')]);
    } finally {
      await chmod(skill, 0o755);
      await rm(root, { recursive: true, force: true });
    }
  });
});
