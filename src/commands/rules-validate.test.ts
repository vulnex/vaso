import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, statSync, mkdirSync, chmodSync, symlinkSync, readFileSync, lstatSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { registerAllChecks } from '../checks/index.js';
import { checkRegistry } from '../core/check-registry.js';
import { runRulesInit, runRulesValidate } from './rules.js';

const rule = (id: string) => `  - id: ${id}\n    name: n\n    category: config\n    severity: warning\n    description: d\n    file_exists:\n      path: ".env"\n      pass_when: "not-exists"\n`;

describe('vaso rules validate (dt17)', () => {
  afterEach(() => { process.exitCode = 0; vi.restoreAllMocks(); });

  it('reports a built-in check ID and a duplicate ID — the rules scan would skip', async () => {
    if (checkRegistry.getAll().length === 0) registerAllChecks();
    const file = join(mkdtempSync(join(tmpdir(), 'vaso-rules-')), 'r.yml');
    writeFileSync(file, `rules:\n${rule('CC-001')}${rule('ORG-100')}${rule('ORG-100')}`);
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    await runRulesValidate(file, { format: 'json' });
    const report = JSON.parse(out.join('\n'));
    expect(report.valid).toBe(false);
    expect(report.rules).toBe(1);
    expect(report.errors.map((e: { message: string }) => e.message).join('\n')).toMatch(/built-in check ID[\s\S]*more than once/);
    expect(process.exitCode).toBe(1);
  });

  it('exits 1 on invalid rules and on bad YAML in every format, as terminal mode does', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-rules-'));
    const bad = join(dir, 'bad.yml');
    writeFileSync(bad, 'rules:\n  - id: X\n');
    const yaml = join(dir, 'yaml.yml');
    writeFileSync(yaml, 'rules: [\n');
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    for (const format of ['json', undefined]) {
      for (const file of [bad, yaml]) {
        process.exitCode = 0;
        out.length = 0;
        await runRulesValidate(file, { format });
        expect(process.exitCode).toBe(1);
        if (format === 'json') expect(JSON.parse(out.join('\n')).valid).toBe(false);
      }
    }
  });

  it('prints no YAML warning quoting the file (an unresolved tag)', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'vaso-rules-')), 'r.yml');
    writeFileSync(file, 'rules:\n  - id: ORG-1\n    password: !secret sk-ant-api03-TagPlantedQq77\n');
    const out: string[] = [];
    const sink = (...a: unknown[]) => { out.push(a.map(String).join(' ')); };
    vi.spyOn(console, 'log').mockImplementation(sink);
    vi.spyOn(console, 'error').mockImplementation(sink);
    vi.spyOn(console, 'warn').mockImplementation(sink);
    vi.spyOn(process, 'emitWarning').mockImplementation(sink as never);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation((c: unknown) => { out.push(String(c)); return true; });
    for (const format of ['json', undefined]) await runRulesValidate(file, { format });
    stderr.mockRestore();
    expect(out.join('\n')).not.toContain('TagPlanted');
    expect(out.join('\n')).not.toMatch(/Unresolved tag/);
  });

  it('judges a duplicate key as vaso scan --rules does: same verdict, same message', async () => {
    const { loadRules } = await import('../rules/index.js');
    const dir = mkdtempSync(join(tmpdir(), 'vaso-rules-'));
    const file = join(dir, 'r.yml');
    writeFileSync(file, `rules:\n  - id: ORG-1\n    id: ORG-DupPlanted9\n${rule('ORG-2').replace(/^ {2}- id: ORG-2\n/, '')}`);
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    await runRulesValidate(file, { format: 'json' });
    const report = JSON.parse(out.join('\n'));
    expect(report.valid).toBe(false);
    expect(process.exitCode).toBe(1);
    const loaded = await loadRules({ extraPaths: [file], skipGlobal: true, skipProject: true });
    const scanErrors = loaded.allErrors.filter(e => e.file === file).map(e => e.message);
    expect(scanErrors).toEqual(report.errors.map((e: { message: string }) => e.message));
    expect(scanErrors[0]).toMatch(/^Invalid YAML syntax: .*duplicate key at line 3/);
  });

  it('escapes control characters in the path it prints', async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'vaso-rules-')), 'p\x1b]0;PWN\x07\u202eX');
    mkdirSync(dir);
    const file = join(dir, 'r.yml');
    writeFileSync(file, `rules:\n${rule('ORG-100')}`);
    const out: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.join(' ')); });
    await runRulesValidate(file, {});
    expect(out.join('\n')).toMatch(/valid rule/);
    expect(out.join('\n')).not.toMatch(/[\x1b\x07\u202e]/);
  });
});

describe.skipIf(process.platform === 'win32')('vaso rules init', () => {
  afterEach(() => { process.exitCode = 0; vi.restoreAllMocks(); });

  it('writes the starter file owner-only whatever the umask, also over an existing file with --force', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = join(mkdtempSync(join(tmpdir(), 'vaso-rules-init-')), 'rules');
    const old = process.umask(0o002);
    try {
      await runRulesInit({ dir });
      expect(statSync(join(dir, 'example.yaml')).mode & 0o777).toBe(0o600);
      chmodSync(join(dir, 'example.yaml'), 0o664);
      await runRulesInit({ dir, force: true });
      expect(statSync(join(dir, 'example.yaml')).mode & 0o777).toBe(0o600);
    } finally {
      process.umask(old);
    }
  });

  it('creates the --dir folder owner-only whatever the umask', async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'vaso-rules-init-')), 'a', 'rules');
    const old = process.umask(0o000);
    try {
      await runRulesInit({ dir });
      expect(statSync(dir).mode & 0o777).toBe(0o700);
      expect(statSync(join(dir, '..')).mode & 0o777).toBe(0o700);
    } finally {
      process.umask(old);
    }
  });

  it('says --dir is not a directory when it is a file, not that example.yaml exists', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vaso-rules-init-'));
    const file = join(root, 'rl');
    writeFileSync(file, 'mine\n');
    const err: string[] = [];
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { err.push(a.join(' ')); });
    for (const dir of [file, join(file, 'sub')]) {
      for (const force of [false, true]) {
        err.length = 0;
        await runRulesInit({ dir, force });
        expect(process.exitCode).toBe(2);
        process.exitCode = 0;
        expect(err.join('\n')).toMatch(/is not a directory/);
        expect(err.join('\n')).not.toMatch(/already exists/);
      }
    }
    expect(readFileSync(file, 'utf-8')).toBe('mine\n');
    expect(readdirSync(root)).toEqual(['rl']);
  });

  it.skipIf(process.platform === 'win32')('--force replaces a symlinked example.yaml, never writing or chmodding its target', async () => {
    const root = mkdtempSync(join(tmpdir(), 'vaso-rules-init-'));
    const dir = join(root, 'rules');
    mkdirSync(dir);
    const victim = join(root, 'victim.txt');
    writeFileSync(victim, 'keep\n');
    chmodSync(victim, 0o644);
    symlinkSync('../victim.txt', join(dir, 'example.yaml'));
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    await runRulesInit({ dir });
    expect(process.exitCode).toBe(2);
    process.exitCode = 0;
    expect(readFileSync(victim, 'utf-8')).toBe('keep\n');
    await runRulesInit({ dir, force: true });
    expect(process.exitCode).toBe(0);
    expect(readFileSync(victim, 'utf-8')).toBe('keep\n');
    expect(statSync(victim).mode & 0o777).toBe(0o644);
    expect(lstatSync(join(dir, 'example.yaml')).isSymbolicLink()).toBe(false);
    expect(statSync(join(dir, 'example.yaml')).mode & 0o777).toBe(0o600);
    expect(readdirSync(dir)).toEqual(['example.yaml']);
  });
});
