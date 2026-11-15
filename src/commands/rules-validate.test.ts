import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, statSync, mkdirSync, chmodSync } from 'node:fs';
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
});
