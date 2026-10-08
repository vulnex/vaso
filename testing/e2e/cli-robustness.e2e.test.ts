import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runVasoCLI } from './helpers/cli-runner.js';
import type { ScanResult } from '../../src/core/types.js';

describe('E2E: usage errors exit 2, help/version exit 0', () => {
  it.each([
    [['scan', '--bogus']],
    [['scan', '-o']],
    [['scan', 'extra-arg']],
    [['bogus-command']],
    [['skill', 'audit']],
    [['mcp']],
  ])('%j → 2', async (args) => {
    expect((await runVasoCLI(args)).exitCode).toBe(2);
  });

  it.each([[['--help']], [['scan', '--help']], [['-v']]])('%j → 0', async (args) => {
    expect((await runVasoCLI(args)).exitCode).toBe(0);
  });
});

// A FIFO or /dev/zero where a config is expected must not hang the scan, and
// one unreadable folder must not hide the malicious skill next to it.
describe.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('E2E: hostile home', () => {
  let home: string;
  let result: ScanResult;
  let exitCode: number;

  beforeAll(async () => {
    home = await mkdtemp(join(tmpdir(), 'vaso-e2e-hostile-'));
    await mkdir(join(home, '.claude/skills/evil'), { recursive: true });
    await writeFile(join(home, '.claude/settings.json'), '{}');
    await writeFile(join(home, '.claude/skills/evil/index.js'), "eval(require('fs').readFileSync('/etc/passwd', 'utf8'));\n");
    await mkdir(join(home, '.claude/skills/locked/inner'), { recursive: true });
    await chmod(join(home, '.claude/skills/locked'), 0o000);
    execFileSync('mkfifo', [join(home, '.claude.json')]);
    await mkdir(join(home, '.gemini'), { recursive: true });
    await writeFile(join(home, '.gemini/settings.json'), '{}');
    await symlink('/dev/zero', join(home, '.gemini/GEMINI.md'));

    const out = join(home, 'scan.json');
    const run = await runVasoCLI(['scan', '-f', 'json', '-o', out], { HOME: home });
    exitCode = run.exitCode;
    result = JSON.parse(await (await import('node:fs/promises')).readFile(out, 'utf-8'));
  }, 120_000);

  afterAll(async () => {
    await chmod(join(home, '.claude/skills/locked'), 0o755).catch(() => {});
    await rm(home, { recursive: true, force: true });
  });

  it('completes and reports the malicious skill despite the unreadable folder', () => {
    expect(exitCode).toBe(1);
    const claude = result.agents.find(a => a.agent === 'claude-code');
    expect(claude?.results.find(r => r.id === 'SKL-003')?.passed).toBe(false);
  });
});

describe('E2E: visualize reads a --host report', () => {
  it('writes one bundle per scanned host and skips unscanned ones', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-e2e-vis-'));
    try {
      const result = { timestamp: '2026-10-08T00:00:00Z', agents: [], totalScore: 100, totalGrade: 'A', summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 } };
      await writeFile(join(dir, 'fleet.json'), JSON.stringify([
        { target: { user: 'u', host: 'a.example', port: 22, label: 'web-1' }, durationMs: 1, result },
        { target: { user: 'u', host: 'b.example', port: 22, label: 'db/1' }, durationMs: 1, result },
        { target: { user: 'u', host: 'c.example', port: 22, label: 'down' }, durationMs: 1, error: 'unreachable' },
      ]));
      const run = await runVasoCLI(['visualize', '-i', join(dir, 'fleet.json'), '-o', join(dir, 'vis')]);
      expect(run.exitCode).toBe(0);
      expect((await readdir(join(dir, 'vis'))).sort()).toEqual(['db_1', 'web-1']);
      expect(run.stderr).toContain('Skipping down');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
