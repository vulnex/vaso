import { describe, it, expect, vi, afterAll } from 'vitest';
import { mkdirSync, writeFileSync, readFileSync, statSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanResult } from './types.js';

const home = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  home.dir = actual.platform() === 'win32' ? '' : (await import('node:fs')).mkdtempSync(join(actual.tmpdir(), 'vaso-baseline-'));
  return { ...actual, homedir: () => home.dir };
});

const SECRET = 'sk-or-v1-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';

describe.skipIf(process.platform === 'win32')('saveBaseline', () => {
  afterAll(() => { if (home.dir) rmSync(home.dir, { recursive: true, force: true }); });

  it('writes owner-only files without config contents, tightening an existing latest.json', async () => {
    // Importing the module first runs the node:os mock, which creates the temp home
    const { saveBaseline, loadBaseline } = await import('./baseline.js');
    expect(home.dir).not.toBe('');
    const dir = join(home.dir, '.vaso', 'baselines');
    mkdirSync(dir, { recursive: true, mode: 0o755 });
    writeFileSync(join(dir, 'latest.json'), '{}', { mode: 0o644 });
    const result: ScanResult = {
      timestamp: '2026-10-05T00:00:00.000Z',
      agents: [{
        agent: 'qwen-code',
        installation: { agent: 'qwen-code', installDir: '/h/.qwen', configFiles: [{ filePath: '/h/.qwen/settings.json', format: 'json', raw: `{"apiKey":"${SECRET}"}`, data: { apiKey: SECRET } }] },
        results: [], score: 100, grade: 'A',
      }],
      totalScore: 100, totalGrade: 'A',
    } as unknown as ScanResult;

    const path = await saveBaseline(result);
    for (const p of [path, join(dir, 'latest.json')]) {
      expect(readFileSync(p, 'utf-8')).not.toContain(SECRET);
      expect(statSync(p).mode & 0o777, p).toBe(0o600);
    }
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    // Diffing still works from the stripped baseline
    const loaded = await loadBaseline();
    expect(loaded?.agents[0].installation.installDir).toBe('/h/.qwen');
  });
});

