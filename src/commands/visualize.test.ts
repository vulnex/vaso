import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtemp, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hostDirNames, runVisualize } from './visualize.js';

describe('hostDirNames', () => {
  it('never yields ., .. or an empty name', () => {
    const names = hostDirNames(['..', '.', '', '...']);
    for (const n of names) {
      expect(n).not.toMatch(/^\.*$/);
      expect(n).not.toContain('/');
    }
    expect(new Set(names.map(n => n.toLowerCase())).size).toBe(names.length);
  });

  it('keeps user@host labels readable', () => {
    expect(hostDirNames(['alice@box'])).toEqual(['alice@box']);
  });

  it('gives labels that sanitize to the same name distinct directories', () => {
    expect(hostDirNames(['a b', 'a_b', 'A_B', 'a/b'])).toEqual(['a_b', 'a_b-2', 'A_B-3', 'a_b-4']);
  });

  it('keeps long labels within file-name limits and unique', () => {
    const long = 'x'.repeat(300);
    const [a, b] = hostDirNames([long, `${long}y`]);
    expect(a.length).toBeLessThanOrEqual(100);
    expect(a).not.toBe(b);
  });
});

describe('runVisualize multi-host input', () => {
  let dir: string | undefined;
  afterEach(async () => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  const result = { agents: [], totalScore: 100, totalGrade: 'A', timestamp: '2026-01-01T00:00:00Z' };

  it('writes every host bundle inside -o, even for a ".." label', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-vis-'));
    const input = join(dir, 'fleet.json');
    await writeFile(input, JSON.stringify([
      { target: { label: '..', host: 'h1' }, result },
      { target: { label: 'b', host: 'h2' }, result },
    ]));
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const out = join(dir, 'out', 'inner');
    await runVisualize({ input, output: out });
    expect(process.exitCode ?? 0).toBe(0);
    expect((await readdir(join(dir, 'out'))).sort()).toEqual(['inner']);
    expect((await readdir(out)).sort()).toEqual(['b', 'host__']);
  });

  it('escapes control characters from the input in the skip notice', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-vis-'));
    const input = join(dir, 'fleet.json');
    await writeFile(input, JSON.stringify([
      { target: { label: 'bad\u001b]0;TITLE\u0007\u001b[2J' }, error: 'x\u001b[31m' },
      { target: { label: 'ok' }, result },
    ]));
    const errs: string[] = [];
    vi.spyOn(console, 'error').mockImplementation((m: unknown) => { errs.push(String(m)); });
    const logs: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((m: unknown) => { logs.push(String(m)); });
    await runVisualize({ input, output: join(dir, 'out') });
    const skip = errs.find(e => e.includes('Skipping'));
    expect(skip).toBeDefined();
    // chalk may add its own SGR codes; the input's OSC/BEL/clear-screen must not survive
    expect(skip).not.toContain('\u0007');
    expect(skip).not.toContain('\u001b]0;');
    expect(skip).not.toContain('\u001b[2J');
    expect(skip).not.toContain('x\u001b[31m');
  });
});
