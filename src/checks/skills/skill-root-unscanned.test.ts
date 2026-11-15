import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CheckModule, ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { skillChecks } from './index.js';
import { iocChecks } from '../ioc/index.js';

// A skills directory the config sets outside the user's home is not walked
// (local and remote alike). It must never read as "no skills directory": SKL-002
// reports it as a warning, once per directory; the other skill-tree checks say
// their verdict is not verified.

const ctx = (unscanned: ScanContext['installation']['unscannedSkillsDirs'], skillsDirs?: string[]): ScanContext => ({
  installation: {
    agent: 'nanobot', installDir: '/nonexistent-vaso-home/.nanobot', configFiles: [],
    ...(skillsDirs ? { skillsDirs } : {}),
    unscannedSkillsDirs: unscanned,
  },
  configs: [], platform: 'linux', fs: new LocalFSProvider(), skillFiles: [],
});

// an existing directory outside the (fake) home
const OUT = [{ path: '', reason: 'outside' as const }];
const byId = (id: string): CheckModule => [...skillChecks, ...iocChecks].find(c => c.id === id)!;
let tmp = '';

beforeAll(async () => {
  tmp = await realpath(await mkdtemp(join(tmpdir(), 'vaso-unscanned-')));
  OUT[0].path = join(tmp, 'srv', 'nanobot', 'ws', 'skills');
  await mkdir(OUT[0].path, { recursive: true });
});
afterAll(async () => rm(tmp, { recursive: true, force: true }));

describe('a skills directory outside the home', () => {
  it('SKL-002 reports it as a warning naming the directory', async () => {
    const r = await byId('SKL-002').run(ctx(OUT));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.message).toBe(`skills directory ${OUT[0].path} not scanned (outside the user's home or in a credential store)`);
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence![0].mitigated).toBeUndefined();
  });

  it('is reported once per directory, also next to scanned directories', async () => {
    const r = await byId('SKL-002').run(ctx([...OUT, { path: 'rel/skills', reason: 'relative' }], ['/nonexistent-vaso-home/skills']));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence!.filter(e => e.file === OUT[0].path)).toHaveLength(1);
    expect(r.message).toContain('rel/skills not scanned (set as a relative path)');
  });

  it.each(['SKL-001', 'SKL-003', 'SKL-004', 'SKL-005', 'SKL-006', 'SKL-007', 'SKL-008', 'SKL-009', 'SKL-010',
    'SKL-011', 'SKL-012', 'SKL-013', 'IOC-003', 'IOC-004', 'IOC-005', 'IOC-006', 'IOC-007'])(
    '%s says not verified, not "No skills directory found"', async (id) => {
      const r = await byId(id).run(ctx(OUT));
      expect(r.message).not.toMatch(/No skills/);
      expect(r.message).toContain('Not verified');
      expect(r.message).toContain(OUT[0].path);
    });

  it('SKL-002 notes one that does not exist, informational', async () => {
    const r = await byId('SKL-002').run(ctx([{ path: join(tmp, 'nonexist-zz', 'skills'), reason: 'outside' }]));
    expect(r.severity).toBe('info');
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence![0].mitigated).toBe(true);
    const missing = join(tmp, 'nonexist-zz', 'skills');
    expect(r.evidence![0].detail).toBe(`not scanned: skills directory ${missing} (outside the user's home or in a credential store) does not exist — nothing to scan`);
    expect(r.message).toContain('does not exist');
  });

  it('SKL-002 says how to review it: vaso skill audit <path>', async () => {
    const r = await byId('SKL-002').run(ctx(OUT));
    expect(r.evidence![0].detail).toContain(`review it with \`vaso skill audit ${OUT[0].path}\``);
    expect(r.evidence![0].detail).not.toContain('by hand');
  });

  it.each(['SKL-001', 'SKL-004', 'SKL-005', 'SKL-013', 'IOC-003', 'IOC-006', 'IOC-007'])(
    '%s next to a scanned directory: the pass names the one not scanned', async (id) => {
      const r = await byId(id).run(ctx(OUT, ['/nonexistent-vaso-home/skills']));
      expect(r.passed).toBe(true);
      expect(r.message.endsWith(`(skills directory ${OUT[0].path} not scanned; see SKL-002)`), r.message).toBe(true);
    });

  it('IOC-008 skipped (no API key) carries no "not scanned" note; its verdict over the trees does', async () => {
    const saved = process.env['VIRUSTOTAL_API_KEY'];
    delete process.env['VIRUSTOTAL_API_KEY'];
    try {
      const skipped = await byId('IOC-008').run(ctx(OUT, ['/nonexistent-vaso-home/skills']));
      expect(skipped.message).toBe('VirusTotal check skipped — no VIRUSTOTAL_API_KEY set');
      process.env['VIRUSTOTAL_API_KEY'] = 'k';
      const run = await byId('IOC-008').run(ctx(OUT, ['/nonexistent-vaso-home/skills']));
      expect(run.message.endsWith(`(skills directory ${OUT[0].path} not scanned; see SKL-002)`), run.message).toBe(true);
    } finally {
      if (saved === undefined) delete process.env['VIRUSTOTAL_API_KEY'];
      else process.env['VIRUSTOTAL_API_KEY'] = saved;
    }
  });

  it('without any skills directory the checks still pass as before', async () => {
    const r = await byId('SKL-004').run(ctx(undefined));
    expect(r.passed).toBe(true);
    expect(r.message).toBe('No skills directory found');
    expect((await byId('SKL-002').run(ctx(undefined))).passed).toBe(true);
  });
});
