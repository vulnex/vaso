import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateSnapshot, loadSnapshotFile, SnapshotLoadError, MAX_SNAPSHOT_FILE_CONTENT_CHARS,
} from './snapshot-load.js';

function snap(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: 't',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: { '/home/u/.x/config.json': { content: '{}', mode: 0o600, exists: true } },
    directories: {}, commandOutputs: {}, env: {},
    ...overrides,
  };
}

describe('validateSnapshot', () => {
  it('accepts a probe-shaped snapshot', () => {
    expect(validateSnapshot(snap())).toEqual([]);
  });

  it('rejects non-objects and missing homedir', () => {
    expect(validateSnapshot(null)).toEqual(['Snapshot is not a JSON object']);
    expect(validateSnapshot([])).toEqual(['Snapshot is not a JSON object']);
    expect(validateSnapshot(snap({ homedir: undefined }))).toContain('Missing or relative homedir field');
    expect(validateSnapshot(snap({ homedir: 'rel/home' }))).toContain('Missing or relative homedir field');
  });

  it('rejects a non-string probeVersion instead of crashing on it', () => {
    expect(validateSnapshot(snap({ probeVersion: 131 }))).toContain('Invalid probeVersion field (a version string expected)');
    expect(validateSnapshot(snap({ probeVersion: '1.3.1' }))).toEqual([]);
  });

  it('rejects privilege without scannedUsers', () => {
    const errors = validateSnapshot(snap({ privilege: { username: 'u' } }));
    expect(errors.some(e => e.startsWith('Invalid privilege field'))).toBe(true);
  });

  it('rejects malformed file entries and oversized content', () => {
    expect(validateSnapshot(snap({ files: { '/a': 'x', '/b': { content: 5 } } })))
      .toContain('2 file entries are not {content, mode, exists} objects');
    const big = 'a'.repeat(MAX_SNAPSHOT_FILE_CONTENT_CHARS + 1);
    const errors = validateSnapshot(snap({ files: { '/big': { content: big, mode: 0o600, exists: true } } }));
    expect(errors.some(e => e.includes("per-file limit"))).toBe(true);
  });
});

describe('loadSnapshotFile', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-snapload-')); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('loads a valid file and reports problems for an invalid one', async () => {
    const good = join(dir, 'good.json');
    await writeFile(good, JSON.stringify(snap()));
    expect((await loadSnapshotFile(good)).hostname).toBe('h');

    const bad = join(dir, 'bad.json');
    await writeFile(bad, JSON.stringify(snap({ homedir: undefined })));
    await expect(loadSnapshotFile(bad)).rejects.toBeInstanceOf(SnapshotLoadError);

    await writeFile(join(dir, 'nojson.json'), '{');
    await expect(loadSnapshotFile(join(dir, 'nojson.json'))).rejects.toThrow(/not valid JSON/);
    await expect(loadSnapshotFile(join(dir, 'missing.json'))).rejects.toThrow(/not found/);
  });

  it('neutralizes terminal escapes in the host and user names it prints', async () => {
    const path = join(dir, 'esc.json');
    await writeFile(path, JSON.stringify(snap({
      hostname: 'box\u001b]8;;https://evil.example\u0007click\u001b]8;;\u0007',
      privilege: { uid: 1000, username: 'u\u001b[2J', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['a\nb'], skippedPaths: [] },
    })));
    const s = await loadSnapshotFile(path);
    expect(s.hostname).toBe('box\\x1b]8;;https://evil.example\\x07click\\x1b]8;;\\x07');
    expect(s.privilege.username).toBe('u\\x1b[2J');
    expect(s.privilege.scannedUsers).toEqual(['a\\nb']);
    // Ordinary names are untouched
    await writeFile(path, JSON.stringify(snap({ hostname: 'web-01.example.com' })));
    expect((await loadSnapshotFile(path)).hostname).toBe('web-01.example.com');
  });
});

describe('probeVersionWarning', () => {
  it('warns for snapshots from an older or unversioned probe only', async () => {
    const { probeVersionWarning } = await import('./snapshot-load.js');
    expect(probeVersionWarning({}, '1.3.1')).toMatch(/older than 1\.3\.1/);
    expect(probeVersionWarning({ probeVersion: '1.2.1' }, '1.3.1')).toMatch(/1\.2\.1, older/);
    expect(probeVersionWarning({ probeVersion: '1.3.0' }, '1.3.1')).toBeUndefined();
    expect(probeVersionWarning({ probeVersion: '1.4.0' }, '1.3.1')).toBeUndefined();
    expect(probeVersionWarning({ probeVersion: 'dev' }, '1.3.1')).toBeUndefined();
  });
});

describe('validateSnapshot field types', () => {
  it('rejects a string or out-of-range mode instead of reading it as 0 (owner-only)', async () => {
    const { validateSnapshot } = await import('./snapshot-load.js');
    const base = {
      version: 1, platform: 'linux', hostname: 'h', homedir: '/home/u', timestamp: 't',
      directories: {}, commandOutputs: {}, env: {},
    };
    const ok = { ...base, files: { '/home/u/.env': { content: 'A=1', mode: 0o644, exists: true } } };
    expect(validateSnapshot(ok)).toEqual([]);
    expect(validateSnapshot({ ...base, files: { '/home/u/.env': { content: '', mode: '0644', exists: true } } }).join()).toMatch(/not \{content, mode, exists\}/);
    expect(validateSnapshot({ ...base, files: { '/x': { content: '', mode: 0o644, exists: 'yes' } } }).length).toBe(1);
    expect(validateSnapshot({ ...ok, directoryModes: { '/home/u': '755' } }).join()).toMatch(/directoryModes/);
    expect(validateSnapshot({ ...ok, owners: { '/home/u': [1000] } }).join()).toMatch(/owners/);
  });
});
