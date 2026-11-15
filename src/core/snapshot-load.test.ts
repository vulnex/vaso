import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateSnapshot, loadSnapshotFile, SnapshotLoadError, MAX_SNAPSHOT_FILE_CONTENT_CHARS, MAX_CONFIG_TREES,
  snapshotErrorLines,
} from './snapshot-load.js';

describe('validateSnapshot configTrees', () => {
  it('accepts literal absolute directory keys with a known status', () => {
    expect(validateSnapshot(snap({ configTrees: { '/home/u/ws/skills': 'collected', '/': 'refused', '/home/u/a*b': 'limit' } }))).toEqual([]);
  });

  it('rejects too many trees, relative, unnormalized or over-long keys', () => {
    const many = Object.fromEntries(Array.from({ length: MAX_CONFIG_TREES + 1 }, (_, i) => [`/home/u/t${i}`, 'collected']));
    expect(validateSnapshot(snap({ configTrees: many })).join()).toMatch(/more than 2000 trees/);
    for (const key of ['rel/skills', '/home/u/../x', '/home/u/ws/', '/home//u', `/${'a'.repeat(5000)}`, '/a\0b', '']) {
      expect(validateSnapshot(snap({ configTrees: { [key]: 'collected' } })).join(), JSON.stringify(key.slice(0, 20)))
        .toMatch(/normalized absolute directory paths/);
    }
    expect(validateSnapshot(snap({ configTrees: { '/x': 'walked' } })).join()).toMatch(/collected, refused or limit/);
  });
});

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

  it('rejects mistyped commandOutputs entries (checks read them as text)', () => {
    const ok = { stdout: 'x', stderr: '', exitCode: 0 };
    expect(validateSnapshot(snap({ commandOutputs: { a: ok } }))).toEqual([]);
    expect(validateSnapshot(snap({ commandOutputs: { a: ok, b: { stdout: 5, stderr: [1], exitCode: '0' }, c: 'x' } })))
      .toContain('2 commandOutputs entries are not {stdout, stderr, exitCode} objects (text, text, integer)');
    expect(validateSnapshot(snap({ commandOutputs: { a: { stdout: '', stderr: '' } } })))
      .toContain('1 commandOutputs entry is not {stdout, stderr, exitCode} objects (text, text, integer)');
  });

  it('rejects malformed file entries and oversized content', () => {
    expect(validateSnapshot(snap({ files: { '/a': 'x', '/b': { content: 5 } } })))
      .toContain('2 file entries are not {content, mode, exists} objects');
    const big = 'a'.repeat(MAX_SNAPSHOT_FILE_CONTENT_CHARS + 1);
    const errors = validateSnapshot(snap({ files: { '/big': { content: big, mode: 0o600, exists: true } } }));
    expect(errors.some(e => e.includes("per-file limit"))).toBe(true);
  });
});

describe('validateSnapshot: skill-file heads', () => {
  it('accepts a head that runs to a PE header at e_lfanew, not more than 1 MiB of one', () => {
    const entry = (bytes: number) => ({ '/home/u/.claude/skills/x/a.exe': { exists: true, mode: 0o755, contentOmitted: true, omitted: 'size', head: Buffer.alloc(bytes).toString('base64') } });
    expect(validateSnapshot(snap({ files: entry(0x2004) }))).toEqual([]);
    expect(validateSnapshot(snap({ files: entry((1 << 20) + 4) }))).toEqual([]);
    expect(validateSnapshot(snap({ files: entry((1 << 20) + 64) })).some(e => e.includes('not {content, mode, exists}'))).toBe(true);
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

  it('neutralizes the probe version and timestamp it prints', async () => {
    const path = join(dir, 'esc.json');
    await writeFile(path, JSON.stringify(snap({ probeVersion: '1.4.1\u001b[2J', timestamp: 't‮' })));
    const s = await loadSnapshotFile(path);
    expect(s.probeVersion).toBe('1.4.1\\x1b[2J');
    expect(s.timestamp).toBe('t\\u202e');
  });

  it('tidies a trailing or doubled slash in the home directory', async () => {
    const path = join(dir, 'home.json');
    await writeFile(path, JSON.stringify(snap({ homedir: '/home//u/' })));
    expect((await loadSnapshotFile(path)).homedir).toBe('/home/u');
  });

  it('rejects a home directory that is / or has . or .. segments', () => {
    expect(validateSnapshot(snap({ homedir: '/' }))).toContain('Invalid homedir field: is the filesystem root');
    expect(validateSnapshot(snap({ homedir: '//' }))).toContain('Invalid homedir field: is the filesystem root');
    expect(validateSnapshot(snap({ homedir: '/home/x/../u' }))).toContain('Invalid homedir field: has "." or ".." segments');
    expect(validateSnapshot(snap({ homedir: '/home/u/../../../..' }))).toContain('Invalid homedir field: has "." or ".." segments');
    expect(validateSnapshot(snap({ homedir: '/home/./u' }))).toContain('Invalid homedir field: has "." or ".." segments');
  });

  it('says a string version is not the number 1', () => {
    expect(validateSnapshot(snap({ version: '1' }))).toContain('Unsupported snapshot version: "1" (expected the number 1)');
  });

  it('error lines escape control characters quoted from the file', async () => {
    const path = join(dir, 'ctrl.json');
    await writeFile(path, JSON.stringify(snap({ platform: 'darwin\u001b]0;T\u0007\u001b[2J' })));
    const err = await loadSnapshotFile(path).catch(e => e);
    expect(err).toBeInstanceOf(SnapshotLoadError);
    const text = snapshotErrorLines(err).join('\n');
    expect(text).toContain('darwin\\x1b]0;T\\x07\\x1b[2J');
    expect(text).not.toMatch(/[\u0000-\u0008\u000b-\u001f]/);

    const nul = join(dir, 'nul.json');
    await writeFile(nul, '{"version": 1,\u0000\u001b[2J}');
    const parseErr = await loadSnapshotFile(nul).catch(e => e);
    expect(snapshotErrorLines(parseErr).join('\n')).not.toMatch(/[\u0000-\u0008\u000b-\u001f]/);
  });

  it('reads only a regular file: a FIFO or a device is refused, not waited on or read', async () => {
    const { execFileSync } = await import('node:child_process');
    const fifo = join(dir, 'fifo.json');
    execFileSync('mkfifo', [fifo]);
    await expect(loadSnapshotFile(fifo)).rejects.toThrow(/not a regular file/);
    await expect(loadSnapshotFile('/dev/zero')).rejects.toThrow(/not a regular file/);
    await expect(loadSnapshotFile(dir)).rejects.toThrow(/not a regular file/);
  });
});

describe('validateSnapshot: platform, env and symlinks', () => {
  it('accepts only Node platform names', () => {
    expect(validateSnapshot(snap({ platform: 'darwin' }))).toEqual([]);
    expect(validateSnapshot(snap({ platform: 'linux\u001b[2J' })).some(e => e.startsWith('Unknown platform'))).toBe(true);
  });

  it('requires string env values and symlink targets', () => {
    expect(validateSnapshot(snap({ env: { A: 1 } }))).toContain('Invalid env field (string values expected)');
    expect(validateSnapshot(snap({ symlinks: { '/a': { x: 1 } } }))).toContain('Invalid symlinks field (link targets expected)');
    expect(validateSnapshot(snap({ symlinks: { '/a': '/b' } }))).toEqual([]);
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
