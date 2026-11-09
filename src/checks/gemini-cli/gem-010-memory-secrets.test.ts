import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FSProvider } from '../../core/fs-provider.js';
import type { ScanContext } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../../core/snapshot-fs-provider.js';
import type { ProbeSnapshot } from '../../core/snapshot-types.js';
import { captureConfigLoadErrors } from '../../core/config-loader.js';
import { gem010 } from './gem-010-memory-secrets.js';

const KEY = 'sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const asRoot = process.getuid?.() === 0;

function ctx(installDir: string, fs: FSProvider, profile?: 'project'): ScanContext {
  return { installation: { agent: 'gemini-cli', installDir, configFiles: [], profile }, configs: [], platform: 'linux', fs };
}

function snapshot(home: string, files: ProbeSnapshot['files'], extra: Partial<ProbeSnapshot> = {}): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1, probeVersion: '1.4.1', hostname: 'h', platform: 'linux', homedir: home, timestamp: '',
    privilege: { uid: 501, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files, directories: {}, commandOutputs: {}, env: {}, ...extra,
  } as ProbeSnapshot);
}

describe('GEM-010 project memory index (~/.gemini/tmp/<id>/memory/MEMORY.md)', () => {
  let home: string;
  let gemini: string;
  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), 'gem010-'));
    gemini = join(home, '.gemini');
    await mkdir(join(gemini, 'tmp', 'p1', 'memory'), { recursive: true });
    await mkdir(join(gemini, 'tmp', 'p1', 'chats'), { recursive: true });
  });
  afterEach(async () => {
    await chmod(join(gemini, 'tmp'), 0o755).catch(() => undefined);
    await chmod(join(gemini, 'tmp', 'p1'), 0o755).catch(() => undefined);
    await rm(home, { recursive: true, force: true });
  });

  it('flags a secret in a project memory index, never in chats', async () => {
    await writeFile(join(gemini, 'tmp', 'p1', 'memory', 'MEMORY.md'), `- deploy key ${KEY}\n`);
    const result = await gem010.run(ctx(gemini, new LocalFSProvider()));
    expect(result.passed).toBe(false);
    expect(JSON.stringify(result.evidence)).toContain('memory/MEMORY.md');

    await writeFile(join(gemini, 'tmp', 'p1', 'memory', 'MEMORY.md'), '# notes\n');
    await writeFile(join(gemini, 'tmp', 'p1', 'chats', 'session-1.jsonl'), `{"text":"${KEY}"}\n`);
    expect((await gem010.run(ctx(gemini, new LocalFSProvider()))).passed).toBe(true);
  });

  it('reads the sandbox runtime dir too (~/.cache/.gemini/tmp)', async () => {
    const idx = join(home, '.cache', '.gemini', 'tmp', 'p2', 'memory', 'MEMORY.md');
    await mkdir(join(idx, '..'), { recursive: true });
    await writeFile(idx, `token ${KEY}\n`);
    expect((await gem010.run(ctx(gemini, new LocalFSProvider()))).passed).toBe(false);
  });

  it('a project install has no index of its own', async () => {
    await writeFile(join(gemini, 'tmp', 'p1', 'memory', 'MEMORY.md'), `${KEY}\n`);
    expect((await gem010.run(ctx(gemini, new LocalFSProvider(), 'project'))).passed).toBe(true);
  });

  it.skipIf(asRoot)('an unreadable tmp or project dir is a CONFIG-LOAD, not clean', async () => {
    await chmod(join(gemini, 'tmp'), 0);
    let { loadErrors } = await captureConfigLoadErrors(() => gem010.run(ctx(gemini, new LocalFSProvider())));
    expect(loadErrors.map(e => e.filePath)).toContain(join(gemini, 'tmp'));
    await chmod(join(gemini, 'tmp'), 0o755);
    await chmod(join(gemini, 'tmp', 'p1'), 0);
    ({ loadErrors } = await captureConfigLoadErrors(() => gem010.run(ctx(gemini, new LocalFSProvider()))));
    expect(loadErrors.length).toBeGreaterThan(0);
  });

  it('remote: answers like local, and says when the probe omitted an index', async () => {
    const tmp = join(gemini, 'tmp');
    const idx = join(tmp, 'p1', 'memory', 'MEMORY.md');
    const fs = snapshot(home, { [idx]: { exists: true, mode: 0o644, content: `k ${KEY}\n` } }, {
      directories: { [tmp]: ['p1/'] },
    });
    expect((await gem010.run(ctx(gemini, fs))).passed).toBe(false);

    const omitted = snapshot(home, { [idx]: { exists: true, mode: 0o644, content: '', contentOmitted: true, omitted: 'size' } }, {
      directories: { [tmp]: ['p1/'] },
    });
    const result = await gem010.run(ctx(gemini, omitted));
    expect(result.passed).toBe(true);
    expect(result.message).toContain(`${idx} (omitted: size) not verified`);

    // A denied project dir (probe ≥ 1.4.1 records its mode) → CONFIG-LOAD
    const denied = snapshot(home, {}, { directories: { [tmp]: ['p1/'] }, directoryModes: { [tmp]: 0o755, [join(tmp, 'p1')]: 0 } });
    const { loadErrors } = await captureConfigLoadErrors(() => gem010.run(ctx(gemini, denied)));
    expect(loadErrors.length).toBeGreaterThan(0);
  });
});
