import { describe, it, expect } from 'vitest';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';
import { decodeWindsurfUserSettings } from '../adapters/windsurf-user-settings.js';

function makeSnapshot(overrides: Partial<ProbeSnapshot> = {}): ProbeSnapshot {
  return {
    version: 1,
    hostname: 'test-host',
    platform: 'linux',
    homedir: '/home/testuser',
    timestamp: '2026-03-20T10:00:00Z',
    privilege: {
      uid: 1000,
      username: 'testuser',
      isRoot: false,
      sudoAvailable: false,
      escalated: false,
      scannedUsers: ['testuser'],
      skippedPaths: [],
    },
    files: {},
    directories: {},
    commandOutputs: {},
    env: {},
    ...overrides,
  };
}

describe('SnapshotFSProvider', () => {
  // ---------------------------------------------------------------------------
  // readFile
  // ---------------------------------------------------------------------------
  describe('readFile', () => {
    it('returns content for existing file', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/etc/config.json': { content: '{"key":"value"}', mode: 0o644, exists: true },
          },
        }),
      );
      const content = await provider.readFile('/etc/config.json');
      expect(content).toBe('{"key":"value"}');
    });

    it('throws ENOENT for missing file', async () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      await expect(provider.readFile('/nonexistent')).rejects.toThrow('ENOENT');
    });

    it('throws ENOENT for file with exists: false', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/etc/missing.json': { content: '', mode: 0o644, exists: false },
          },
        }),
      );
      await expect(provider.readFile('/etc/missing.json')).rejects.toThrow('ENOENT');
    });
  });

  // ---------------------------------------------------------------------------
  // readdir
  // ---------------------------------------------------------------------------
  describe('readdir', () => {
    it('returns directory listing from snapshot', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          directories: {
            '/etc': ['config.json', 'hosts'],
          },
        }),
      );
      const entries = await provider.readdir('/etc');
      expect(entries).toEqual(['config.json', 'hosts']);
    });

    it('derives listing from collected file paths when directory not explicitly listed', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/app/src/index.ts': { content: '', mode: 0o644, exists: true },
            '/app/src/utils.ts': { content: '', mode: 0o644, exists: true },
            '/app/package.json': { content: '', mode: 0o644, exists: true },
          },
        }),
      );
      const entries = await provider.readdir('/app');
      expect(entries).toContain('src');
      expect(entries).toContain('package.json');
    });

    it('leaves files the probe did not find out of a derived listing', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/root/.config/systemd/user/agent.service': { content: '', mode: 0, exists: false },
            '/root/.config/systemd/user/other.service': { content: '', mode: 0, exists: false },
          },
        }),
      );
      await expect(provider.readdir('/root/.config/systemd/user')).rejects.toThrow('ENOENT');
      expect(await provider.access('/root/.config/systemd/user')).toBe(false);
    });

    it('throws ENOENT for uncollected directory', async () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      await expect(provider.readdir('/nowhere')).rejects.toThrow('ENOENT');
    });

    it('strips trailing slash from dir entry names produced by the Go probe', async () => {
      // The Go probe appends '/' to directory entries (collector.go:217). Names
      // must come back clean so callers can path.join() without producing '//'.
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          directories: {
            '/home/u/.gemini/tmp': ['alice/', 'gemini-testing/', 'README.md'],
          },
        }),
      );
      const entries = await provider.readdir('/home/u/.gemini/tmp');
      expect(entries).toEqual(['alice', 'gemini-testing', 'README.md']);
    });
  });

  // ---------------------------------------------------------------------------
  // readdirEntries
  // ---------------------------------------------------------------------------
  describe('readdirEntries', () => {
    it('returns DirentInfo with correct isFile/isDirectory', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/app/index.ts': { content: 'code', mode: 0o644, exists: true },
          },
          directories: {
            '/app': ['index.ts', 'lib'],
            '/app/lib': ['helper.ts'],
          },
        }),
      );
      const entries = await provider.readdirEntries('/app');
      const fileEntry = entries.find(e => e.name === 'index.ts');
      const dirEntry = entries.find(e => e.name === 'lib');

      expect(fileEntry).toBeDefined();
      expect(fileEntry!.isFile).toBe(true);
      expect(fileEntry!.isDirectory).toBe(false);

      expect(dirEntry).toBeDefined();
      expect(dirEntry!.isDirectory).toBe(true);
      expect(dirEntry!.isFile).toBe(false);
    });

    it('supports recursive option', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/app/index.ts': { content: 'a', mode: 0o644, exists: true },
            '/app/lib/helper.ts': { content: 'b', mode: 0o644, exists: true },
          },
        }),
      );
      const entries = await provider.readdirEntries('/app', { recursive: true });
      expect(entries.length).toBe(2);
      const names = entries.map(e => e.name);
      expect(names).toContain('index.ts');
      expect(names).toContain('helper.ts');
      // All entries from recursive listing should be files
      expect(entries.every(e => e.isFile)).toBe(true);
    });

    it('returns parentPath', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/app/lib/helper.ts': { content: '', mode: 0o644, exists: true },
          },
        }),
      );
      const entries = await provider.readdirEntries('/app', { recursive: true });
      const helper = entries.find(e => e.name === 'helper.ts');
      expect(helper).toBeDefined();
      expect(helper!.parentPath).toBe('/app/lib');
    });
  });

  // ---------------------------------------------------------------------------
  // access
  // ---------------------------------------------------------------------------
  describe('access', () => {
    it('returns true for existing file', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/etc/config.json': { content: '{}', mode: 0o644, exists: true },
          },
        }),
      );
      expect(await provider.access('/etc/config.json')).toBe(true);
    });

    it('returns true for existing directory', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          directories: { '/etc': ['hosts'] },
        }),
      );
      expect(await provider.access('/etc')).toBe(true);
    });

    it('returns false for uncollected path', async () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      expect(await provider.access('/nonexistent')).toBe(false);
    });

    it('returns true for path that has children (implicit directory)', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/app/src/index.ts': { content: '', mode: 0o644, exists: true },
          },
        }),
      );
      // /app/src is not explicitly in directories, but has a child file
      expect(await provider.access('/app/src')).toBe(true);
      // /app is also an implicit parent
      expect(await provider.access('/app')).toBe(true);
    });

    it('returns false for directory keys with null listings (failed probe)', async () => {
      // Older probe versions inserted a key with null when os.ReadDir failed
      // because the dir didn't exist; access() must not treat those as present.
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/home/u/.lyrie/.env': { content: '', mode: 0o600, exists: false },
            '/home/u/.lyrie/pairing.json': { content: '', mode: 0o600, exists: false },
          },
          directories: {
            '/home/u/.lyrie': null as unknown as string[],
            '/home/u/.lyrie/memory': null as unknown as string[],
            '/home/u/.lyrie/migrations': null as unknown as string[],
          },
        }),
      );
      expect(await provider.access('/home/u/.lyrie')).toBe(false);
      expect(await provider.access('/home/u/.lyrie/memory')).toBe(false);
      expect(await provider.access('/home/u/.lyrie/migrations')).toBe(false);
      expect(await provider.access('/home/u/.lyrie/pairing.json')).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // stat
  // ---------------------------------------------------------------------------
  describe('stat', () => {
    it('returns mode for existing file', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/etc/config.json': { content: '{}', mode: 0o600, exists: true },
          },
        }),
      );
      const st = await provider.stat('/etc/config.json');
      expect(st.mode).toBe(0o600);
    });

    it('isFile() returns true and isDirectory() returns false for files', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/etc/config.json': { content: '{}', mode: 0o644, exists: true },
          },
        }),
      );
      const st = await provider.stat('/etc/config.json');
      expect(st.isFile()).toBe(true);
      expect(st.isDirectory()).toBe(false);
    });

    it('returns mode 0o755 for directories', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          directories: { '/etc': ['hosts'] },
        }),
      );
      const st = await provider.stat('/etc');
      expect(st.mode).toBe(0o755);
      expect(st.isDirectory()).toBe(true);
      expect(st.isFile()).toBe(false);
    });

    it('throws for missing path', async () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      await expect(provider.stat('/nonexistent')).rejects.toThrow('ENOENT');
    });
  });

  // ---------------------------------------------------------------------------
  // realpath
  // ---------------------------------------------------------------------------
  describe('realpath', () => {
    it('returns path as-is for existing path', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          files: {
            '/etc/config.json': { content: '{}', mode: 0o644, exists: true },
          },
        }),
      );
      expect(await provider.realpath('/etc/config.json')).toBe('/etc/config.json');
    });

    it('throws for missing path', async () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      await expect(provider.realpath('/nonexistent')).rejects.toThrow('ENOENT');
    });
  });

  // ---------------------------------------------------------------------------
  // exec / execSync
  // ---------------------------------------------------------------------------
  describe('exec', () => {
    it('returns stdout for successful command', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'openclaw --version': { stdout: 'v1.2.3\n', stderr: '', exitCode: 0 },
          },
        }),
      );
      const result = await provider.exec('openclaw', ['--version']);
      expect(result.stdout).toBe('v1.2.3\n');
      expect(result.exitCode).toBe(0);
    });

    it('returns error result for missing command', async () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      const result = await provider.exec('unknown', ['--flag']);
      expect(result.exitCode).toBe(127);
      expect(result.stderr).toContain('not collected');
    });

    it('matches commands by key format "cmd arg1 arg2"', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'netstat -tlnp': { stdout: 'tcp 0.0.0.0:8080\n', stderr: '', exitCode: 0 },
          },
        }),
      );
      const result = await provider.exec('netstat', ['-tlnp']);
      expect(result.stdout).toBe('tcp 0.0.0.0:8080\n');
      expect(result.exitCode).toBe(0);
    });

    it('resolves full-path binary against snapshot id keyed by basename', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'codex-version': { stdout: 'codex 0.41.0\n', stderr: '', exitCode: 0 },
          },
        }),
      );
      const result = await provider.exec('/usr/local/bin/codex', ['--version']);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('0.41.0');
    });

    it('translates `which <bin>` into the <bin>-which snapshot entry', async () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'openclaw-which': { stdout: '/usr/local/bin/openclaw\n', stderr: '', exitCode: 0 },
          },
        }),
      );
      const result = await provider.exec('which', ['openclaw']);
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe('/usr/local/bin/openclaw');
    });
  });

  describe('execSync', () => {
    it('returns stdout for successful command', () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'openclaw --version': { stdout: 'v1.2.3\n', stderr: '', exitCode: 0 },
          },
        }),
      );
      const stdout = provider.execSync('openclaw', ['--version']);
      expect(stdout).toBe('v1.2.3\n');
    });

    it('throws for failed command (non-zero exit)', () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'bad-cmd run': { stdout: '', stderr: 'error occurred', exitCode: 1 },
          },
        }),
      );
      expect(() => provider.execSync('bad-cmd', ['run'])).toThrow('Command failed (exit 1)');
    });

    it('throws for missing command', () => {
      const provider = new SnapshotFSProvider(makeSnapshot());
      expect(() => provider.execSync('unknown', ['--flag'])).toThrow('not collected');
    });

    it('returns version output when called with full binary path', () => {
      const provider = new SnapshotFSProvider(
        makeSnapshot({
          commandOutputs: {
            'claude-version': { stdout: '1.0.66 (Claude Code)\n', stderr: '', exitCode: 0 },
          },
        }),
      );
      const stdout = provider.execSync('/usr/local/bin/claude', ['--version']);
      expect(stdout).toContain('1.0.66');
    });
  });

  // ---------------------------------------------------------------------------
  // homedir
  // ---------------------------------------------------------------------------
  describe('homedir', () => {
    it('returns snapshot homedir', () => {
      const provider = new SnapshotFSProvider(makeSnapshot({ homedir: '/home/alice' }));
      expect(provider.homedir()).toBe('/home/alice');
    });
  });

  // ---------------------------------------------------------------------------
  // platform
  // ---------------------------------------------------------------------------
  describe('platform', () => {
    it('returns snapshot platform', () => {
      const provider = new SnapshotFSProvider(makeSnapshot({ platform: 'darwin' }));
      expect(provider.platform).toBe('darwin');
    });
  });

  // ---------------------------------------------------------------------------
  // hostname / privilege getters
  // ---------------------------------------------------------------------------
  describe('hostname', () => {
    it('returns correct hostname', () => {
      const provider = new SnapshotFSProvider(makeSnapshot({ hostname: 'prod-server-01' }));
      expect(provider.hostname()).toBe('prod-server-01');
    });
  });

  describe('privilege', () => {
    it('returns correct privilege info', () => {
      const privilege = {
        uid: 0,
        username: 'root',
        isRoot: true,
        sudoAvailable: true,
        escalated: true,
        scannedUsers: ['root', 'alice'],
        skippedPaths: ['/home/bob'],
      };
      const provider = new SnapshotFSProvider(makeSnapshot({ privilege }));
      expect(provider.privilege.isRoot).toBe(true);
      expect(provider.privilege.username).toBe('root');
      expect(provider.privilege.uid).toBe(0);
      expect(provider.privilege.scannedUsers).toEqual(['root', 'alice']);
      expect(provider.privilege.skippedPaths).toEqual(['/home/bob']);
    });
  });
});

// Remote-scan parity fixes found by the 2026-09-25 deep test (Mac/Linux over SSH).
describe('SnapshotFSProvider — probe ≥ 1.0.0 fields', () => {
  it('treats omitted content as unreadable, not empty', async () => {
    const provider = new SnapshotFSProvider(makeSnapshot({
      files: { '/home/testuser/.codex/sessions/a.jsonl': { content: '', mode: 0o600, exists: true, contentOmitted: true } },
    }));
    await expect(provider.readFile('/home/testuser/.codex/sessions/a.jsonl')).rejects.toThrow('content not collected');
    expect(await provider.access('/home/testuser/.codex/sessions/a.jsonl')).toBe(true);
  });

  it('keeps directory-ness from the probe listing (OpenClaw agents/<name>/)', async () => {
    const provider = new SnapshotFSProvider(makeSnapshot({
      directories: { '/home/testuser/.openclaw/agents': ['main/', 'skill-creator/', 'notes.txt'] },
    }));
    const entries = await provider.readdirEntries('/home/testuser/.openclaw/agents');
    expect(entries.filter(e => e.isDirectory).map(e => e.name)).toEqual(['main', 'skill-creator']);
    expect(entries.find(e => e.name === 'notes.txt')?.isDirectory).toBe(false);
  });

  it('answers directory permissions from recorded modes and refuses to guess otherwise', async () => {
    const provider = new SnapshotFSProvider(makeSnapshot({
      directories: { '/home/testuser/.copilot': ['config.json'], '/home/testuser/.other': [] },
      directoryModes: { '/home/testuser/.copilot': 0o700 },
    }));
    const known = await provider.permissions('/home/testuser/.copilot');
    expect(known).not.toBe('unsupported');
    expect(known !== 'unsupported' && known.octal).toBe('700');
    expect(await provider.permissions('/home/testuser/.other')).toBe('unsupported');
    expect((await provider.stat('/home/testuser/.copilot')).mode).toBe(0o700);
  });
});


describe('SnapshotFSProvider — symlinks (probe ≥ 1.0.1)', () => {
  const skills = '/home/testuser/.claude/skills';
  const snapshot = makeSnapshot({
    files: {
      [`${skills}/gstack/browse/src/lib.ts`]: { content: 'x', mode: 0o644, exists: true },
      [`${skills}/browse/SKILL.md`]: { content: '# skill', mode: 0o644, exists: true },
      [`${skills}/browse/own.ts`]: { content: 'y', mode: 0o644, exists: true },
    },
    directories: { [`${skills}/browse`]: ['SKILL.md', 'own.ts', 'src'] },
    symlinks: {
      [`${skills}/browse/SKILL.md`]: `${skills}/gstack/browse/SKILL.md`,
      [`${skills}/browse/src`]: `${skills}/gstack/browse/src`,
    },
  });
  const fs = new SnapshotFSProvider(snapshot);

  it('lists symlinks as links, never as the file or directory they point to', async () => {
    const entries = await fs.readdirEntries(`${skills}/browse`);
    expect(entries.find(e => e.name === 'SKILL.md')).toMatchObject({ isFile: false, isDirectory: false, isSymbolicLink: true });
    expect(entries.find(e => e.name === 'src')).toMatchObject({ isSymbolicLink: true });
    expect(entries.find(e => e.name === 'own.ts')).toMatchObject({ isFile: true });

    const recursive = await fs.readdirEntries(skills, { recursive: true });
    const files = recursive.filter(e => e.isFile).map(e => `${e.parentPath}/${e.name}`);
    expect(files.sort()).toEqual([`${skills}/browse/own.ts`, `${skills}/gstack/browse/src/lib.ts`]);
    expect(recursive.filter(e => e.isSymbolicLink).map(e => e.name).sort()).toEqual(['SKILL.md', 'src']);
  });

  it('answers readlink from recorded targets', async () => {
    expect(await fs.readlink(`${skills}/browse/src`)).toBe(`${skills}/gstack/browse/src`);
    await expect(fs.readlink(`${skills}/browse/own.ts`)).rejects.toThrow();
  });

  it('keeps old snapshots (no symlinks field) unchanged', async () => {
    const old = new SnapshotFSProvider(makeSnapshot({ files: { [`${skills}/a/x.ts`]: { content: 'x', mode: 0o644, exists: true } } }));
    expect((await old.readdirEntries(skills, { recursive: true }))[0]).toMatchObject({ isFile: true });
  });

  describe('binary files (base64 transport, probe >= 1.0.1)', () => {
    const raw = new Uint8Array([0x0a, 0x05, 0x74, 0x75, 0x72, 0x62, 0x6f, 0xff, 0xfe, 0x00, 0x80]);
    const fs = new SnapshotFSProvider(makeSnapshot({
      files: {
        '/b.bin': { content: Buffer.from(raw).toString('base64'), mode: 0o644, exists: true, encoding: 'base64' },
        '/t.txt': { content: 'héllo', mode: 0o644, exists: true },
      },
    }));

    it('returns the exact bytes of a base64 entry', async () => {
      expect(Buffer.from(await fs.readBytes('/b.bin')).equals(Buffer.from(raw))).toBe(true);
    });

    it('decodes base64 entries in readFile like a local utf-8 read', async () => {
      expect(await fs.readFile('/b.bin')).toBe(Buffer.from(raw).toString('utf-8'));
    });

    it('leaves plain text entries untouched', async () => {
      expect(await fs.readFile('/t.txt')).toBe('héllo');
      expect(Buffer.from(await fs.readBytes('/t.txt')).toString('utf-8')).toBe('héllo');
    });

    it('lets a remote scan decode Windsurf 3.x user_settings.pb', async () => {
      // field 52: a non-UTF-8 blob (the model catalogue); field 27 = 3: Turbo
      const pb = Buffer.from([0x08, 0x01, 0xa2, 0x03, 0x04, 0xff, 0xfe, 0xc0, 0x80, 0xd8, 0x01, 0x03]);
      const snap = new SnapshotFSProvider(makeSnapshot({
        files: { '/s.pb': { content: pb.toString('base64'), mode: 0o644, exists: true, encoding: 'base64' } },
      }));
      expect(decodeWindsurfUserSettings(await snap.readBytes('/s.pb'))?.autoExecutionPolicy).toBe('turbo');
      // The old text transport mangled the same bytes beyond decoding
      const legacy = new SnapshotFSProvider(makeSnapshot({
        files: { '/s.pb': { content: pb.toString('utf-8'), mode: 0o644, exists: true } },
      }));
      expect(decodeWindsurfUserSettings(await legacy.readBytes('/s.pb'))?.autoExecutionPolicy).not.toBe('turbo');
    });
  });
});

