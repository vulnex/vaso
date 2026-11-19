import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { CheckModule, ParsedConfig, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { FileEntry, ProbeSnapshot } from '../core/snapshot-types.js';
import { interpreterScripts, worldWritableCommandPath } from './writable-command.js';
import { hm010 } from '../checks/hermes/hm-010-mcp-server-hardening.js';
import { at007 } from '../checks/atomic-agent/at-007-mcp-server-hardening.js';
import { cd009 } from '../checks/claude-desktop/cd-009-world-writable-command.js';

const posix = process.platform !== 'win32';
const uid = process.getuid?.() ?? 1000;

/**
 * Commands (and scripts) any local user can swap, judged alike locally and
 * from a probe snapshot — which carries each stat'd path's mode and owner,
 * its directories' modes up to the root, and the links it went through.
 */
describe.runIf(posix)('MCP command any local user can replace', () => {
  let root: string;
  const local = new LocalFSProvider();
  beforeEach(async () => {
    // realpath: macOS tmpdir is under the /var → /private/var link
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-wwdir-')));
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  async function put(rel: string, mode = 0o755): Promise<string> {
    const p = join(root, rel);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, '#!/bin/sh\n');
    await chmod(p, mode);
    return p;
  }

  /**
   * The host as a probe would ship it: the given paths stat'd (mode, owner),
   * every directory above root..path recorded, links recorded. With
   * `special`, directory modes carry the sticky bit (probe ≥ specialModeBits).
   */
  async function snapshotOf(paths: string[], opts: { special?: boolean; owners?: Record<string, number>; links?: Record<string, string> } = {}): Promise<SnapshotFSProvider> {
    const files: Record<string, FileEntry> = {};
    const directoryModes: Record<string, number> = {};
    const owners: Record<string, [number, number]> = {};
    const { lstat, stat } = await import('node:fs/promises');
    const recordDirs = async (p: string) => {
      for (let d = dirname(p); ; d = dirname(d)) {
        const s = await stat(d);
        directoryModes[d] = opts.special ? s.mode & 0o7777 : s.mode & 0o777;
        owners[d] = [opts.owners?.[d] ?? s.uid, s.gid];
        if (dirname(d) === d) break;
      }
    };
    for (const p of paths) {
      try {
        const s = await stat(p);
        files[p] = { content: '', mode: s.mode & 0o777, exists: true, contentOmitted: true, omitted: 'metadata' };
        owners[p] = [opts.owners?.[p] ?? s.uid, s.gid];
        await recordDirs(p);
        const l = await lstat(p);
        if (l.isSymbolicLink()) await recordDirs(await realpath(p));
      } catch {
        files[p] = { content: '', mode: 0, exists: false };
      }
    }
    return new SnapshotFSProvider({
      version: 1, hostname: 'box', platform: process.platform === 'darwin' ? 'darwin' : 'linux', homedir: root, timestamp: 't',
      privilege: { uid, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files, directoryModes, owners, symlinks: opts.links ?? {},
      directories: {}, commandOutputs: {}, env: {},
      ...(opts.special ? { specialModeBits: true } : {}),
    } as ProbeSnapshot);
  }

  const cases: Array<[CheckModule, ParsedConfig['format'], string, (c: string, args: string[]) => Record<string, unknown>]> = [
    [hm010, 'yaml', 'config.yaml', (c, args) => ({ mcp_servers: { s: { command: c, args } } })],
    [at007, 'json', 'config.json', (c, args) => ({ mcp: { servers: [{ name: 's', enabled: true, transport: { kind: 'stdio', command: c, args } }] } })],
    [cd009, 'json', 'claude_desktop_config.json', (c, args) => ({ mcpServers: { s: { command: c, args } } })],
  ];

  async function runBoth(check: CheckModule, format: ParsedConfig['format'], name: string, data: Record<string, unknown>, remoteFs: FSProvider) {
    const configPath = join(root, name);
    await writeFile(configPath, '{}');
    const config: ParsedConfig = { raw: '', format, filePath: configPath, data };
    const ctx = (fs: FSProvider): ScanContext => ({
      installation: { agent: check.supportedAgents![0], installDir: root, configFiles: [config] },
      configs: [config], platform: fs.platform, fs,
    });
    return { local: await check.run(ctx(local)), remote: await check.run(ctx(remoteFs)) };
  }

  it('flags a command in a world-writable directory, locally and from a snapshot', async () => {
    await mkdir(join(root, 'open'));
    await chmod(join(root, 'open'), 0o777);
    const cmd = await put('open/mcp-server');
    for (const [check, format, name, data] of cases) {
      const { local: l, remote: r } = await runBoth(check, format, name, data(cmd, []), await snapshotOf([cmd, join(root, name)], { special: true }));
      for (const res of [l, r]) {
        expect(res.passed, check.id).toBe(false);
        expect(res.evidence![0].snippet).toContain(`${join(root, 'open')} (mode 777)`);
      }
      expect(r.evidence).toEqual(l.evidence);
    }
  });

  it('flags a world-writable directory above the command (it can rename the subdirectory)', async () => {
    const cmd = await put('gp/sub/srv');
    await chmod(join(root, 'gp'), 0o777);
    expect(await worldWritableCommandPath(local, cmd)).toEqual({ kind: 'directory', path: join(root, 'gp'), octal: '777', mode: '777' });
    const remote = await snapshotOf([cmd], { special: true });
    expect(await worldWritableCommandPath(remote, cmd)).toEqual(await worldWritableCommandPath(local, cmd));
  });

  it('follows a link to its target in a world-writable directory', async () => {
    await mkdir(join(root, 'open'));
    await chmod(join(root, 'open'), 0o777);
    const real = await put('open/real');
    await mkdir(join(root, 'safe'));
    const link = join(root, 'safe', 'srv');
    await symlink(real, link);
    const want = { kind: 'directory', path: join(root, 'open'), octal: '777', mode: '777', via: real };
    expect(await worldWritableCommandPath(local, link)).toEqual(want);
    const remote = await snapshotOf([link], { special: true, links: { [link]: real } });
    expect(await worldWritableCommandPath(remote, link)).toEqual(want);
  });

  it('flags the script an interpreter runs from a world-writable directory', async () => {
    await mkdir(join(root, 'open'));
    await chmod(join(root, 'open'), 0o777);
    const script = await put('open/server.js', 0o644);
    for (const [check, format, name, data] of cases) {
      const { local: l, remote: r } = await runBoth(check, format, name, data('node', [script]), await snapshotOf([script, join(root, name)], { special: true }));
      expect(l.passed, check.id).toBe(false);
      expect(l.evidence![0].snippet).toContain(`args = ${script}: ${join(root, 'open')} (mode 777)`);
      expect(l.evidence![0].detail).toMatch(/^Script the MCP server runs/);
      expect(r.evidence).toEqual(l.evidence);
    }
  });

  it('a script a snapshot did not stat is not verified, not safe', async () => {
    const script = await put('open/server.js', 0o644);
    const { remote: r } = await runBoth(cd009, 'json', 'c.json', { mcpServers: { s: { command: 'node', args: [script] } } }, await snapshotOf([]));
    expect(r.passed).toBe(true);
    expect(r.message).toContain(`${script} not verified`);
  });

  describe('sticky world-writable directory (1777, like /tmp)', () => {
    let dir: string;
    beforeEach(async () => {
      dir = join(root, 'shared');
      await mkdir(dir);
      await chmod(dir, 0o1777);
    });

    it('protects a command its user owns — locally and from a snapshot that records the sticky bit', async () => {
      const cmd = await put('shared/srv');
      expect(await worldWritableCommandPath(local, cmd)).toBeUndefined();
      expect(await worldWritableCommandPath(await snapshotOf([cmd], { special: true }), cmd)).toBeUndefined();
    });

    it('is not verified from a snapshot whose probe drops the sticky bit', async () => {
      const cmd = await put('shared/srv');
      expect(await worldWritableCommandPath(await snapshotOf([cmd]), cmd)).toBe('uncollected');
    });

    it('still flags a command that does not exist yet (anyone can plant it), printing the sticky bit', async () => {
      const cmd = join(dir, 'not-yet');
      expect(await worldWritableCommandPath(local, cmd)).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '1777', missing: true });
    });

    it('still flags a command another user owns', async () => {
      const cmd = await put('shared/srv');
      const remote = await snapshotOf([cmd], { special: true, owners: { [cmd]: uid + 4242 } });
      expect(await worldWritableCommandPath(remote, cmd)).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '1777', foreignOwner: true });
    });

    it('prints the mode the same way in every check', async () => {
      const cmd = join(dir, 'not-yet');
      for (const [check, format, name, data] of cases) {
        const { local: l } = await runBoth(check, format, name, data(cmd, []), await snapshotOf([]));
        expect(l.evidence![0].snippet, check.id).toContain(`${dir} (mode 1777)`);
        expect(l.evidence![0].detail, check.id).toContain('(sticky)');
      }
    });
  });

  it('reports the binary first, then its directory', async () => {
    await mkdir(join(root, 'open'));
    await chmod(join(root, 'open'), 0o777);
    const cmd = await put('open/mcp-server');
    expect(await worldWritableCommandPath(local, cmd)).toEqual({ kind: 'directory', path: join(root, 'open'), octal: '777', mode: '777' });
    await chmod(cmd, 0o777);
    expect(await worldWritableCommandPath(local, cmd)).toMatchObject({ kind: 'binary', path: cmd });
  });

  it('passes a command nobody else can reach', async () => {
    const cmd = await put('safe/srv');
    expect(await worldWritableCommandPath(local, cmd)).toBeUndefined();
    expect(await worldWritableCommandPath(await snapshotOf([cmd], { special: true }), cmd)).toBeUndefined();
  });
});

describe('interpreterScripts', () => {
  it('names the absolute script an interpreter runs', () => {
    expect(interpreterScripts('node', ['/srv/x/server.js'])).toEqual(['/srv/x/server.js']);
    expect(interpreterScripts('/usr/bin/python3', ['-u', '/srv/x/s.py', '--port', '1'])).toEqual(['/srv/x/s.py']);
    expect(interpreterScripts('node', ['--import', '/srv/x/reg.mjs', '/srv/x/main.js'])).toEqual(['/srv/x/main.js', '/srv/x/reg.mjs']);
    expect(interpreterScripts('bash', ['/srv/x/run.sh'])).toEqual(['/srv/x/run.sh']);
    expect(interpreterScripts('deno', ['run', '-A', '/srv/x/mod.ts'])).toEqual(['/srv/x/mod.ts']);
  });

  it('ignores relative scripts, modules, packages and direct commands', () => {
    expect(interpreterScripts('node', ['server.js'])).toEqual([]);
    expect(interpreterScripts('python3', ['-m', 'pkg.server'])).toEqual([]);
    expect(interpreterScripts('npx', ['-y', '@scope/server@1.0.0'])).toEqual([]);
    expect(interpreterScripts('/opt/bin/srv', ['/data'])).toEqual([]);
    expect(interpreterScripts('bash', ['-c', 'exec x'])).toEqual([]);
  });
});
