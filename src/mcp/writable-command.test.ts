import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { CheckModule, ParsedConfig, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { FileEntry, ProbeSnapshot } from '../core/snapshot-types.js';
import { interpreterScripts, worldWritableCommandPath, writableLaunchText, type WritableCommandPath } from './writable-command.js';
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
    // realpath: macOS tmpdir is under the /var → /private/var link. Under
    // /tmp, opened up: other users must reach the tree (macOS's per-user
    // tmpdir is 700, which mitigates every finding beneath it)
    root = await realpath(await mkdtemp(join('/tmp', 'vaso-wwdir-')));
    await chmod(root, 0o755);
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
   * A missing path (or a dangling link's target): its missing directories
   * recorded as absent and the existing ones above recorded — unless
   * `oldProbe` (1.4.1 and the dt24 build record nothing there).
   */
  async function snapshotOf(paths: string[], opts: {
    special?: boolean; owners?: Record<string, number>; links?: Record<string, string>;
    linkOwners?: Record<string, number>; oldProbe?: boolean;
  } = {}): Promise<SnapshotFSProvider> {
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
    const recordAbsent = async (p: string) => {
      for (let d = dirname(p); ; d = dirname(d)) {
        const there = await stat(d).then(() => true, () => false);
        if (there) return recordDirs(join(d, 'x'));
        files[d] = { content: '', mode: 0, exists: false };
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
        if (opts.oldProbe) continue;
        await recordAbsent(p);
        const target = opts.links?.[p];
        if (target) await recordAbsent(target);
      }
    }
    return new SnapshotFSProvider({
      version: 1, hostname: 'box', platform: process.platform === 'darwin' ? 'darwin' : 'linux', homedir: root, timestamp: 't',
      privilege: { uid, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files, directoryModes, owners, symlinks: opts.links ?? {},
      linkOwners: Object.fromEntries(Object.entries(opts.linkOwners ?? {}).map(([k, v]) => [k, [v, 0]])),
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

    it('from a snapshot whose probe drops the sticky bit: root\'s shared directory is not verified, a user\'s is taken as not sticky', async () => {
      const cmd = await put('shared/srv');
      expect(await worldWritableCommandPath(await snapshotOf([cmd], { owners: { [dir]: 0 } }), cmd)).toBe('uncollected');
      expect(await worldWritableCommandPath(await snapshotOf([cmd]), cmd)).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '777' });
    });

    it('still flags a command that does not exist yet (anyone can plant it), printing the sticky bit', async () => {
      const cmd = join(dir, 'not-yet');
      expect(await worldWritableCommandPath(local, cmd)).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '1777', missing: true });
    });

    it('still flags a command another user owns', async () => {
      const cmd = await put('shared/srv');
      const remote = await snapshotOf([cmd], { special: true, owners: { [cmd]: uid + 4242 } });
      expect(await worldWritableCommandPath(remote, cmd)).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '1777', foreignOwner: true, owner: uid + 4242, entry: cmd });
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

  describe('a command that does not exist yet', () => {
    beforeEach(async () => {
      await mkdir(join(root, 'open'));
      await chmod(join(root, 'open'), 0o777);
    });

    it('is plantable in a world-writable directory, locally and from a snapshot alike', async () => {
      for (const cmd of [join(root, 'open', 'missing'), join(root, 'open', 'nodir', 'x', 'cmd')]) {
        const want = { kind: 'directory', path: join(root, 'open'), octal: '777', mode: '777', missing: true };
        expect(await worldWritableCommandPath(local, cmd)).toEqual(want);
        expect(await worldWritableCommandPath(await snapshotOf([cmd], { special: true }), cmd)).toEqual(want);
      }
    });

    it('passes in a safe directory, locally and from a snapshot', async () => {
      const cmd = join(root, 'safe', 'sub', 'missing');
      await mkdir(join(root, 'safe'));
      expect(await worldWritableCommandPath(local, cmd)).toBeUndefined();
      expect(await worldWritableCommandPath(await snapshotOf([cmd], { special: true }), cmd)).toBeUndefined();
    });

    it('is not verified from a probe that recorded nothing above it', async () => {
      const cmd = join(root, 'open', 'nodir', 'cmd');
      expect(await worldWritableCommandPath(await snapshotOf([cmd], { special: true, oldProbe: true }), cmd)).toBe('uncollected');
    });

    it('a dangling link into a world-writable directory: its target can be planted', async () => {
      await mkdir(join(root, 'safe'));
      const link = join(root, 'safe', 'dang');
      const target = join(root, 'open', 'notthere');
      await symlink(target, link);
      const want = { kind: 'directory', path: join(root, 'open'), octal: '777', mode: '777', via: target };
      expect(await worldWritableCommandPath(local, link)).toEqual(want);
      expect(await worldWritableCommandPath(await snapshotOf([link], { special: true, links: { [link]: target } }), link)).toEqual(want);
    });
  });

  describe('a sticky directory owned by another user', () => {
    it('does not protect what is in it: its owner can rename it', async () => {
      const dir = join(root, 'bobst');
      await mkdir(dir);
      await chmod(dir, 0o1777);
      const cmd = await put('bobst/srv');
      const remote = await snapshotOf([cmd], { special: true, owners: { [dir]: uid + 7 } });
      const got = await worldWritableCommandPath(remote, cmd);
      expect(got).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '1777', foreignDirOwner: true, owner: uid + 7 });
      const { detail } = writableLaunchText({ role: 'command', path: cmd, writable: got as WritableCommandPath });
      expect(detail).toBe(`MCP server command: its directory ${dir} is world-writable and sticky, but the directory belongs to another user (uid ${uid + 7}) — that user (or root) can swap ${cmd} before launch`);
    });

    it('a link is judged by its own owner, not its target\'s', async () => {
      const dir = join(root, 'shared');
      await mkdir(dir);
      await chmod(dir, 0o1777);
      const real = await put('safe/real');
      const link = join(dir, 'srv');
      await symlink(real, link);
      // Another user's link to the user's own file: that user can swap the link
      const remote = await snapshotOf([link], { special: true, links: { [link]: real }, linkOwners: { [link]: uid + 9 } });
      const got = await worldWritableCommandPath(remote, link);
      expect(got).toEqual({ kind: 'directory', path: dir, octal: '777', mode: '1777', foreignOwner: true, owner: uid + 9, entry: link });
      expect(writableLaunchText({ role: 'command', path: link, writable: got as WritableCommandPath }).detail)
        .toContain(`sticky, but it belongs to another user (uid ${uid + 9}) — that user (or root) can swap ${link}`);
      // The user's own link: protected, locally and remotely; a probe that didn't record its owner: not verified
      expect(await worldWritableCommandPath(local, link)).toBeUndefined();
      expect(await worldWritableCommandPath(await snapshotOf([link], { special: true, links: { [link]: real }, linkOwners: { [link]: uid } }), link)).toBeUndefined();
      expect(await worldWritableCommandPath(await snapshotOf([link], { special: true, links: { [link]: real } }), link)).toBe('uncollected');
    });
  });

  it('a world-writable directory other users can\'t reach is a mitigated finding', async () => {
    await mkdir(join(root, 'priv'));
    await mkdir(join(root, 'priv', 'open'));
    await chmod(join(root, 'priv', 'open'), 0o777);
    await chmod(join(root, 'priv'), 0o700);
    const cmd = await put('priv/open/srv');
    const want = { kind: 'directory', path: join(root, 'priv', 'open'), octal: '777', mode: '777', barrier: `${join(root, 'priv')} (700)` };
    expect(await worldWritableCommandPath(local, cmd)).toEqual(want);
    expect(await worldWritableCommandPath(await snapshotOf([cmd], { special: true }), cmd)).toEqual(want);
    for (const [check, format, name, data] of cases) {
      const { local: l, remote: r } = await runBoth(check, format, name, data(cmd, []), await snapshotOf([cmd, join(root, name)], { special: true }));
      expect(l.passed, check.id).toBe(false);
      expect(l.severity, check.id).toBe('info');
      expect(l.evidence![0].mitigated, check.id).toBe(true);
      expect(l.evidence![0].detail, check.id).toContain(`mitigated: not reachable by other users, parent ${join(root, 'priv')} (700) blocks traversal`);
      expect(r.evidence).toEqual(l.evidence);
    }
    await chmod(join(root, 'priv'), 0o755);
  });

  it('a 750 home blocks only when its group is the owner\'s private group', async () => {
    // macOS: /Users/u drwxr-x--- u:staff — staff (gid 20) is every user's
    // primary group, so the others still traverse it and swap the command.
    // Linux: /home/u 750 u:u — a private group, nobody else gets in.
    const host = (platform: 'darwin' | 'linux', home: string, gid: number, privateGroups?: Record<string, number>) => {
      const open = `${home}/open`;
      return new SnapshotFSProvider({
        version: 1, hostname: 'h', platform, homedir: home, timestamp: 't',
        privilege: { uid: 501, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
        files: {
          [`${open}/srv`]: { content: '', mode: 0o755, exists: true, contentOmitted: true, omitted: 'metadata' },
          [`${home}/ww`]: { content: '', mode: 0o777, exists: true, contentOmitted: true, omitted: 'metadata' },
        },
        directoryModes: { '/': 0o755, [dirname(home)]: 0o755, [home]: 0o750, [open]: 0o777 },
        owners: {
          '/': [0, 0], [dirname(home)]: [0, 0], [home]: [501, gid], [open]: [501, gid],
          [`${open}/srv`]: [501, gid], [`${home}/ww`]: [501, gid],
        },
        symlinks: {}, directories: {}, commandOutputs: {}, env: {}, specialModeBits: true,
        ...(privateGroups ? { privateGroups } : {}),
      } as ProbeSnapshot);
    };
    const mac = host('darwin', '/Users/u', 20);
    expect(await worldWritableCommandPath(mac, '/Users/u/open/srv')).toEqual({ kind: 'directory', path: '/Users/u/open', octal: '777', mode: '777' });
    expect(await worldWritableCommandPath(mac, '/Users/u/ww')).toEqual({ kind: 'binary', path: '/Users/u/ww', octal: '777', mode: '777' });
    const linux = host('linux', '/home/u', 1000, { 1000: 501 });
    expect(await worldWritableCommandPath(linux, '/home/u/open/srv'))
      .toEqual({ kind: 'directory', path: '/home/u/open', octal: '777', mode: '777', barrier: '/home/u (750)' });
    expect(await worldWritableCommandPath(linux, '/home/u/ww')).toEqual({ kind: 'binary', path: '/home/u/ww', octal: '777', mode: '777', barrier: '/home/u (750)' });
    // A shared group on Linux (not anyone's private group) still reaches it
    const shared = host('linux', '/home/u', 100, { 1000: 501 });
    expect(await worldWritableCommandPath(shared, '/home/u/open/srv')).toEqual({ kind: 'directory', path: '/home/u/open', octal: '777', mode: '777' });
  });

  it('a 750 parent with a shared group is no barrier locally either', async () => {
    // New directories under /tmp take its group (wheel on macOS) — not the
    // owner's private group; on Linux they take the user's primary group,
    // which is private on most distributions (then it does block).
    await mkdir(join(root, 'home', 'open'), { recursive: true });
    await chmod(join(root, 'home', 'open'), 0o777);
    await chmod(join(root, 'home'), 0o750);
    const cmd = await put('home/open/srv');
    const { stat } = await import('node:fs/promises');
    const gid = (await stat(join(root, 'home'))).gid;
    const priv = await local.privateGroups();
    const blocks = process.platform === 'linux' && priv.get(gid) === uid;
    const got = await worldWritableCommandPath(local, cmd);
    expect(got).toEqual({ kind: 'directory', path: join(root, 'home', 'open'), octal: '777', mode: '777', ...(blocks ? { barrier: `${join(root, 'home')} (750)` } : {}) });
    await chmod(join(root, 'home'), 0o755);
  });

  it('lists each path not verified once', async () => {
    const script = join(root, 'elsewhere', 's.js');
    const config = join(root, 'c.json');
    await writeFile(config, '{}');
    const data = { mcpServers: { a: { command: 'node', args: [script] }, b: { command: 'node', args: [script] } } };
    const remote = await snapshotOf([]);
    const res = await cd009.run({
      installation: { agent: 'claude-desktop', installDir: root, configFiles: [] },
      configs: [{ raw: '', format: 'json', filePath: config, data }], platform: remote.platform, fs: remote,
    });
    expect(res.message).toBe(`command path(s) ${script} not verified — the remote probe doesn't collect it (checked on local scans)`.replace('command path(s)', 'MCP command path(s)'));
  });

  describe('Hermes commands', () => {
    it('expands a leading ~ and strips spaces, as Hermes does; args are taken as written', async () => {
      await mkdir(join(root, 'tools'));
      await chmod(join(root, 'tools'), 0o777);
      const bin = await put('tools/mcp-bin');
      const home = Object.assign(Object.create(local) as LocalFSProvider, { homedir: () => root });
      for (const command of ['~/tools/mcp-bin', `  ${bin} `]) {
        const config: ParsedConfig = { raw: '', format: 'yaml', filePath: join(root, 'config.yaml'), data: { mcp_servers: { s: { command } } } };
        await writeFile(config.filePath, '');
        const remote = await snapshotOf([bin, config.filePath], { special: true });
        const ctx = (fs: FSProvider): ScanContext => ({ installation: { agent: 'hermes', installDir: root, configFiles: [config] }, configs: [config], platform: fs.platform, fs });
        const l = await hm010.run(ctx(home));
        expect(l.passed, command).toBe(false);
        expect(l.evidence![0].snippet).toBe(`mcp_servers.s.command = ${bin}: ${join(root, 'tools')} (mode 777)`);
        expect((await hm010.run(ctx(remote))).evidence).toEqual(l.evidence);
      }
      // Claude Desktop runs the command as written: a `~` path is no absolute path
      const { local: l } = await runBoth(cd009, 'json', 'c.json', { mcpServers: { s: { command: '~/tools/mcp-bin' } } }, await snapshotOf([]));
      expect(l.passed).toBe(true);
    });

    it('a ${VAR} a snapshot could not expand is not verified', async () => {
      const config: ParsedConfig = { raw: '', format: 'yaml', filePath: join(root, 'config.yaml'), data: { mcp_servers: { s: { command: '${TOOLS}/mcp-bin' } } } };
      const remote = await snapshotOf([]);
      const r = await hm010.run({ installation: { agent: 'hermes', installDir: root, configFiles: [config] }, configs: [config], platform: remote.platform, fs: remote });
      expect(r.message).toContain('${TOOLS}/mcp-bin not verified');
    });
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

  it('skips the values of each interpreter\'s options', () => {
    expect(interpreterScripts('bash', ['-o', 'pipefail', '/x/s.sh'])).toEqual(['/x/s.sh']);
    expect(interpreterScripts('bash', ['-O', 'extglob', '/x/s.sh'])).toEqual(['/x/s.sh']);
    expect(interpreterScripts('bash', ['-eo', 'pipefail', '/x/s.sh'])).toEqual(['/x/s.sh']);
    expect(interpreterScripts('bash', ['--', '/x/s.sh'])).toEqual(['/x/s.sh']);
    expect(interpreterScripts('bash', ['-c', '/x/s.sh --flag'])).toEqual(['/x/s.sh']);
    expect(interpreterScripts('bash', ['-s', '/x/arg'])).toEqual([]);
    expect(interpreterScripts('perl', ['-I', '/safe', '/x/x.pl'])).toEqual(['/x/x.pl']);
    expect(interpreterScripts('perl', ['-I/safe', '/x/x.pl'])).toEqual(['/x/x.pl']);
    expect(interpreterScripts('perl', ['-e', 'print 1', '/x/arg'])).toEqual([]);
    expect(interpreterScripts('ruby', ['-r', '/x/pre.rb', '/x/x.rb'])).toEqual(['/x/pre.rb', '/x/x.rb']);
    expect(interpreterScripts('php', ['-d', 'x=1', '-f', '/x/s.php'])).toEqual(['/x/s.php']);
    expect(interpreterScripts('lua', ['-l', 'socket', '/x/s.lua'])).toEqual(['/x/s.lua']);
    expect(interpreterScripts('java', ['-jar', '/x/s.jar'])).toEqual(['/x/s.jar']);
    expect(interpreterScripts('java', ['-cp', '/x/lib', 'com.x.Main'])).toEqual([]);
    expect(interpreterScripts('/usr/bin/java', ['/x/Main.java'])).toEqual(['/x/Main.java']);
    expect(interpreterScripts('node', ['--require=/x/pre.js', '/x/s.js'])).toEqual(['/x/s.js', '/x/pre.js']);
  });

  it('looks through env to the command it runs', () => {
    expect(interpreterScripts('env', ['FOO=1', 'node', '/x/s.js'])).toEqual(['/x/s.js']);
    expect(interpreterScripts('/usr/bin/env', ['python3', '/x/s.py'])).toEqual(['/x/s.py']);
    expect(interpreterScripts('/usr/bin/env', ['-u', 'X', '-i', '/x/srv', '--port', '1'])).toEqual(['/x/srv']);
    expect(interpreterScripts('/usr/bin/env', ['-S', 'node /x/s.js'])).toEqual(['/x/s.js']);
    expect(interpreterScripts('/usr/bin/env', ['bash', '-c', 'echo hi'])).toEqual([]);
  });
});
