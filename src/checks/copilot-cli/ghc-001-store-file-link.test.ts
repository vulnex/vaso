import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../../core/snapshot-fs-provider.js';
import type { ProbeSnapshot } from '../../core/snapshot-types.js';
import type { AgentInstallation, CheckResult, ScanContext } from '../../core/types.js';
import { dedupePermissionFindings } from '../../core/duplicate-findings.js';
import { pol003 } from '../policy/pol-003-session-credentials.js';
import { copilotCliAdapter } from '../../adapters/copilot-cli.js';
import { copilotCliChecks } from './index.js';

const check = copilotCliChecks.find(c => c.id === 'GHC-001')!;

const put = async (path: string, mode: number, content = 'x') => {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await writeFile(path, content);
  await chmod(path, mode);
};

let root: string;
beforeEach(async () => { root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-ghc001f-'))); await chmod(root, 0o755); });
afterEach(async () => { await rm(root, { recursive: true, force: true }); });

function localCtx(installDir: string, home?: string): ScanContext {
  const fs = new LocalFSProvider();
  if (home) fs.homedir = () => home;
  return {
    installation: { agent: 'copilot-cli', installDir, configFiles: [] } as AgentInstallation,
    configs: [], platform: process.platform as ScanContext['platform'], fs,
    credentialPaths: copilotCliAdapter.getCredentialPaths!(installDir),
  };
}

function snapshotCtx(home: string, extra: Pick<ProbeSnapshot, 'files' | 'directories' | 'symlinks' | 'directoryModes'>, installDir = `${home}/.copilot`): ScanContext {
  const fs = new SnapshotFSProvider({
    version: 1, hostname: 'box', platform: 'linux', homedir: home, timestamp: '2026-11-16T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: extra.files, directories: extra.directories, symlinks: extra.symlinks, commandOutputs: {}, env: {},
    directoryModes: { '/': 0o40755, '/home': 0o40755, '/data': 0o40755, [home]: 0o40755, ...extra.directoryModes },
  });
  return {
    installation: { agent: 'copilot-cli', installDir, configFiles: [] } as AgentInstallation,
    configs: [], platform: 'linux', fs,
    credentialPaths: copilotCliAdapter.getCredentialPaths!(installDir),
  };
}

const verdict = (r: CheckResult) => ({ passed: r.passed, severity: r.severity, fixable: r.fixable, files: r.evidence?.map(e => e.file), snippets: r.evidence?.map(e => e.snippet) });

describe('GHC-001: a store folder that is a link to a file', () => {
  it('is a store link into a credential store (warning, not fixable) with its target\'s mode — never "absent"; local and snapshot agree', async () => {
    const home = join(root, 'home');
    const cop = join(home, '.copilot');
    const key = join(home, '.ssh', 'id_rsa');
    await put(key, 0o644);
    await put(join(cop, 'config.json'), 0o600, '{}');
    await symlink(key, join(cop, 'session-state'));
    const local = await check.run(localCtx(cop, home));
    expect(local).toMatchObject({ passed: false, severity: 'warning', fixable: false });
    expect(local.message).toMatch(/1 store link\(s\) point into a sensitive location/);
    expect(local.evidence?.map(e => e.file)).toEqual([join(cop, 'session-state')]);
    expect(local.evidence?.[0].snippet).toBe(`-> ${key} mode 0644`);
    expect(local.evidence?.[0].detail).toMatch(/^session-state\/ itself is a link to the file .*id_rsa \(SSH/);
    await check.fix!(localCtx(cop, home));
    expect((await stat(key)).mode & 0o777).toBe(0o644);

    // As the probe records it: the link and the mode a stat through it answers
    const h = '/home/u';
    const remote = await check.run(snapshotCtx(h, {
      files: {
        [`${h}/.copilot/config.json`]: { content: '{}', mode: 0o100600, exists: true },
        [`${h}/.copilot/session-state`]: { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'metadata' },
      },
      directories: { [`${h}/.copilot`]: ['config.json', 'session-state'] },
      symlinks: { [`${h}/.copilot/session-state`]: `${h}/.ssh/id_rsa` },
      directoryModes: { [`${h}/.copilot`]: 0o40700, [`${h}/.ssh`]: 0o40755 },
    }));
    const local2 = { ...verdict(local), files: [`${h}/.copilot/session-state`], snippets: [`-> ${h}/.ssh/id_rsa mode 0644`] };
    expect(verdict(remote)).toEqual(local2);
  });

  it('POL-003 judges the link alike on both sides, is not offered to vaso fix, and folds into GHC-001', async () => {
    const home = join(root, 'home');
    const cop = join(home, '.copilot');
    const key = join(home, '.ssh', 'id_rsa');
    await put(key, 0o644);
    await mkdir(cop, { mode: 0o700 });
    await symlink(key, join(cop, 'session-state'));
    const ctx = localCtx(cop, home);
    const pol = await pol003.run(ctx);
    expect(pol).toMatchObject({ passed: false, fixable: false });
    expect(pol.evidence?.map(e => e.file)).toEqual([join(cop, 'session-state')]);
    expect(pol.fixDescription).toMatch(/a link, which vaso fix doesn't change/);
    const h = '/home/u';
    const remote = await pol003.run(snapshotCtx(h, {
      files: { [`${h}/.copilot/session-state`]: { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'metadata' } },
      directories: { [`${h}/.copilot`]: ['session-state'] },
      symlinks: { [`${h}/.copilot/session-state`]: `${h}/.ssh/id_rsa` },
      directoryModes: { [`${h}/.copilot`]: 0o40700, [`${h}/.ssh`]: 0o40755 },
    }));
    expect(remote).toMatchObject({ passed: false, fixable: false });
    const [ghc, folded] = dedupePermissionFindings([await check.run(ctx), pol]);
    expect(ghc.passed).toBe(false);
    expect(folded).toMatchObject({ passed: true, foldedInto: 'GHC-001', fixable: false });
  });

  it('a link to an ordinary file of the home is a store link too', async () => {
    const home = join(root, 'home');
    const cop = join(home, '.copilot');
    await put(join(home, 'notes.txt'), 0o600);
    await mkdir(cop, { mode: 0o700 });
    await symlink(join(home, 'notes.txt'), join(cop, 'session-state'));
    const r = await check.run(localCtx(cop, home));
    expect(r).toMatchObject({ passed: false, severity: 'warning', fixable: false });
    expect(r.message).toMatch(/point to a file instead of a folder/);
    expect(r.evidence?.[0].detail).toMatch(/link to the file .*notes\.txt, in the home, not a folder/);
  });
});

describe('GHC-001: the agent folder itself linked away', () => {
  it('~/.copilot linked out of the home: one warning for the link, nothing behind it judged or changed; local and snapshot agree', async () => {
    const home = join(root, 'home');
    const out = join(root, 'out', 'cop');
    await put(join(out, 'session-state', 'abc', 'events.jsonl'), 0o644);
    await put(join(out, 'session-store.db'), 0o644);
    await mkdir(home, { recursive: true });
    await symlink(out, join(home, '.copilot'));
    const cop = join(home, '.copilot');
    const r = await check.run(localCtx(cop, home));
    expect(r).toMatchObject({ passed: false, severity: 'warning', fixable: false });
    expect(r.message).toMatch(/is a link out of the home — its private stores there are not checked/);
    expect(r.evidence?.map(e => e.file)).toEqual([cop]);
    expect(r.evidence?.[0].snippet).toBe(`-> ${out}`);
    expect((await check.fix!(localCtx(cop, home))).applied).toBe(false);
    expect((await stat(join(out, 'session-store.db'))).mode & 0o777).toBe(0o644);

    const h = '/home/u';
    const remote = await check.run(snapshotCtx(h, {
      files: { '/data/cop/config.json': { content: '{}', mode: 0o100600, exists: true }, [`${h}/.copilot/session-store.db`]: { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'metadata' } },
      directories: { [`${h}/.copilot`]: ['config.json', 'session-state/', 'session-store.db'] },
      symlinks: { [`${h}/.copilot`]: '/data/cop' },
      directoryModes: { [`${h}/.copilot`]: 0o40755 },
    }));
    expect(verdict(remote)).toEqual({ ...verdict(r), files: [`${h}/.copilot`], snippets: ['-> /data/cop'] });
  });

  it('~/.copilot linked into a credential store or onto the home is named so', async () => {
    const home = join(root, 'home');
    await mkdir(join(home, '.aws', 'cop'), { recursive: true });
    await symlink(join(home, '.aws', 'cop'), join(home, '.copilot'));
    const r = await check.run(localCtx(join(home, '.copilot'), home));
    expect(r.message).toMatch(/into a sensitive location \(AWS credentials/);
    const h = '/home/u';
    const onHome = await check.run(snapshotCtx(h, {
      files: {}, directories: { [`${h}/.copilot`]: ['x'] }, symlinks: { [`${h}/.copilot`]: h }, directoryModes: {},
    }));
    expect(onHome.message).toMatch(/to the home or a folder above it/);
  });

  // (snapshots: every folder reachable, so the findings are not mitigated)
  const ownStore = (dir: string): Pick<ProbeSnapshot, 'files' | 'directories' | 'directoryModes'> => ({
    files: { [`${dir}/session-state/abc/events.jsonl`]: { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'metadata' } },
    directories: { [dir]: ['session-state/'], [`${dir}/session-state`]: ['abc/'], [`${dir}/session-state/abc`]: ['events.jsonl'] },
    directoryModes: { [dir]: 0o40755, [`${dir}/session-state`]: 0o40755, [`${dir}/session-state/abc`]: 0o40755 },
  });

  it('~/.copilot linked within the home is walked as the agent\'s own (and fixable)', async () => {
    const h = '/home/u';
    const real = `${h}/dotfiles/cop`;
    const store = ownStore(`${h}/.copilot`);
    const r = await check.run(snapshotCtx(h, {
      ...store, symlinks: { [`${h}/.copilot`]: real },
      directoryModes: { ...store.directoryModes, [`${h}/dotfiles`]: 0o40755, [real]: 0o40755 },
    }));
    expect(r).toMatchObject({ passed: false, severity: 'critical', fixable: true });
    expect(r.evidence?.map(e => e.file)).toEqual([`${h}/.copilot/session-state/abc/events.jsonl`]);
  });

  it('a folder set outside the home (COPILOT_HOME) is the agent\'s own: judged, but not offered to vaso fix, which writes only inside the home', async () => {
    const r = await check.run(snapshotCtx('/home/u', { ...ownStore('/data/cp'), symlinks: {} }, '/data/cp'));
    expect(r).toMatchObject({ passed: false, severity: 'critical', fixable: false });
    expect(r.evidence?.map(e => e.file)).toEqual(['/data/cp/session-state/abc/events.jsonl']);
    expect(r.message).toMatch(/not changed by vaso fix: \/data\/cp is outside the home/);
    expect(r.fixDescription).toMatch(/chmod -R go-rwx \/data\/cp/);
    // …linked into the home, vaso fix can change it
    const inHome = await check.run(snapshotCtx('/home/u', {
      ...ownStore('/data/cp'), symlinks: { '/data/cp': '/home/u/cp' },
    }, '/data/cp'));
    expect(inHome).toMatchObject({ passed: false, fixable: true });
  });

  it('a folder set outside the home locally: not fixable, and vaso fix still refuses it', async () => {
    const home = join(root, 'home');
    await mkdir(home, { recursive: true });
    const cp = join(root, 'data', 'cp');
    await put(join(cp, 'session-state', 'abc', 'events.jsonl'), 0o644);
    const r = await check.run(localCtx(cp, home));
    expect(r).toMatchObject({ passed: false, fixable: false });
    expect(r.evidence?.map(e => e.file)).toEqual([join(cp, 'session-state', 'abc', 'events.jsonl')]);
  });
});

describe('GHC-001: COPILOT_HOME named .copilot below a folder linked out of the home', () => {
  for (const sub of ['.copilot', join('a', '.copilot')]) {
    it(`~/x/${sub} with ~/x linked out: a link out of the home, nothing behind it judged or changed`, async () => {
      const home = join(root, 'home');
      await mkdir(home, { recursive: true });
      const outside = join(root, 'outside', 'x');
      const real = join(outside, sub);
      await put(join(real, 'session-state', 'abc', 'events.jsonl'), 0o644);
      await put(join(real, 'mcp-secrets', 'CANARY.json'), 0o644);
      await symlink(outside, join(home, 'x'));
      const cop = join(home, 'x', sub);
      const ctx = localCtx(cop, home);
      ctx.fs.getEnv = (k: string) => (k === 'COPILOT_HOME' ? cop : undefined);
      const r = await check.run(ctx);
      expect(r).toMatchObject({ passed: false, severity: 'warning', fixable: false });
      expect(r.message).toMatch(/is a link out of the home/);
      expect(JSON.stringify(r)).not.toMatch(/CANARY|events\.jsonl/);
      await check.fix!(ctx);
      expect((await stat(join(real, 'mcp-secrets', 'CANARY.json'))).mode & 0o777).toBe(0o644);
    });
  }
});

describe('GHC-001: fix targets beyond the listed evidence', () => {
  it('judges every open store file, not the 40 listed and the "+N more" line naming the store folder', async () => {
    const { markRefusedFix } = await import('../../remediation/fix-refusal.js');
    const home = join(root, 'home');
    const cop = join(home, '.copilot');
    const sec = join(cop, 'mcp-secrets');
    await mkdir(sec, { recursive: true, mode: 0o700 });
    await chmod(cop, 0o700);
    await chmod(sec, 0o700);
    const targets = join(home, 'targets');
    for (let i = 0; i < 45; i++) {
      const name = `a${String(i).padStart(2, '0')}.json`;
      await put(join(targets, name), 0o644);
      await symlink(join(targets, name), join(sec, name));
    }
    for (let i = 0; i < 5; i++) await put(join(sec, `z${i}.json`), 0o644);
    const before = await check.run(localCtx(cop, home));
    const ctx = localCtx(cop, home);
    const r1 = await check.run(ctx);
    expect(r1.evidence?.some(e => /^\+\d+ more file/.test(e.snippet ?? ''))).toBe(true);
    expect((await markRefusedFix(check, ctx, r1, { home })).fixable).toBe(true);
    expect(before.fixable).toBe(true);
    // the real files fixed: only links are left — no longer offered
    for (let i = 0; i < 5; i++) await chmod(join(sec, `z${i}.json`), 0o600);
    const ctx2 = localCtx(cop, home);
    const r2 = await check.run(ctx2);
    expect(r2.evidence?.some(e => e.file === sec)).toBe(true);
    const marked = await markRefusedFix(check, ctx2, r2, { home });
    expect(marked.fixable).toBe(false);
    expect(marked.message).toMatch(/not changed by vaso fix: .*a00\.json is a symlink/);
  });
});

describe('GHC-001: COPILOT_HOME set inside a credential store (no link)', () => {
  it('says the folder is inside it, not that it is a link', async () => {
    const home = join(root, 'home');
    const cop = join(home, '.aws', 'cop');
    await put(join(cop, 'session-state', 'abc', 'events.jsonl'), 0o644);
    const ctx = localCtx(cop, home);
    ctx.fs.getEnv = (k: string) => (k === 'COPILOT_HOME' ? cop : undefined);
    const r = await check.run(ctx);
    expect(r).toMatchObject({ passed: false, severity: 'warning', fixable: false });
    expect(r.message).toBe(`Copilot CLI folder ${cop} is inside AWS credentials (~/.aws) — its private stores there are not checked and its config files are not read`);
    expect(r.evidence?.[0].detail).toMatch(/is inside AWS credentials/);
    expect(JSON.stringify(r)).not.toMatch(/is a link|events\.jsonl/);
  });
});
