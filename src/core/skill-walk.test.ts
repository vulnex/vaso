import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, symlink, rm, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { LocalFSProvider } from './local-fs-provider.js';
import { walkSkillTree, listSkillDirs } from './skill-walk.js';
import { getSkillFiles } from './utils.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';

const fs = new LocalFSProvider();
let base: string;
let skills: string;
let outside: string;

const files = (entries: Awaited<ReturnType<typeof walkSkillTree>>) =>
  entries.filter(e => e.isFile).map(e => join(e.parentPath ?? '', e.name)).sort();

beforeEach(async () => {
  base = await realpath(await mkdtemp(join(tmpdir(), 'vaso-skillwalk-')));
  skills = join(base, 'skills');
  outside = join(base, 'checkout');
  await mkdir(join(skills, 'local'), { recursive: true });
  await writeFile(join(skills, 'local', 'index.js'), 'x');
  await mkdir(join(outside, 'linked', 'lib'), { recursive: true });
  await writeFile(join(outside, 'linked', 'index.js'), 'eval(x)');
  await writeFile(join(outside, 'linked', 'lib', 'util.js'), 'y');
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

describe.skipIf(process.platform === 'win32')('walkSkillTree', () => {
  it('follows a skill symlinked in from outside the tree, under the link path', async () => {
    await symlink(join(outside, 'linked'), join(skills, 'linked'));
    expect(files(await walkSkillTree(fs, skills))).toEqual([
      join(skills, 'linked', 'index.js'),
      join(skills, 'linked', 'lib', 'util.js'),
      join(skills, 'local', 'index.js'),
    ]);
    expect(await getSkillFiles(skills, fs)).toContain(join(skills, 'linked', 'lib', 'util.js'));
  });

  it('does not walk a link into the tree twice', async () => {
    await symlink(join(skills, 'local'), join(skills, 'alias'));
    expect(files(await walkSkillTree(fs, skills))).toEqual([join(skills, 'local', 'index.js')]);
  });

  it('survives cycles and dangling links, and walks one target once', async () => {
    await symlink(join(outside, 'linked'), join(skills, 'a'));
    await symlink(join(outside, 'linked'), join(skills, 'b'));
    await symlink(outside, join(outside, 'linked', 'lib', 'up')); // cycle back above the target
    await symlink(join(base, 'missing'), join(skills, 'dangling'));
    const found = files(await walkSkillTree(fs, skills));
    expect(found.filter(f => f.endsWith('util.js'))).toHaveLength(1);
    expect(found.length).toBeLessThan(10);
  });

  it('follows a symlinked file', async () => {
    await symlink(join(outside, 'linked', 'index.js'), join(skills, 'single.js'));
    expect(files(await walkSkillTree(fs, skills))).toContain(join(skills, 'single.js'));
  });

  it('reports a skill once when a link to its parent dir also exists', async () => {
    // chain/devlink → checkout/ (the parent), linked → checkout/linked
    await mkdir(join(skills, 'chain'), { recursive: true });
    await symlink(outside, join(skills, 'chain', 'devlink'));
    await symlink(join(outside, 'linked'), join(skills, 'linked'));
    await writeFile(join(outside, 'lone.js'), 'z');
    await symlink(join(outside, 'lone.js'), join(skills, 'lone.js'));
    const found = files(await walkSkillTree(fs, skills));
    expect(found.filter(f => f.endsWith('util.js'))).toEqual([join(skills, 'linked', 'lib', 'util.js')]);
    expect(found.filter(f => f.endsWith('lone.js'))).toEqual([join(skills, 'lone.js')]);
  });

  it('never follows a link into a credential store, but still follows ordinary linked skills', async () => {
    await mkdir(join(base, '.ssh'), { recursive: true });
    await writeFile(join(base, '.ssh', 'id_ed25519'), 'KEY');
    await mkdir(join(base, '.aws'), { recursive: true });
    await writeFile(join(base, '.aws', 'credentials'), 'AWS');
    await symlink('../.ssh', join(skills, 'sshlink'));
    await symlink(join(base, '.ssh'), join(skills, '.ssh')); // named like the sink
    await symlink(join(base, '.aws', 'credentials'), join(skills, 'local', 'creds.txt'));
    await symlink(join(outside, 'linked'), join(skills, 'linked'));
    // A real directory named .ssh inside a skill is the skill's own content
    await mkdir(join(skills, 'local', '.ssh'), { recursive: true });
    await writeFile(join(skills, 'local', '.ssh', 'setup.js'), 'z');
    const entries = await walkSkillTree(fs, skills);
    const found = files(entries);
    expect(found.some(f => f.includes('id_ed25519') || f.endsWith('creds.txt'))).toBe(false);
    expect(found).toContain(join(skills, 'linked', 'index.js'));
    expect(found).toContain(join(skills, 'local', '.ssh', 'setup.js'));
    // The links themselves are still listed (SKL-013 reads their targets)
    expect(entries.filter(e => e.isSymbolicLink).map(e => e.name).sort()).toEqual(['.ssh', 'creds.txt', 'sshlink']);
  });

  it('never reads an agent token file the tree reaches through a linked root or a file link', async () => {
    await mkdir(join(base, '.claude', 'kit'), { recursive: true });
    await writeFile(join(base, '.claude', '.credentials.json'), '{"accessToken":"TOKCANARY"}');
    await writeFile(join(base, '.claude', 'kit', 'SKILL.md'), '---\nname: kit\n---\n');
    await mkdir(join(base, '.config', 'gh'), { recursive: true });
    await writeFile(join(base, '.config', 'gh', 'hosts.yml'), 'oauth_token: x');
    await writeFile(join(base, '.config', 'notes.md'), 'n');
    // a root linked to ~/.claude, one linked to ~/.config
    await symlink(join(base, '.claude'), join(base, 'linked-root'));
    expect(files(await walkSkillTree(fs, join(base, 'linked-root')))).toEqual([join(base, 'linked-root', 'kit', 'SKILL.md')]);
    await symlink(join(base, '.config'), join(base, 'cfg-root'));
    expect(files(await walkSkillTree(fs, join(base, 'cfg-root')))).toEqual([join(base, 'cfg-root', 'notes.md')]);
    // a skill file linked to the token file
    await symlink(join(base, '.claude', '.credentials.json'), join(skills, 'local', 'c.json'));
    expect(files(await walkSkillTree(fs, skills))).toEqual([join(skills, 'local', 'index.js')]);
    // the token store walked as itself is listed (it names itself)
    expect(files(await walkSkillTree(fs, join(base, '.claude')))).toContain(join(base, '.claude', '.credentials.json'));
  });

  it('lists symlinked skill directories by name', async () => {
    await symlink(join(outside, 'linked'), join(skills, 'linked'));
    await symlink(join(outside, 'linked', 'index.js'), join(skills, 'file-link'));
    const names = (await listSkillDirs(fs, skills)).map(e => e.name).sort();
    expect(names).toEqual(['linked', 'local']);
  });
});

describe('walkSkillTree on a probe snapshot', () => {
  const f = (content: string) => ({ exists: true, mode: 0o644, content });
  const snap = new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-10-13T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: {
      '/home/u/skills/local/index.js': f('x'),
      // collected by the probe under the link's path (≥ 1.2.1)
      '/home/u/skills/linked/index.js': f('eval(x)'),
      '/home/u/skills/linked/lib/util.js': f('y'),
    },
    directories: {},
    commandOutputs: {},
    env: {},
    symlinks: {
      '/home/u/skills/linked': '/home/u/checkout/linked',
      '/home/u/skills/alias': '/home/u/skills/local',
    },
  });

  it('lists the same files as a local walk — once each', async () => {
    expect(files(await walkSkillTree(snap, '/home/u/skills'))).toEqual([
      '/home/u/skills/linked/index.js',
      '/home/u/skills/linked/lib/util.js',
      '/home/u/skills/local/index.js',
    ]);
  });

  it('does not follow links into credential stores the probe left out (≥ 1.4.0)', async () => {
    const s = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-10-18T00:00:00Z',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: {
        '/home/u/skills/fmt/SKILL.md': f('---\nname: fmt\n---\n'),
        '/home/u/skills/fmt/creds.txt': { exists: true, mode: 0o600, content: '', contentOmitted: true, omitted: 'sensitive' },
      },
      directories: {},
      commandOutputs: {},
      env: {},
      directoryModes: { '/home/u/.ssh': 0o700 },
      symlinks: {
        '/home/u/skills/fmt/creds.txt': '/home/u/.aws/credentials',
        '/home/u/skills/sshlink': '../.ssh',
      },
    });
    expect(files(await walkSkillTree(s, '/home/u/skills'))).toEqual(['/home/u/skills/fmt/SKILL.md']);
    expect(await getSkillFiles('/home/u/skills', s)).toEqual(['/home/u/skills/fmt/SKILL.md']);
  });

  it('keeps a plain recursive listing from descending through the link', async () => {
    const plain = await snap.readdirEntries('/home/u/skills', { recursive: true });
    expect(plain.filter(e => e.isFile).map(e => e.name)).toEqual(['index.js']);
    expect(plain.filter(e => e.isSymbolicLink).map(e => e.name).sort()).toEqual(['alias', 'linked']);
  });
});

describe('skillFrontmatterName (dt15 P5)', () => {
  const nameOf = async (md: string) => {
    const { skillFrontmatterName } = await import('./skill-walk.js');
    const dir = join(base, 'fm');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'SKILL.md'), md);
    return skillFrontmatterName(fs, dir);
  };

  it('reads bare, quoted and commented names', async () => {
    expect(await nameOf('---\nname: notes  # the notes skill\ndescription: d\n---\n')).toBe('notes');
    expect(await nameOf('---\r\nname: "my notes"\r\ndescription: d\r\n---\r\n')).toBe('my notes');
    expect(await nameOf('---\r\nname: notes \r\ndescription: d\r\n---\r\n')).toBe('notes');
    expect(await nameOf("---\nname: 'x#y'\n---\n")).toBe('x#y');
  });

  it('is linear on a long space run inside the name', async () => {
    const start = Date.now();
    expect(await nameOf(`---\nname: notes${' '.repeat(100_000)}x#\ndescription: d\n---\n`)).toBe(`notes${' '.repeat(100_000)}x`);
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
