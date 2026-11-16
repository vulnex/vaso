import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { listSkillTree } from './utils.js';
import { cleanSkillRoot, screenSkillRoots, unscannedReason } from './skill-root-scope.js';
import { collectSkillInventory } from '../inventory/skills.js';
import { skl002 } from '../checks/skills/skl-002-obfuscated-code.js';
import { skl013 } from '../checks/skills/skl-013-symlink-escape.js';
import type { AgentInstallation, ScanContext } from './types.js';
import { maskCredentialsInLine } from '../reporting/serialize.js';

/**
 * A skill linked into a skills tree to where no skills tree is walked (an OS
 * directory, the home itself) is reported not scanned — SKL-002, as a refused
 * skills directory — and SKL-013 doesn't claim its code is scanned there.
 */
describe('skills linked to places no skills tree is walked', () => {
  let root: string;
  let outside: string;
  let home: string;
  let skills: string;
  let fs: LocalFSProvider;

  beforeAll(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-link-refusals-')));
    outside = await realpath(await mkdtemp('/tmp/vaso-link-refusals-out-'));
    home = join(root, 'home');
    skills = join(home, '.claude', 'skills');
    await mkdir(join(skills, 'own'), { recursive: true });
    await writeFile(join(skills, 'own', 'SKILL.md'), '# own\n');
    await mkdir(join(outside, 'store', 'team'), { recursive: true });
    await writeFile(join(outside, 'store', 'team', 'SKILL.md'), '# team\n');
    await symlink(join(outside, 'store', 'team'), join(skills, 'team'));
    await symlink('/usr/share', join(skills, 'share'));
    await symlink(home, join(skills, 'up'));
    fs = Object.assign(Object.create(new LocalFSProvider()) as LocalFSProvider, { homedir: () => home });
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  const installation = (): AgentInstallation => ({ agent: 'claude-code', installDir: join(home, '.claude'), configFiles: [], skillsDir: skills });

  it('the walk lists the links it does not follow', async () => {
    const listing = await listSkillTree(skills, fs);
    expect(listing.refusedLinks.sort()).toEqual([join(skills, 'share'), join(skills, 'up')]);
  });

  it('the inventory reports them not scanned, and SKL-002 warns', async () => {
    const inst = installation();
    const { inventory } = await collectSkillInventory(inst, fs);
    expect(inst.unscannedSkillsDirs?.map(u => [u.path, u.reason, u.refusedAs, u.skillLink])).toEqual([
      [join(skills, 'share'), 'outside', 'an OS directory (/usr)', true],
      [join(skills, 'up'), 'home', undefined, true],
    ]);
    expect(inventory.incomplete?.join('\n')).toContain(`${join(skills, 'share')}: not scanned: skill links to /usr/share, an OS directory (/usr)`);
    const ctx: ScanContext = { installation: inst, configs: [], platform: process.platform as ScanContext['platform'], fs };
    const r = await skl002.run(ctx);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.message).toContain(`skill ${join(skills, 'share')} not scanned (links to /usr/share, an OS directory (/usr))`);
    const links = await skl013.run(ctx);
    const share = links.evidence?.find(e => e.file === join(skills, 'share'));
    expect(share?.detail).toMatch(/its code is not scanned \(see SKL-002\)/);
    const team = links.evidence?.find(e => e.file === join(skills, 'team'));
    expect(team?.detail).toMatch(/its code is scanned there/);
  });
});

describe('where a refused skills directory is', () => {
  it('names the OS directory as the path spells it', async () => {
    const fs = new LocalFSProvider();
    const { unscanned } = await screenSkillRoots(fs, ['/System/Library/Fonts', '/Library/Fonts', '/private/etc/x'], '/nonexistent-vaso-home');
    expect(unscanned.map(u => u.refusedAs)).toEqual(['an OS directory (/System)', 'an OS directory (/Library)', 'an OS directory (/etc)']);
  });

  it('names the OS directory as the OS stores it, however the path is written', async () => {
    const fs = new LocalFSProvider();
    const { unscanned } = await screenSkillRoots(fs, ['/Private/Var/Folders/x', '/PRIVATE/etc/x', '/SYSTEM/Library/Fonts', '/LIBRARY/x', '/USR/share/man'], '/nonexistent-vaso-home');
    expect(unscanned.map(u => u.refusedAs)).toEqual([
      'an OS directory (/var)', 'an OS directory (/etc)', 'an OS directory (/System)', 'an OS directory (/Library)', 'an OS directory (/usr)',
    ]);
  });

  it('suggests vaso skill audit only for another user\'s skills', () => {
    expect(unscannedReason('outside', '/etc/x', { refusedAs: 'an OS directory (/etc)' })).toMatch(/keep skills in a dedicated folder$/);
    expect(unscannedReason('outside', '/home/bob/s', { refusedAs: 'another user\'s home (/home/bob)' })).toMatch(/vaso skill audit \/home\/bob\/s`$/);
  });

  it('keys a config-set directory as cleaned, as the probe records it', async () => {
    expect(cleanSkillRoot('/tmp/./x')).toBe('/tmp/x');
    expect(cleanSkillRoot('/tmp//x/')).toBe('/tmp/x');
    expect(cleanSkillRoot('/etc/../tmp/x')).toBe('/tmp/x');
    expect(cleanSkillRoot('/')).toBe('/');
    expect(cleanSkillRoot('rel/./x')).toBe('rel/./x');
    const { unscanned } = await screenSkillRoots(new LocalFSProvider(), ['/etc/', '/etc'], '/nonexistent-vaso-home');
    expect(unscanned.map(u => u.path)).toEqual(['/etc']);
  });
});

describe('a credential line continued in parentheses', () => {
  it('shows the code, masking its literals but an environment variable name', () => {
    expect(maskCredentialsInLine('api_key = (os.environ.get("K") or')).toBe('api_key = (os.environ.get("K") or');
    expect(maskCredentialsInLine('token = (getenv("T") ||')).toBe('token = (getenv("T") ||');
    expect(maskCredentialsInLine('api_key = (os.environ.get("K") or "fallbackpw")')).toBe('api_key = (os.environ.get("K") or "***")');
    expect(maskCredentialsInLine('password = (hunter2')).toBe('password = ***');
    expect(maskCredentialsInLine('api_key = ("sk-proj-abcdefghijklmnopqrstuvwx")')).not.toContain('abcdefghij');
  });
});
