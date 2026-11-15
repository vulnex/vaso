import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { getSkillFiles } from './utils.js';

/**
 * Links inside a walked skills tree follow the skill-root rule
 * (skill-root-scope.ts; linkInScope in the probe): a skill linked in from
 * another volume is read, one linked from an OS directory or the home itself
 * is not.
 */
describe('links in a skills tree', () => {
  let root: string;
  let outside: string;
  let home: string;
  let fs: LocalFSProvider;

  beforeAll(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-walk-scope-')));
    // under /tmp: os.tmpdir() is under /var on macOS, an OS directory
    outside = await realpath(await mkdtemp('/tmp/vaso-walk-scope-out-'));
    home = join(root, 'home');
    const skills = join(home, '.claude', 'skills');
    await mkdir(join(skills, 'own'), { recursive: true });
    await writeFile(join(skills, 'own', 'SKILL.md'), '# own\n');
    await mkdir(join(outside, 'team'), { recursive: true });
    await writeFile(join(outside, 'team', 'run.sh'), '#!/bin/sh\necho hi\n');
    await writeFile(join(outside, 'f.js'), 'eval(x)\n');
    await symlink(join(outside, 'team'), join(skills, 'team'));
    await symlink(join(outside, 'f.js'), join(skills, 'own', 'f.js'));
    await symlink('/usr/share', join(skills, 'share'));
    await symlink(home, join(skills, 'up'));
    fs = Object.assign(Object.create(new LocalFSProvider()) as LocalFSProvider, { homedir: () => home });
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  it('reads skills linked in from out of the home, not from an OS directory or the home itself', async () => {
    const skills = join(home, '.claude', 'skills');
    const files = await getSkillFiles(skills, fs);
    expect(files).toContain(join(skills, 'team', 'run.sh'));
    expect(files).toContain(join(skills, 'own', 'f.js'));
    expect(files.filter(f => f.startsWith(join(skills, 'share') + '/'))).toEqual([]);
    expect(files.filter(f => f.startsWith(join(skills, 'up') + '/'))).toEqual([]);
  });
});
