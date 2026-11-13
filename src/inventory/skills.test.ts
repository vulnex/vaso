import { afterEach, describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import type { AgentInstallation } from '../core/types.js';
import { getSkillFiles } from '../core/utils.js';
import { cleanDescription, collectSkillInventory, readFrontmatter } from './skills.js';

const fs = new LocalFSProvider();
const roots: string[] = [];

afterEach(async () => {
  for (const d of roots) {
    await chmod(d, 0o700).catch(() => {});
    await rm(d, { recursive: true, force: true }).catch(() => {});
  }
  roots.length = 0;
});

async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'vaso-inv-'));
  roots.push(d);
  return d;
}

async function put(path: string, content = 'x'): Promise<void> {
  await mkdir(join(path, '..'), { recursive: true });
  await writeFile(path, content);
}

function inst(skillsDirs: string[], extra: Partial<AgentInstallation> = {}): AgentInstallation {
  return { agent: 'claude-code', installDir: '/x', configFiles: [], skillsDirs, ...extra };
}

describe('collectSkillInventory', () => {
  it('lists SKILL.md folders as skills, with frontmatter name and description', async () => {
    const root = await tmp();
    await put(join(root, 'pdf', 'SKILL.md'), '---\nname: pdf-tools\ndescription: Work with PDF files\n---\n# PDF\n');
    await put(join(root, 'pdf', 'scripts', 'fill.py'), 'print(1)');
    await put(join(root, 'notes', 'SKILL.md'), '# no frontmatter');

    const { inventory, files } = await collectSkillInventory(inst([root]), fs);

    expect(inventory.skillsDirs).toEqual([{ path: root, exists: true }]);
    expect(inventory.skills.map(s => [s.name, s.files, s.hasCode, s.scope, s.kind]).sort()).toEqual([
      ['notes', 1, false, 'user', 'skill-md'],
      ['pdf-tools', 2, true, 'user', 'skill-md'],
    ]);
    expect(inventory.skills.find(s => s.name === 'pdf-tools')?.description).toBe('Work with PDF files');
    expect(inventory.otherEntries).toEqual([]);
    expect(files?.sort()).toEqual((await getSkillFiles(root)).sort());
  });

  it('counts a nested SKILL.md as part of its outer skill, and finds skills inside category folders', async () => {
    const root = await tmp();
    await put(join(root, 'outer', 'SKILL.md'));
    await put(join(root, 'outer', 'examples', 'inner', 'SKILL.md'));
    await put(join(root, '.system', 'creator', 'SKILL.md'));
    await put(join(root, 'research', 'arxiv', 'SKILL.md'));

    const { inventory } = await collectSkillInventory(inst([root]), fs);

    expect(inventory.skills.map(s => s.path).sort()).toEqual([
      join(root, '.system', 'creator'),
      join(root, 'outer'),
      join(root, 'research', 'arxiv'),
    ]);
    // a category folder holding skills isn't an "other entry"
    expect(inventory.otherEntries).toEqual([]);
  });

  it('lists folders and loose scripts without SKILL.md as other entries, not skills', async () => {
    const root = await tmp();
    await put(join(root, 'helper', 'run.js'));
    await put(join(root, 'empty-dir', 'README.md'));
    await put(join(root, 'loose.sh'), '#!/bin/sh\n');
    await put(join(root, 'notes.txt'));
    await put(join(root, '.DS_Store'));
    await put(join(root, 'node_modules', 'x', 'index.js'));

    const { inventory } = await collectSkillInventory(inst([root]), fs);

    expect(inventory.skills).toEqual([]);
    expect(inventory.otherEntries.map(e => [e.path.slice(root.length + 1), e.type, e.files, e.hasCode]).sort()).toEqual([
      ['empty-dir', 'directory', 0, false],
      ['helper', 'directory', 1, true],
      ['loose.sh', 'file', 1, true],
    ]);
  });

  it('marks missing skills directories and returns no file list when none are declared', async () => {
    const root = await tmp();
    const missing = join(root, 'nope');
    const { inventory } = await collectSkillInventory(inst([missing]), fs);
    expect(inventory.skillsDirs).toEqual([{ path: missing, exists: false }]);
    expect(inventory.incomplete).toBeUndefined();

    const none = await collectSkillInventory(inst([]), fs);
    expect(none.files).toBeUndefined();
    expect(none.inventory.skillsDirs).toEqual([]);
  });

  it('records the target of a symlinked skill under the path the agent uses', async () => {
    const root = await tmp();
    const elsewhere = await tmp();
    await put(join(elsewhere, 'ext', 'SKILL.md'), '---\nname: ext\n---\n');
    await mkdir(join(root, 'skills'));
    await symlink(join(elsewhere, 'ext'), join(root, 'skills', 'ext'));

    const { inventory } = await collectSkillInventory(inst([join(root, 'skills')]), fs);

    expect(inventory.skills).toHaveLength(1);
    expect(inventory.skills[0].path).toBe(join(root, 'skills', 'ext'));
    expect(inventory.skills[0].symlinkTarget).toBe(await fs.realpath(join(elsewhere, 'ext')));
  });

  it('counts a skill whose SKILL.md links into the same tree (gstack layout), with files at the target', async () => {
    const root = await tmp();
    await put(join(root, 'gstack', 'SKILL.md'), '---\nname: gstack\n---\n');
    await put(join(root, 'gstack', 'review', 'SKILL.md'), '---\nname: review\ndescription: Review the diff\n---\n');
    await put(join(root, 'gstack', 'review', 'bin', 'run.sh'), '#!/bin/sh\n');
    await mkdir(join(root, 'review'));
    await symlink(join(root, 'gstack', 'review', 'SKILL.md'), join(root, 'review', 'SKILL.md'));
    await symlink(join(root, 'gstack', 'review', 'bin'), join(root, 'review', 'bin'));
    await mkdir(join(root, 'dangling'));
    await symlink(join(root, 'nowhere', 'SKILL.md'), join(root, 'dangling', 'SKILL.md'));

    const { inventory } = await collectSkillInventory(inst([root]), fs);

    const review = inventory.skills.find(s => s.path === join(root, 'review'));
    expect(review).toMatchObject({ name: 'review', description: 'Review the diff', files: 2, hasCode: true, symlinkTarget: join(root, 'gstack', 'review') });
    expect(inventory.skills.map(s => s.name).sort()).toEqual(['gstack', 'review']);
    expect(inventory.otherEntries.map(e => e.path)).toEqual([join(root, 'dangling')]);
  });

  it('resolves a relative SKILL.md link under a symlinked skills root in the walked spelling', async () => {
    const home = await tmp();
    await put(join(home, 'real-skills', 'gs', 'skills', 'x', 'SKILL.md'), '---\nname: x\n---\n');
    await put(join(home, 'real-skills', 'gs', 'skills', 'x', 'run.py'), 'x');
    await put(join(home, 'real-skills', 'x', 'extra.py'), 'x');
    await symlink('../gs/skills/x/SKILL.md', join(home, 'real-skills', 'x', 'SKILL.md'));
    await symlink(join(home, 'real-skills'), join(home, 'skills'));
    const root = join(home, 'skills');

    const { inventory } = await collectSkillInventory(inst([root]), fs);

    const x = inventory.skills.find(s => s.path === join(root, 'x'));
    expect(x).toMatchObject({ files: 3, symlinkTarget: join(root, 'gs', 'skills', 'x') });
  });

  it.skipIf(process.getuid?.() === 0)('reports an unlistable skill folder as incomplete and still counts its SKILL.md', async () => {
    const root = await tmp();
    await put(join(root, 'locked', 'SKILL.md'));
    await chmod(join(root, 'locked'), 0o111);
    roots.push(join(root, 'locked'));

    const { inventory } = await collectSkillInventory(inst([root]), fs);

    expect(inventory.skills.map(s => s.name)).toEqual(['locked']);
    expect(inventory.incomplete).toEqual([`${join(root, 'locked')}: contents can't be listed`]);
  });

  it('does not count archived skills (Hermes .archive) but lists the folder', async () => {
    const root = await tmp();
    await put(join(root, 'apple', 'notes', 'SKILL.md'));
    await put(join(root, '.archive', 'old-skill', 'SKILL.md'));
    await put(join(root, '.archive', 'old-skill', 'run.py'));
    await put(join(root, '.system', 'creator', 'SKILL.md'));

    const { inventory, files } = await collectSkillInventory(inst([root]), fs);

    expect(inventory.skills.map(s => s.name).sort()).toEqual(['creator', 'notes']);
    expect(inventory.otherEntries.map(e => [e.path.slice(root.length + 1), e.files])).toEqual([['.archive', 2]]);
    // still read by the skill checks
    expect(files).toContain(join(root, '.archive', 'old-skill', 'run.py'));
  });

  it('ignores a stray SKILL.md at the skills root when skills sit below it', async () => {
    const root = await tmp();
    await put(join(root, 'SKILL.md'), '---\nname: rootskill\n---\n');
    await put(join(root, 'a', 'SKILL.md'));
    await put(join(root, 'b', 'SKILL.md'));
    const { inventory } = await collectSkillInventory(inst([root]), fs);
    expect(inventory.skills.map(s => s.name).sort()).toEqual(['a', 'b']);
  });

  it('treats the root as the skill when it is the only one (skill audit of one skill)', async () => {
    const root = await tmp();
    await put(join(root, 'SKILL.md'), '---\nname: solo\n---\n');
    await put(join(root, 'scripts', 'run.py'));
    const { inventory } = await collectSkillInventory(inst([root]), fs);
    expect(inventory.skills.map(s => [s.name, s.files, s.hasCode])).toEqual([['solo', 2, true]]);
    expect(inventory.otherEntries).toEqual([]);
  });

  it('lists dot entries the checks read, and counts ..x files inside a skill', async () => {
    const root = await tmp();
    await put(join(root, '.hidden.sh'), '#!/bin/sh\n');
    await put(join(root, '.tools', 'rs.sh'), '#!/bin/sh\n');
    await put(join(root, '.DS_Store'));
    await put(join(root, 'dotdot', 'SKILL.md'));
    await put(join(root, 'dotdot', '..payload.js'), 'x');
    const { inventory } = await collectSkillInventory(inst([root]), fs);
    expect(inventory.otherEntries.map(e => e.path.slice(root.length + 1)).sort()).toEqual(['.hidden.sh', '.tools']);
    expect(inventory.skills.map(s => [s.name, s.files, s.hasCode])).toEqual([['dotdot', 2, true]]);
  });

  it('stays fast with thousands of skills', async () => {
    const root = await tmp();
    for (let i = 0; i < 3000; i++) await put(join(root, `s${i}`, 'SKILL.md'), '---\nname: x\n---\n');
    const start = Date.now();
    const { inventory } = await collectSkillInventory(inst([root]), fs);
    expect(inventory.skills).toHaveLength(3000);
    expect(Date.now() - start).toBeLessThan(15_000);
  }, 120_000);

  it('uses project scope for project installations and dedupes repeated roots', async () => {
    const root = await tmp();
    await put(join(root, 'a', 'SKILL.md'));
    const { inventory } = await collectSkillInventory(inst([root, root], { profile: 'project' }), fs);
    expect(inventory.skills).toHaveLength(1);
    expect(inventory.skills[0].scope).toBe('project');
    expect(inventory.skillsDirs).toHaveLength(1);
  });
});

describe('readFrontmatter', () => {
  it('falls back to line reads when the frontmatter is not valid YAML', async () => {
    const root = await tmp();
    const p = join(root, 'SKILL.md');
    await writeFile(p, '---\nname: "deploy"\ndescription: Use when: the user deploys: anything\n---\n');
    expect(await readFrontmatter(fs, p)).toEqual({ name: 'deploy', description: 'Use when: the user deploys: anything' });
  });

  it('ignores a file without frontmatter or that cannot be read', async () => {
    const root = await tmp();
    await writeFile(join(root, 'SKILL.md'), '# title\nname: x\n');
    expect(await readFrontmatter(fs, join(root, 'SKILL.md'))).toEqual({});
    expect(await readFrontmatter(fs, join(root, 'missing.md'))).toEqual({});
  });
});

describe('cleanDescription', () => {
  it('flattens control characters and line breaks', () => {
    expect(cleanDescription('line one\nline\u001b[31m two three')).toBe('line one line [31m two three');
  });

  it('shortens to 200 characters', () => {
    const out = cleanDescription('word '.repeat(100))!;
    expect(out.length).toBeLessThanOrEqual(204);
    expect(out.endsWith(' ...')).toBe(true);
  });

  it('masks a PEM body and a bare JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Zk3pQ8rT2vX9yB4nM6sK1wE7hJ5cL0aD';
    expect(cleanDescription(`session ${jwt}`)).not.toContain('Zk3pQ8rT2vX9');
    const pem = '-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAzk3pQ8rT2vX9yB4nM6sK1wE7hJ5cL0aDzk3pQ8rT2vX9yB4n -----END RSA PRIVATE KEY-----';
    expect(cleanDescription(`key ${pem}`)).not.toContain('MIIEowIBAAKCAQEA');
  });

  it('masks secrets', () => {
    const key = 'sk-ant-api03-' + 'A'.repeat(90);
    const out = cleanDescription(`Calls the API with ${key} as needed`)!;
    expect(out).not.toContain('A'.repeat(20));
  });

  it('returns undefined for blank text', () => {
    expect(cleanDescription(' \n\t ')).toBeUndefined();
  });
});
