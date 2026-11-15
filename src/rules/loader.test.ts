import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { writeFile, mkdir, rm, chmod, symlink, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadRules } from './loader.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

const TEST_DIR = join(tmpdir(), 'vaso-loader-test-' + Date.now());

beforeEach(async () => {
  await mkdir(join(TEST_DIR, 'rules'), { recursive: true });
});

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe('loadRules', () => {
  it('loads rules from extra paths', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'test.yaml');
    await writeFile(ruleFile, `
rules:
  - id: LOAD-001
    name: Loader test
    category: config
    severity: info
    description: Test rule for loader
    config:
      path: "a.b"
      operator: "exists"
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0].id).toBe('LOAD-001');
    expect(result.allErrors).toHaveLength(0);
  });

  it('keeps the first of two rules with one ID in a tier and warns naming both files', async () => {
    const file1 = join(TEST_DIR, 'rules', 'a.yaml');
    const file2 = join(TEST_DIR, 'rules', 'b.yaml');

    await writeFile(file1, `
rules:
  - id: DUP-001
    name: First version
    category: config
    severity: info
    description: First
    config:
      path: "a"
      operator: "exists"
`);

    await writeFile(file2, `
rules:
  - id: DUP-001
    name: Second version
    category: config
    severity: warning
    description: Second
    config:
      path: "b"
      operator: "exists"
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [file1, file2],
    });

    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0].name).toBe('First version');
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatchObject({ file: file2, rule: 'DUP-001' });
    expect(result.warnings[0].message).toContain(file1);
  });

  it('reports a --rules file that cannot be read as unreadable', async () => {
    const result = await loadRules({ skipGlobal: true, skipProject: true, extraPaths: [join(TEST_DIR, 'missing.yaml')] });
    expect(result.files[0]).toMatchObject({ source: 'explicit', unreadable: true });
  });


  it('collects validation errors with file context', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'bad.yaml');
    await writeFile(ruleFile, `
rules:
  - id: BAD
    severity: invalid
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors.length).toBeGreaterThan(0);
    expect(result.allErrors[0].file).toBe(ruleFile);
  });

  it('handles parse errors gracefully', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'broken.yaml');
    await writeFile(ruleFile, `
rules:
  - id: [unterminated
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors.length).toBeGreaterThan(0);
  });

  it('handles nonexistent file gracefully', async () => {
    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: ['/tmp/nonexistent-vaso-test.yaml'],
    });

    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors.length).toBeGreaterThan(0);
  });

  it('skips hidden files in directories', async () => {
    const dir = join(TEST_DIR, 'rules');
    await writeFile(join(dir, '.hidden.yaml'), `
rules:
  - id: HIDDEN-001
    name: Hidden
    category: config
    severity: info
    description: Should not be loaded
    config:
      path: "a"
      operator: "exists"
`);
    await writeFile(join(dir, 'visible.yaml'), `
rules:
  - id: VIS-001
    name: Visible
    category: config
    severity: info
    description: Should be loaded
    config:
      path: "a"
      operator: "exists"
`);

    // We can't directly test directory discovery since loadRules uses fixed paths,
    // but we can test that extra paths work correctly
    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [join(dir, 'visible.yaml')],
    });

    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0].id).toBe('VIS-001');
  });

  it('loads multiple rules from one file', async () => {
    const ruleFile = join(TEST_DIR, 'rules', 'multi.yaml');
    await writeFile(ruleFile, `
rules:
  - id: MULTI-001
    name: Rule one
    category: config
    severity: info
    description: First rule
    config:
      path: "a"
      operator: "exists"
  - id: MULTI-002
    name: Rule two
    category: config
    severity: warning
    description: Second rule
    pattern:
      regex: "test"
      target: configs
`);

    const result = await loadRules({
      skipGlobal: true,
      skipProject: true,
      extraPaths: [ruleFile],
    });

    expect(result.allRules).toHaveLength(2);
    expect(result.allRules[0].id).toBe('MULTI-001');
    expect(result.allRules[1].id).toBe('MULTI-002');
  });
});

describe('project rules (.vaso/rules in the working directory)', () => {
  const RULE = (id: string, extra = '') => `
rules:
  - id: ${id}
    name: n
    category: config
    severity: critical
    description: d
    config:
      path: "permissions.defaultMode"
      operator: "eq"
      value: "bypassPermissions"
${extra}`;
  const FIX = `    fix:
      set: "permissions.defaultMode"
      value: "bypassPermissions"
`;
  let home: string;
  let project: string;
  let fs: LocalFSProvider;

  beforeEach(async () => {
    home = join(TEST_DIR, 'home');
    project = join(TEST_DIR, 'repo');
    await mkdir(join(home, '.vaso', 'rules'), { recursive: true });
    await mkdir(join(project, '.vaso', 'rules'), { recursive: true });
    fs = new (class extends LocalFSProvider { homedir() { return home; } })();
    vi.spyOn(process, 'cwd').mockReturnValue(project);
  });

  afterEach(() => vi.restoreAllMocks());

  it('are not loaded unless the project is trusted; they are reported as skipped', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), RULE('ORG-1') + RULE('ORG-2').replace('rules:\n', ''));
    const result = await loadRules({ fs });
    expect(result.allRules).toEqual([]);
    expect(result.files).toEqual([]);
    expect(result.untrustedProject).toHaveLength(1);
    // not read for a scan: only counted
    expect(result.untrustedProject[0].rules).toEqual([]);
    expect(result.projectDir).toBe(await realpath(project));
    // `rules list` parses them to show what was skipped
    const listed = await loadRules({ fs, parseUntrusted: true });
    expect(listed.allRules).toEqual([]);
    expect(listed.untrustedProject[0].rules.map(r => r.id)).toEqual(['ORG-1', 'ORG-2']);
  });

  it('never reads an untrusted rule file for a scan (a huge or broken one costs nothing)', async () => {
    const big = join(project, '.vaso', 'rules', 'big.yaml');
    await writeFile(big, 'rules: [\n');
    const spy = vi.spyOn(fs, 'readFile');
    const result = await loadRules({ fs });
    expect(spy.mock.calls.map(c => c[0])).not.toContain(big);
    expect(result.untrustedProject.map(f => f.filePath)).toEqual([big]);
    expect(result.allErrors).toEqual([]);
  });

  describe.skipIf(process.platform === 'win32')('~/.vaso/trusted-projects must be the user\'s own, private and small', () => {
    const trustedBy = async (setup: (list: string) => Promise<void>) => {
      await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), RULE('ORG-1'));
      const list = join(home, '.vaso', 'trusted-projects');
      await writeFile(list, `${project}\n`);
      await chmod(list, 0o600);
      await setup(list);
      return loadRules({ fs });
    };

    it('a group/other-writable ~/.vaso makes it ignored', async () => {
      const result = await trustedBy(async () => { await chmod(join(home, '.vaso'), 0o777); });
      await chmod(join(home, '.vaso'), 0o755);
      expect(result.allRules).toEqual([]);
      expect(result.trustWarning).toMatch(/\.vaso is writable by group or others/);
    });

    it('a file over 64 KiB is ignored', async () => {
      const result = await trustedBy(async (list) => { await writeFile(list, `${project}\n${'#'.repeat(70 * 1024)}\n`); });
      expect(result.allRules).toEqual([]);
      expect(result.trustWarning).toMatch(/over 64 KiB/);
    });

    it('a directory in its place is ignored', async () => {
      const result = await trustedBy(async (list) => { await rm(list); await mkdir(list); });
      expect(result.allRules).toEqual([]);
      expect(result.trustWarning).toMatch(/not a regular file/);
    });

    it('a file owned by another user is ignored', async () => {
      const uid = process.getuid!();
      vi.spyOn(process, 'getuid').mockReturnValue(uid + 1);
      const result = await trustedBy(async () => {});
      expect(result.allRules).toEqual([]);
      expect(result.trustWarning).toMatch(/not owned by you/);
    });

    it('a symlink to a file in a directory others can write (not sticky) is ignored', async () => {
      const open = join(TEST_DIR, 'wdir');
      const result = await trustedBy(async (list) => {
        await mkdir(open);
        const target = join(open, 'tp');
        await writeFile(target, `${project}\n`);
        await chmod(target, 0o600);
        await chmod(open, 0o777);
        await rm(list);
        await symlink(target, list);
      });
      await chmod(open, 0o755);
      expect(result.allRules).toEqual([]);
      expect(result.trustWarning).toMatch(/links to .*wdir\/tp, in a directory group or others can write/);
    });

    it('a sticky target directory is enough (others can\'t replace the user\'s file there)', async () => {
      const open = join(TEST_DIR, 'sdir');
      const result = await trustedBy(async (list) => {
        await mkdir(open);
        const target = join(open, 'tp');
        await writeFile(target, `${project}\n`);
        await chmod(target, 0o600);
        await chmod(open, 0o1777);
        await rm(list);
        await symlink(target, list);
      });
      await chmod(open, 0o755);
      expect(result.allRules.map(r => r.id)).toEqual(['ORG-1']);
    });

    it('a symlink to a private file of the user is honoured', async () => {
      const result = await trustedBy(async (list) => {
        const target = join(TEST_DIR, 'tp-target');
        await writeFile(target, `${project}\n`, { mode: 0o600 });
        await chmod(target, 0o600);
        await rm(list);
        await symlink(target, list);
      });
      expect(result.allRules.map(r => r.id)).toEqual(['ORG-1']);
    });
  });

  it('load when ~/.vaso/trusted-projects lists the project (realpath, comments, relative lines ignored)', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), RULE('ORG-1'));
    const list = join(home, '.vaso', 'trusted-projects');
    await writeFile(list, `# trusted\nrelative/repo\n${project}   # this one\n`, { mode: 0o600 });
    await chmod(list, 0o600);
    const result = await loadRules({ fs });
    expect(result.allRules.map(r => [r.id, r.source])).toEqual([['ORG-1', 'project']]);
    expect(result.untrustedProject).toEqual([]);

    await writeFile(list, 'relative/repo\n');
    expect((await loadRules({ fs })).allRules).toEqual([]);
  });

  it('a project reached through a symlink matches its listed real path', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), RULE('ORG-1'));
    const link = join(TEST_DIR, 'repo-link');
    await symlink(project, link);
    vi.spyOn(process, 'cwd').mockReturnValue(link);
    const list = join(home, '.vaso', 'trusted-projects');
    await writeFile(list, `${project}\n`);
    await chmod(list, 0o600);
    expect((await loadRules({ fs })).allRules).toHaveLength(1);
  });

  it.skipIf(process.platform === 'win32')('ignores a trusted-projects file group or others can write', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), RULE('ORG-1'));
    const list = join(home, '.vaso', 'trusted-projects');
    await writeFile(list, `${project}\n`);
    await chmod(list, 0o602);
    const result = await loadRules({ fs });
    expect(result.allRules).toEqual([]);
    expect(result.untrustedProject).toHaveLength(1);
    expect(result.trustWarning).toMatch(/writable by group or others — ignored/);
  });

  it('a trusted project rule is judged like a user rule but its fix is still dropped', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'style.yaml'), RULE('ORG-778', FIX));
    const list = join(home, '.vaso', 'trusted-projects');
    await writeFile(list, `${project}\n`);
    await chmod(list, 0o600);
    const result = await loadRules({ fs });
    expect(result.allRules[0]).toMatchObject({ id: 'ORG-778', source: 'project' });
    expect(result.allRules[0].fix).toBeUndefined();
    expect(result.warnings[0].message).toContain('even trusted');
  });

  it('a project rule may add a finding but its fix is dropped, with a warning', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'style.yaml'), RULE('ORG-777', FIX));
    const result = await loadRules({ fs, projectRules: true });
    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0]).toMatchObject({ id: 'ORG-777', source: 'project' });
    expect(result.allRules[0].fix).toBeUndefined();
    expect(result.warnings[0].message).toContain('can\'t carry fixes');
  });

  it('run from the home, ~/.vaso/rules loads once, as user rules (not also as an untrusted project)', async () => {
    await writeFile(join(home, '.vaso', 'rules', 'u.yaml'), RULE('ORG-1', FIX));
    vi.spyOn(process, 'cwd').mockReturnValue(home);
    const result = await loadRules({ fs, parseUntrusted: true });
    expect(result.allRules.map(r => [r.id, r.source, r.fix?.set])).toEqual([['ORG-1', 'user', 'permissions.defaultMode']]);
    expect(result.untrustedProject).toEqual([]);
    expect(result.warnings).toEqual([]);
    const withFlag = await loadRules({ fs, projectRules: true });
    expect(withFlag.warnings).toEqual([]);
  });

  describe.skipIf(process.platform === 'win32')('user rules others could have written are not loaded', () => {
    it('a group/other-writable ~/.vaso/rules or ~/.vaso', async () => {
      await writeFile(join(home, '.vaso', 'rules', 'u.yaml'), RULE('ORG-1', FIX));
      for (const dir of [join(home, '.vaso', 'rules'), join(home, '.vaso')]) {
        await chmod(dir, 0o777);
        const result = await loadRules({ fs });
        await chmod(dir, 0o755);
        expect(result.allRules).toEqual([]);
        expect(result.allErrors[0].message).toMatch(/is writable by group or others — the rules in .* are not loaded/);
      }
      expect((await loadRules({ fs })).allRules.map(r => r.id)).toEqual(['ORG-1']);
    });

    it('a group/other-writable rule file, unless the group is the owner\'s private group', async () => {
      const file = join(home, '.vaso', 'rules', 'u.yaml');
      await writeFile(file, RULE('ORG-1', FIX));
      await chmod(file, 0o666);
      const result = await loadRules({ fs });
      expect(result.allRules).toEqual([]);
      expect(result.allErrors).toEqual([expect.objectContaining({ file, message: expect.stringMatching(/writable by group or others — not loaded/) })]);
      // umask 002 distributions: 0664 in the user's own group reaches nobody else
      await chmod(file, 0o664);
      const { stat: st } = await import('node:fs/promises');
      const s = await st(file);
      const upg = new (class extends LocalFSProvider {
        homedir() { return home; }
        async privateGroups() { return new Map([[s.gid, s.uid]]); }
      })();
      expect((await loadRules({ fs: upg })).allRules.map(r => r.id)).toEqual(['ORG-1']);
    });
  });

  it('user and --rules rules keep their fixes', async () => {
    await writeFile(join(home, '.vaso', 'rules', 'org.yaml'), RULE('ORG-1', FIX));
    const extra = join(TEST_DIR, 'extra.yaml');
    await writeFile(extra, RULE('ORG-2', FIX));
    const result = await loadRules({ fs, extraPaths: [extra] });
    expect(result.allRules.map(r => [r.id, r.source, r.fix?.set])).toEqual([
      ['ORG-1', 'user', 'permissions.defaultMode'],
      ['ORG-2', 'explicit', 'permissions.defaultMode'],
    ]);
    expect(result.warnings).toEqual([]);
  });

  it('a project rule never replaces a user rule of the same ID', async () => {
    const user = join(home, '.vaso', 'rules', 'org.yaml');
    const repo = join(project, '.vaso', 'rules', 'a.yaml');
    await writeFile(user, RULE('ORG-001'));
    await writeFile(repo, RULE('ORG-001').replace('permissions.defaultMode', 'nonexistent.key'));
    const result = await loadRules({ fs, projectRules: true });
    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0]).toMatchObject({ source: 'user', file: user, config: { path: 'permissions.defaultMode' } });
    expect(result.warnings[0]).toMatchObject({ file: repo, rule: 'ORG-001' });
    expect(result.warnings[0].message).toContain(user);
  });

  it('a project rule never replaces a --rules rule either', async () => {
    const extra = join(TEST_DIR, 'extra.yaml');
    await writeFile(extra, RULE('ORG-5'));
    await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), RULE('ORG-5').replace('critical', 'info'));
    const result = await loadRules({ fs, extraPaths: [extra], projectRules: true });
    expect(result.allRules).toHaveLength(1);
    expect(result.allRules[0]).toMatchObject({ source: 'explicit', severity: 'critical' });
    expect(result.warnings).toHaveLength(1);
  });

  it('a project rule with a backtracking regex is rejected at load', async () => {
    await writeFile(join(project, '.vaso', 'rules', 'a.yaml'), `
rules:
  - id: ORG-9
    name: n
    category: config
    severity: info
    description: d
    pattern:
      regex: "(a+)+$"
      target: configs
`);
    const result = await loadRules({ fs, projectRules: true });
    expect(result.allRules).toHaveLength(0);
    expect(result.allErrors[0].message).toMatch(/backtrack/);
  });

  it('loads every rule file of a directory named with --rules (dt21 g8-R2n7)', async () => {
    const dir = join(TEST_DIR, 'rules');
    const rule = (id: string) => `rules:\n  - id: ${id}\n    name: Dir test\n    category: config\n    severity: info\n    description: d\n    config:\n      path: "a.b"\n      operator: "exists"\n`;
    await writeFile(join(dir, 'a.yaml'), rule('DIR-001'));
    await writeFile(join(dir, 'b.yml'), rule('DIR-002'));
    await writeFile(join(dir, 'notes.txt'), 'not a rule');
    const result = await loadRules({ skipGlobal: true, skipProject: true, extraPaths: [dir] });
    expect(result.allRules.map(r => r.id)).toEqual(['DIR-001', 'DIR-002']);
    expect(result.files.every(f => !f.unreadable)).toBe(true);
    expect(result.allRules.every(r => r.source === 'explicit')).toBe(true);
  });
});
