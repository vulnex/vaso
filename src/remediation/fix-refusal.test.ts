import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, symlink, link, chmod, rm, realpath, stat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { ScanEngine } from '../core/engine.js';
import { CheckRegistry } from '../core/check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import { defineCheck } from '../core/check-builder.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import type { CheckResult, ScanContext } from '../core/types.js';
import { fixRefusal, fixHomeOf, markRefusedFix, permissionFixTargets, configFixTargets, shellQuote, codeSpan } from './fix-refusal.js';
import { RemediationEngine } from './engine.js';

/** A local provider whose home is a temporary directory. */
class HomeFS extends LocalFSProvider {
  constructor(private home: string) { super(); }
  override homedir(): string { return this.home; }
}

const posix = process.platform !== 'win32';

describe.skipIf(!posix)('fixRefusal', () => {
  let root: string;
  let home: string;
  let outside: string;
  let fs: HomeFS;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-refusal-')));
    home = join(root, 'home');
    outside = join(root, 'data');
    await mkdir(home);
    await mkdir(outside);
    fs = new HomeFS(home);
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it('accepts a regular file or folder inside the home', async () => {
    await writeFile(join(home, 'a.json'), '{}');
    expect(await fixRefusal(join(home, 'a.json'), fs, { home })).toBeUndefined();
    expect(await fixRefusal(home, fs, { home })).toBeUndefined();
  });

  it('refuses a file outside the home', async () => {
    await writeFile(join(outside, 'auth.json'), '{}');
    expect(await fixRefusal(join(outside, 'auth.json'), fs, { home })).toMatchObject({ kind: 'outside', reason: 'is outside the home' });
  });

  it('refuses a symlink, wherever it points (a fix never writes through one)', async () => {
    await writeFile(join(home, 'real.json'), '{}');
    await symlink(join(home, 'real.json'), join(home, 'link.json'));
    await symlink(join(home, 'nowhere'), join(home, 'dangling.json'));
    expect(await fixRefusal(join(home, 'link.json'), fs, { home })).toMatchObject({ kind: 'symlink', reason: 'is a symlink' });
    expect(await fixRefusal(join(home, 'dangling.json'), fs, { home })).toMatchObject({ kind: 'symlink' });
  });

  it('refuses a file whose folder is a link out of the home', async () => {
    await writeFile(join(outside, 'auth.json'), '{}');
    await symlink(outside, join(home, '.codex'));
    const r = await fixRefusal(join(home, '.codex', 'auth.json'), fs, { home });
    expect(r).toMatchObject({ kind: 'through-link' });
    expect(r && r !== 'none' && r.reason).toContain(`resolves into ${outside}`);
  });

  it('refuses a file a linked folder takes into a credential store, but not one written at its own path there', async () => {
    await mkdir(join(home, '.aws', 'cop'), { recursive: true });
    await writeFile(join(home, '.aws', 'cop', 'session-store.db'), 'x');
    await writeFile(join(home, '.aws', 'credentials'), 'x');
    await symlink(join(home, '.aws', 'cop'), join(home, '.copilot'));
    const r = await fixRefusal(join(home, '.copilot', 'session-store.db'), fs, { home });
    expect(r).toMatchObject({ kind: 'sensitive', reason: 'is reached through a symlink into AWS credentials (~/.aws)' });
    // the folder link itself, as a target
    expect(await fixRefusal(join(home, '.copilot'), fs, { home })).toMatchObject({ kind: 'symlink' });
    // written where it is: fixed (a permission fix of ~/.aws/credentials by its own path)
    expect(await fixRefusal(join(home, '.aws', 'credentials'), fs, { home })).toBeUndefined();
    expect(await fixRefusal(join(home, '.aws', 'cop', 'session-store.db'), fs, { home })).toBeUndefined();
    // the home itself linked into nothing sensitive is fine
    await mkdir(join(home, '.ssh'));
    await writeFile(join(home, '.ssh', 'picoclaw_ed25519.key'), 'k');
    expect(await fixRefusal(join(home, '.ssh', 'picoclaw_ed25519.key'), fs, { home })).toBeUndefined();
  });

  it('accepts a file behind a folder link that stays in the home', async () => {
    await mkdir(join(home, 'dotfiles'));
    await writeFile(join(home, 'dotfiles', 'c.json'), '{}');
    await symlink(join(home, 'dotfiles'), join(home, '.agent'));
    expect(await fixRefusal(join(home, '.agent', 'c.json'), fs, { home })).toBeUndefined();
  });

  it('refuses a hard-linked file and a FIFO', async () => {
    await writeFile(join(home, 'a.json'), '{}');
    await link(join(home, 'a.json'), join(home, 'b.json'));
    expect(await fixRefusal(join(home, 'a.json'), fs, { home })).toMatchObject({ kind: 'hard-link', reason: 'has 2 hard links' });
    execFileSync('mkfifo', [join(home, 'pipe')]);
    expect(await fixRefusal(join(home, 'pipe'), fs, { home })).toMatchObject({ kind: 'special' });
  });

  it('treats a missing file or something that is not a path as no target', async () => {
    expect(await fixRefusal(join(home, 'missing.json'), fs, { home })).toBe('none');
    expect(await fixRefusal('ps', fs, { home })).toBe('none');
  });

  it('confines an install outside every home to the scanning user\'s home', async () => {
    expect(await fixHomeOf(join(outside, 'codex'), fs)).toBe(home);
    expect(await fixHomeOf(join(home, '.codex'), fs)).toBe(home);
  });
});

describe.skipIf(!posix)('markRefusedFix', () => {
  let root: string;
  let home: string;
  let fs: HomeFS;
  const ctx = (configs: string[] = []): ScanContext => ({
    installation: { agent: 'codex', installDir: join(home, '.codex'), configFiles: [] },
    configs: configs.map(filePath => ({ raw: '', format: 'json' as const, filePath, data: {} })),
    platform: process.platform,
    fs,
  });
  const result = (files: string[], extra: Partial<CheckResult> = {}): CheckResult => ({
    id: 'TST-001', name: 't', category: 'config', severity: 'warning', passed: false,
    message: 'auth.json is over-permissive', fixable: true, fixDescription: 'chmod it',
    evidence: files.map(file => ({ file, snippet: 'mode 0644' })), ...extra,
  });

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-refusal-')));
    home = join(root, 'home');
    await mkdir(join(root, 'data'), { recursive: true });
    await mkdir(home);
    fs = new HomeFS(home);
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it('clears fixable when every target is refused, says why and gives the chmod command', async () => {
    const out = join(root, 'data', 'auth.json');
    await writeFile(out, '{}');
    const r = await markRefusedFix({ fixTargets: permissionFixTargets }, ctx(), result([out]), { home });
    expect(r.fixable).toBe(false);
    expect(r.message).toBe(`auth.json is over-permissive; not changed by vaso fix: ${out} is outside the home`);
    expect(r.fixDescription).toContain(`chmod go-rwx ${out}`);
  });

  it('keeps a partly refusable finding fixable and names what the fix leaves', async () => {
    const inside = join(home, 'a.json');
    await writeFile(inside, '{}');
    await symlink(inside, join(home, 'k.json'));
    const r = await markRefusedFix({ fixTargets: permissionFixTargets }, ctx(), result([inside, join(home, 'k.json')]), { home });
    expect(r.fixable).toBe(true);
    expect(r.fixDescription).toBe('chmod it');
    expect(r.message).toBe(`auth.json is over-permissive; not changed by vaso fix: ${join(home, 'k.json')} is a symlink`);
  });

  it('leaves a finding alone when nothing is refused or nothing can be judged', async () => {
    await writeFile(join(home, 'a.json'), '{}');
    const ok = result([join(home, 'a.json')]);
    expect(await markRefusedFix({ fixTargets: permissionFixTargets }, ctx(), ok, { home })).toBe(ok);
    const unknown = result(['env:FOO', join(home, 'missing')]);
    expect(await markRefusedFix(undefined, ctx(), unknown, { home })).toBe(unknown);
  });

  it('a config fix counts only the installation\'s config files', async () => {
    const out = join(root, 'data', 'managed.json');
    const cfg = join(home, 'config.json');
    await writeFile(out, '{}');
    await writeFile(cfg, '{}');
    // The outside file is not a config the fix writes: nothing to judge
    expect(configFixTargets(ctx([cfg]), result([out]))).toBeUndefined();
    await symlink(cfg, join(home, 'linked.json'));
    const r = await markRefusedFix({ fixTargets: configFixTargets }, ctx([join(home, 'linked.json')]), result([join(home, 'linked.json'), out]), { home });
    expect(r.fixable).toBe(false);
    expect(r.fixDescription).toBe(`chmod it — make this change by hand in ${join(home, 'linked.json')}: vaso fix changes only regular files and folders inside the home (where its backup can restore them), never through a symlink or a hard link`);
  });

  it('gives a copy-paste command for odd names: shell-quoted, no raw control character, a code span that holds backticks', async () => {
    const odd = join(root, 'data', "a'b $(touch PWNED) `id`\n;x.json");
    await writeFile(odd, '{}');
    const r = await markRefusedFix({ fixTargets: permissionFixTargets }, ctx(), result([odd]), { home });
    const dir = join(root, 'data');
    expect(r.fixDescription).toContain(`\`\` chmod go-rwx $'${dir}/a\\'b $(touch PWNED) \`id\`\\n;x.json' \`\``);
    // eslint-disable-next-line no-control-regex
    expect(r.fixDescription).not.toMatch(/[\x00-\x1f]/);
    expect(shellQuote("a'b")).toBe(`'a'\\''b'`);
    expect(shellQuote('/home/u/a b')).toBe(`'/home/u/a b'`);
    expect(shellQuote('/home/u/a\tb\\c')).toBe(`$'/home/u/a\\tb\\\\c'`);
    expect(codeSpan('chmod x')).toBe('`chmod x`');
    expect(codeSpan('a ``b`` c')).toBe('``` a ``b`` c ```');
  });

  it('a folded result loses the fix without a note in its passing message', async () => {
    const out = join(root, 'data', 'auth.json');
    await writeFile(out, '{}');
    const folded = result([out], { passed: true, foldedInto: 'CDX-003', message: 'Reported by CDX-003' });
    const r = await markRefusedFix(undefined, ctx(), folded, { home });
    expect(r).toMatchObject({ fixable: false, message: 'Reported by CDX-003' });
  });

  it('a partly refused folded result keeps its fix and notes what it leaves in its fix description', async () => {
    const inside = join(home, 'a.json');
    await writeFile(inside, '{}');
    await symlink(inside, join(home, 'k.json'));
    const folded = result([inside, join(home, 'k.json')], { passed: true, foldedInto: 'HM-003', message: 'Reported by HM-003' });
    const r = await markRefusedFix({ fixTargets: permissionFixTargets }, ctx(), folded, { home });
    expect(r).toMatchObject({ fixable: true, message: 'Reported by HM-003' });
    expect(r.fixDescription).toBe(`chmod it; not changed by vaso fix: ${join(home, 'k.json')} is a symlink`);
  });
});

describe('fix families', () => {
  it('every built-in check with a fix says what it changes', async () => {
    const { registerAllChecks } = await import('../checks/index.js');
    const { checkRegistry } = await import('../core/check-registry.js');
    registerAllChecks();
    const all = checkRegistry.getAll();
    expect(all.filter(c => c.fix).length).toBeGreaterThan(40);
    expect(all.filter(c => c.fix && !c.fixTargets).map(c => c.id)).toEqual([]);
  });
});

describe.skipIf(!posix)('scan and fix agree on refused fixes', () => {
  let root: string;
  let home: string;
  let installDir: string;

  beforeEach(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-refusal-')));
    home = join(root, 'home');
    installDir = join(root, 'data', 'codex');
    await mkdir(home);
    await mkdir(installDir, { recursive: true });
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  function setup(fs: HomeFS) {
    const adapters = new AdapterRegistry();
    const adapter: AgentAdapter = {
      agent: 'codex', displayName: 'Codex',
      async detect() { return [{ agent: 'codex', installDir, configFiles: [] }]; },
      getConfigPaths() { return []; },
      getSkillsDir() { return undefined; },
      getGatewayInfo() { return undefined; },
    };
    adapters.register(adapter);
    const checks = new CheckRegistry();
    const auth = join(installDir, 'auth.json');
    checks.register(defineCheck({
      id: 'TST-PERM', name: 'perm', category: 'coding-agent', severity: 'warning', description: 'perm',
      supportedAgents: ['codex'],
      fixTargets: permissionFixTargets,
      async run(_c, h) {
        const mode = (await stat(auth)).mode & 0o077;
        return h.fromEvidence(mode ? [{ file: auth, snippet: 'mode 0644' }] : [], {
          passed: 'ok', failed: () => 'auth.json is over-permissive', fixable: true, fixDescription: 'chmod go-rwx auth.json',
        });
      },
      async fix() { return { checkId: 'TST-PERM', applied: false, message: 'should not run' }; },
    }));
    return new ScanEngine(adapters, checks, fs);
  }

  it('an install outside the home is not offered to vaso fix', async () => {
    await writeFile(join(installDir, 'auth.json'), '{}');
    await chmod(join(installDir, 'auth.json'), 0o644);
    const result = await setup(new HomeFS(home)).scan({});
    const r = result.agents[0].results.find(x => x.id === 'TST-PERM')!;
    expect(r).toMatchObject({ passed: false, fixable: false });
    expect(r.message).toContain(`not changed by vaso fix: ${join(installDir, 'auth.json')} is outside the home`);
    // …so the remediation engine has nothing to run
    const fixes = await new RemediationEngine(new CheckRegistry()).fix(result, { yes: true });
    expect(fixes).toEqual([]);
  });
});
