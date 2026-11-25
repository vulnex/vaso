import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, CheckResult } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { classifySensitiveRead } from '../../analyzers/sensitive-paths.js';
import { skl003 } from './skl-003-eval-exec.js';
import { skl006 } from './skl-006-credential-harvesting.js';
import { skl010 } from './skl-010-unauthorized-fs.js';

// 1.4.4 precision fixes, found auditing Meta Muse Code's bundled skills:
// reading /etc/os-release is not credential harvesting, os.exec* never uses a
// shell, and a local helper's program parameter is what its callers pass.
// Each benign shape has a risky twin that must stay reported.

let dir: string;
const ctx = (): ScanContext => ({
  installation: { agent: 'openclaw', installDir: dir, configFiles: [], skillsDir: dir },
  configs: [], platform: 'linux', fs: new LocalFSProvider(),
});
async function run(check: { run: (c: ScanContext) => Promise<CheckResult> }, files: Record<string, string>): Promise<CheckResult> {
  await rm(join(dir, 'skill'), { recursive: true, force: true });
  for (const [name, text] of Object.entries(files)) {
    await mkdir(join(dir, 'skill', name, '..'), { recursive: true });
    await writeFile(join(dir, 'skill', name), text);
  }
  return check.run(ctx());
}
const live = (r: CheckResult) => (r.evidence ?? []).filter(e => !e.mitigated);

beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-144-')); });
afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

describe('reads under /etc: only secret and account files are sensitive', () => {
  it('classifySensitiveRead keeps /etc secrets, drops OS description files', () => {
    for (const p of ['/etc/os-release', '/etc/timezone', '/etc/hostname', '/etc/lsb-release', '/etc/machine-id']) {
      expect(classifySensitiveRead(p), p).toEqual([]);
    }
    for (const p of ['/etc/shadow', '/etc/passwd', '/etc/sudoers', '/etc/sudoers.d/ops', '/etc/ssh/ssh_host_ed25519_key', '/etc/ssl/private/site.key', '/etc/krb5.keytab']) {
      expect(classifySensitiveRead(p).length, p).toBeGreaterThan(0);
    }
    // Other sinks are unchanged
    expect(classifySensitiveRead('/home/u/.ssh/id_rsa').length).toBeGreaterThan(0);
  });

  it('Python: open("/etc/os-release") passes SKL-006/010; open("/etc/shadow") stays critical', async () => {
    const benign = { 'scripts/new.py': 'def distro():\n    with open("/etc/os-release", encoding="utf-8") as fh:\n        return fh.read()\n' };
    expect((await run(skl006, benign)).passed).toBe(true);
    expect((await run(skl010, benign)).passed).toBe(true);
    const risky = { 'scripts/grab.py': 'def grab():\n    with open("/etc/shadow") as fh:\n        return fh.read()\n' };
    const r = await run(skl006, risky);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });
});

describe('Python os.exec* / os.spawn* never use a shell', () => {
  it('re-executing the script under another interpreter is info; os.system stays critical', async () => {
    const reexec = await run(skl003, {
      'scripts/check.py': 'import os, sys\ndef again(py, argv):\n    os.execv(py, [py, os.path.abspath(__file__)] + argv)\n',
    });
    expect(live(reexec)).toEqual([]);
    const system = await run(skl003, { 'scripts/x.py': 'import os\ndef go(cmd):\n    os.system(cmd)\n' });
    expect(system.severity).toBe('critical');
    expect(live(system).length).toBe(1);
  });

  it('os.execv of a shell, or an interpreter given -c, is not "direct"', async () => {
    const sh = await run(skl003, { 'scripts/x.py': 'import os\ndef go(cmd):\n    os.execv("/bin/sh", ["sh", "-c", cmd])\n' });
    expect(live(sh).length).toBe(1);
  });
});

describe('JS: a local helper\'s program parameter is what its callers pass', () => {
  const helper = (calls: string, opts = '{ ...opts, timeout: 1000 }') => [
    "import { spawnSync } from 'node:child_process';",
    `function runSync(step, cmd, args, opts) { return spawnSync(cmd, args, ${opts}); }`,
    calls,
  ].join('\n');

  it('every caller passing a fixed tool: info', async () => {
    const r = await run(skl003, { 'scripts/r.mjs': helper("export function go() { runSync('a', 'ffmpeg', ['-version'], { encoding: 'utf8' }); runSync('b', 'npm', ['--version']); }") });
    expect(r.evidence?.length).toBe(1);
    expect(live(r)).toEqual([]);
  });

  it('one caller passing a runtime value: still critical', async () => {
    const r = await run(skl003, { 'scripts/r.mjs': helper("export function go(bin) { runSync('a', 'ffmpeg', []); runSync('b', bin, []); }") });
    expect(live(r).length).toBe(1);
    expect(r.severity).toBe('critical');
  });

  it('a caller turning the shell on through the options it passes: critical', async () => {
    const r = await run(skl003, { 'scripts/r.mjs': helper("export function go() { runSync('a', 'ffmpeg', [], { shell: true }); }") });
    expect(live(r).length).toBe(1);
  });

  it('an exported helper (callers unknown): critical', async () => {
    const r = await run(skl003, {
      'scripts/r.mjs': "import { spawnSync } from 'node:child_process';\nexport function runSync(cmd, args) { return spawnSync(cmd, args); }\nrunSync('git', ['status']);\n",
    });
    expect(live(r).length).toBe(1);
  });

  it('a helper passed around as a value (not only called): critical', async () => {
    const r = await run(skl003, {
      'scripts/r.mjs': "import { spawnSync } from 'node:child_process';\nconst run = (cmd) => spawnSync(cmd, []);\nrun('git');\nexport const hooks = [run];\n",
    });
    expect(live(r).length).toBe(1);
  });
});
