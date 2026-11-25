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
  it('os.exec* is direct: a fixed program is info, a runtime-found interpreter a warning; os.system stays critical', async () => {
    const fixed = await run(skl003, {
      'scripts/check.py': 'import os, sys\ndef again(argv):\n    os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)] + argv)\n',
    });
    expect(live(fixed)).toEqual([]);
    const reexec = await run(skl003, {
      'scripts/check.py': 'import os, sys\ndef again(py, argv):\n    os.execv(py, [py, os.path.abspath(__file__)] + argv)\n',
    });
    expect(live(reexec).length).toBe(1);
    expect(reexec.severity).toBe('warning');
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

  it('one caller passing a runtime value: a program chosen at runtime, no shell — warning', async () => {
    const r = await run(skl003, { 'scripts/r.mjs': helper("export function go(bin) { runSync('a', 'ffmpeg', []); runSync('b', bin, []); }") });
    expect(live(r).length).toBe(1);
    expect(r.severity).toBe('warning');
  });

  it('a caller turning the shell on through the options it passes: critical', async () => {
    const r = await run(skl003, { 'scripts/r.mjs': helper("export function go(bin) { runSync('a', bin, [], { shell: true }); }") });
    expect(live(r).length).toBe(1);
    expect(r.severity).toBe('critical');
  });

  it('an exported helper (callers unknown): program chosen at runtime — warning', async () => {
    const r = await run(skl003, {
      'scripts/r.mjs': "import { spawnSync } from 'node:child_process';\nexport function runSync(cmd, args) { return spawnSync(cmd, args); }\nrunSync('git', ['status']);\n",
    });
    expect(live(r).length).toBe(1);
    expect(r.severity).toBe('warning');
  });

  it('a helper passed around as a value (not only called): program chosen at runtime — warning', async () => {
    const r = await run(skl003, {
      'scripts/r.mjs': "import { spawnSync } from 'node:child_process';\nconst run = (cmd) => spawnSync(cmd, []);\nrun('git');\nexport const hooks = [run];\n",
    });
    expect(live(r).length).toBe(1);
    expect(r.severity).toBe('warning');
  });
});

describe('middle tier: a program chosen at runtime, started without a shell, is a warning', () => {
  it('JS: spawnSync(process.argv[2]) is a warning; the same through a shell stays critical', async () => {
    const w = await run(skl003, { 'scripts/a.mjs': "import { spawnSync } from 'node:child_process';\nspawnSync(process.argv[2], ['--version']);\n" });
    expect(live(w).length).toBe(1);
    expect(w.severity).toBe('warning');
    const c = await run(skl003, { 'scripts/a.mjs': "import { spawnSync } from 'node:child_process';\nspawnSync(process.argv[2], ['--version'], { shell: true });\n" });
    expect(c.severity).toBe('critical');
    const e = await run(skl003, { 'scripts/a.mjs': "import { execSync } from 'node:child_process';\nexecSync(process.argv[2]);\n" });
    expect(e.severity).toBe('critical');
  });

  it('Python: a runtime program path is a warning; a module constant and sys.executable stay info', async () => {
    const w = await run(skl003, { 'scripts/a.py': 'import subprocess, sys\ndef go(path):\n    subprocess.run([path, "--version"])\n' });
    expect(live(w).length).toBe(1);
    expect(w.severity).toBe('warning');
    const k = await run(skl003, { 'scripts/a.py': 'import subprocess, sys\nFFMPEG = "ffmpeg"\ndef go(src):\n    subprocess.run([FFMPEG, "-i", src])\n    subprocess.run([sys.executable, "-m", "pip", "--version"])\n' });
    expect(live(k)).toEqual([]);
    const sh = await run(skl003, { 'scripts/a.py': 'import subprocess\ndef go(cmd):\n    subprocess.run(cmd, shell=True)\n' });
    expect(sh.severity).toBe('critical');
  });

  it('a downloaded or decoded program stays critical whatever runs it', async () => {
    const r = await run(skl003, { 'scripts/a.mjs': "import { spawnSync } from 'node:child_process';\nspawnSync(Buffer.from('L2Jpbi9zaA==', 'base64').toString(), []);\n" });
    expect(r.severity).toBe('critical');
  });
});

describe('Python: a helper\'s argv parameter is judged by what its callers pass', () => {
  const helper = 'import subprocess, sys\nFF = ["ffmpeg", "-hide_banner"]\ndef run(cmd, binary=False):\n    return subprocess.run(cmd, capture_output=True)\n';

  it('callers passing literal lists, FF + [...] or sys.executable: info', async () => {
    const r = await run(skl003, { 'scripts/m.py': helper + 'def probe(p):\n    run(["ffprobe", "-v", "error", p])\n    run(FF + ["-i", p])\n    run([sys.executable, "-m", "pip"])\n' });
    expect(r.evidence?.length).toBe(1);
    expect(live(r)).toEqual([]);
  });

  it('one caller passing a program found at runtime: warning', async () => {
    const r = await run(skl003, { 'scripts/m.py': helper + 'def probe(ff, p):\n    run(["ffprobe", p])\n    run([ff, "-version"])\n' });
    expect(live(r).length).toBe(1);
    expect(r.severity).toBe('warning');
  });

  it('a helper nothing in the file calls, or one passed around as a value: warning', async () => {
    expect((await run(skl003, { 'scripts/m.py': helper })).severity).toBe('warning');
    const r = await run(skl003, { 'scripts/m.py': helper + 'HANDLERS = [run]\nrun(["git", "status"])\n' });
    expect(r.severity).toBe('warning');
  });
});

