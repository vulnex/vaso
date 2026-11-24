import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { chmod, copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

/**
 * Remote scans against a fake `ssh`/`scp` on PATH: the "host" prints what a
 * hostile or compromised machine could send as probe output, and ssh writes
 * a host-key notice to stderr the way the real one does on first contact.
 * The CLI runs from a copy of dist/ whose probe/dist holds a stand-in probe
 * (a local build wins over the download, so nothing is fetched).
 */
const PROJECT_ROOT = resolve(import.meta.dirname, '../..');
const SSH_NOTICE = "Warning: Permanently added 'fake.test' (ED25519) to the list of known hosts.";

const FAKE_SSH = `#!/bin/sh
last=""
for a in "$@"; do last="$a"; done
case "$last" in
  -N) echo "${SSH_NOTICE}" >&2; exit 0 ;;
  "uname -s && uname -m") printf 'Linux\\nx86_64\\n'; exit 0 ;;
  *"mktemp -d"*) [ -n "$FAKE_MKTEMP_FAIL" ] && exit 0; echo /tmp/vaso-probe.FakeHost123; exit 0 ;;
  *--manifest*) cat "$FAKE_PROBE_OUT"; exit 0 ;;
esac
exit 0
`;

describe.skipIf(process.platform === 'win32')('E2E: remote probe output is validated like a snapshot file', () => {
  let root: string;
  let bin: string;

  beforeAll(async () => {
    // Under node_modules so the copied bundle still resolves its dependencies
    await mkdir(join(PROJECT_ROOT, 'node_modules', '.cache'), { recursive: true });
    root = await mkdtemp(join(PROJECT_ROOT, 'node_modules', '.cache', 'vaso-e2e-remote-'));
    await cp(join(PROJECT_ROOT, 'dist'), join(root, 'dist'), { recursive: true });
    await copyFile(join(PROJECT_ROOT, 'package.json'), join(root, 'package.json'));
    await mkdir(join(root, 'probe', 'dist'), { recursive: true });
    await writeFile(join(root, 'probe', 'dist', 'vaso-probe-linux-amd64'), '#!/bin/sh\n');
    bin = join(root, 'bin');
    await mkdir(bin);
    await writeFile(join(bin, 'ssh'), FAKE_SSH);
    await writeFile(join(bin, 'scp'), '#!/bin/sh\nexit 0\n');
    await chmod(join(bin, 'ssh'), 0o755);
    await chmod(join(bin, 'scp'), 0o755);
    await mkdir(join(root, 'home'));
  }, 60_000);

  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  async function scanWith(probeOutput: string, scanArgs: string[], globalArgs: string[] = [], extraEnv: Record<string, string> = {}) {
    const out = join(root, `probe-out-${Math.random().toString(36).slice(2)}.txt`);
    await writeFile(out, probeOutput);
    return new Promise<{ exitCode: number; stderr: string; stdout: string }>((done, fail) => {
      const child = spawn(process.execPath, [join(root, 'dist', 'cli.js'), ...globalArgs, 'scan', '--host', 'u@fake.test', '--ssh-timeout', '5', ...scanArgs], {
        cwd: join(root, 'home'),
        env: { ...process.env, HOME: join(root, 'home'), PATH: `${bin}:${process.env.PATH}`, FAKE_PROBE_OUT: out, NO_COLOR: '1', VASO_SKIP_IOC_UPDATE: '1', ...extraEnv },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      child.on('error', fail);
      child.on('close', code => done({ exitCode: code ?? 1, stderr, stdout }));
    });
  }

  const valid = JSON.stringify({ version: 1, platform: 'linux', hostname: 'fake', homedir: '/home/u', files: {}, directories: {}, commandOutputs: {} });

  it.each([
    ['not JSON', 'Segmentation fault\n', /not valid JSON/],
    ['wrong shape', JSON.stringify({ version: 1, platform: 'linux', hostname: 'h', homedir: '/home/u', files: [], directories: {}, commandOutputs: {} }), /invalid files field/i],
    ['bad file entries', JSON.stringify({ version: 1, platform: 'linux', hostname: 'h', homedir: 'rel', files: { '/x': { content: 1, mode: 'rw', exists: 'yes' } }, directories: {}, commandOutputs: {} }), /relative homedir.*not \{content, mode, exists\}/],
  ])('%s → host not scanned, exit 3', async (_name, output, why) => {
    const run = await scanWith(output, []);
    expect(run.exitCode).toBe(3);
    expect(run.stderr).toMatch(/u@fake\.test returned unusable probe output, host not scanned/);
    expect(run.stderr).toMatch(why);
  }, 60_000);

  // dt25 g9-F1: nothing is uploaded unless the target made a private directory
  it('a host that cannot make a private temp directory is not scanned, exit 3', async () => {
    const run = await scanWith(valid, [], [], { FAKE_MKTEMP_FAIL: '1' });
    expect(run.exitCode).toBe(3);
    expect(run.stderr).toMatch(/could not create a private temporary directory for the probe/);
  }, 60_000);

  it('valid probe output scans', async () => {
    const run = await scanWith(valid, []);
    expect(run.exitCode).not.toBe(3);
    expect(run.stderr).not.toMatch(/unusable probe output/);
  }, 60_000);

  it("--silent keeps ssh's own stderr off the terminal; the report still records the failure", async () => {
    const report = join(root, 'silent.json');
    const run = await scanWith('nope', ['-f', 'json', '-o', report, '--silent']);
    expect(run.exitCode).toBe(3);
    expect(run.stderr).not.toContain('Permanently added');
    expect(await readFile(report, 'utf-8')).toContain('unusable probe output');
  }, 60_000);

  it("without --silent ssh's notice is shown, and --silent --debug shows it too", async () => {
    expect((await scanWith(valid, [])).stderr).toContain('Permanently added');
    const report = join(root, 'debug.json');
    const run = await scanWith(valid, ['-f', 'json', '-o', report, '--silent'], ['--debug']);
    expect(run.stderr).toContain('Permanently added');
  }, 60_000);
});
