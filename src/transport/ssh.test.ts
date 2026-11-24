import { describe, it, expect, vi } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { assertDistinctLabels, assertIdentityFiles, describeConnectFailure, executeRemoteProbe, makePrivateLocalDir, parseProbeOutput, parseRemoteTempDir, parseSSHTarget, uniqueTargets, withRetry } from './ssh.js';

describe('parseProbeOutput', () => {
  const target = { user: 'u', host: 'h.test' };
  const valid = { version: 1, platform: 'linux', hostname: 'h', homedir: '/home/u', files: {}, directories: {}, commandOutputs: {} };

  it('accepts what a probe prints', () => {
    expect(parseProbeOutput(JSON.stringify(valid), target).hostname).toBe('h');
  });

  it('holds remote output to the snapshot-file checks, as one escaped line', () => {
    expect(() => parseProbeOutput('null', target)).toThrow(/u@h\.test returned unusable probe output, host not scanned — Invalid probe output: Snapshot is not a JSON object/);
    expect(() => parseProbeOutput('{"a":', target)).toThrow(/not valid JSON/);
    const big = 'a'.repeat(48 * 1024 * 1024 + 1);
    expect(() => parseProbeOutput(JSON.stringify({ ...valid, files: { '/x': { content: big, mode: 0o644, exists: true } } }), target)).toThrow(/per-file limit/);
    let message = '';
    try {
      parseProbeOutput(JSON.stringify({ ...valid, files: { '/a\n\u001b]0;pwned\u0007': { content: big, mode: 0o644, exists: true } } }), target);
    } catch (err) { message = (err as Error).message; }
    expect(message).not.toMatch(/[\n\u001b\u0007]/);
    expect(message).toContain('\\x1b');
  });
});

describe('parseSSHTarget', () => {
  it('rejects an empty user, option-like parts and control characters', () => {
    expect(() => parseSSHTarget('@192.0.2.1')).toThrow(/missing user/);
    expect(() => parseSSHTarget('-oProxyCommand=x@192.0.2.1')).toThrow(/may not start with "-"/);
    expect(() => parseSSHTarget('u@-oProxyCommand=x')).toThrow(/may not start with "-"/);
    expect(() => parseSSHTarget('u ser@host')).toThrow(/whitespace/);
    expect(() => parseSSHTarget('u@192.0.2.1:99999')).toThrow(/port must be/);
    expect(() => parseSSHTarget('u@192.0.2.1:0')).toThrow(/port must be/);
  });

  it('rejects a host that is no host name or address, before ssh runs', () => {
    for (const t of ['u@host;id', 'u@host$(id)', 'u@ho`st', "u@h'x", 'u@host|x']) {
      expect(() => parseSSHTarget(t), t).toThrow(/invalid host/);
    }
    for (const t of ['u@agent-01.example.com', 'u@192.0.2.1', 'u@fe80::1%en0', 'u@[2001:db8::1]:2222', 'u@my_host']) {
      expect(() => parseSSHTarget(t), t).not.toThrow();
    }
  });

  it('dedupes repeated targets', () => {
    const { targets, duplicates } = uniqueTargets([parseSSHTarget('u@h'), parseSSHTarget('u@h:22'), parseSSHTarget('u@h:2222')]);
    expect(targets.map(t => t.port)).toEqual([22, 2222]);
    expect(duplicates).toEqual(['u@h']);
  });

  it('parses user@host with default port 22', () => {
    expect(parseSSHTarget('user@host')).toEqual({
      user: 'user',
      host: 'host',
      port: 22,
      label: 'user@host',
    });
  });

  it('parses user@host:port', () => {
    expect(parseSSHTarget('user@host:2222')).toEqual({
      user: 'user',
      host: 'host',
      port: 2222,
      label: 'user@host:2222',
    });
  });

  it('parses user@ip-address', () => {
    expect(parseSSHTarget('deploy@10.0.0.1')).toEqual({
      user: 'deploy',
      host: '10.0.0.1',
      port: 22,
      label: 'deploy@10.0.0.1',
    });
  });

  it('parses user@ip-address:port', () => {
    expect(parseSSHTarget('deploy@10.0.0.1:22')).toEqual({
      user: 'deploy',
      host: '10.0.0.1',
      port: 22,
      label: 'deploy@10.0.0.1',
    });
  });

  it('omits port from default label when port is 22', () => {
    const t = parseSSHTarget('admin@example.com');
    expect(t.label).toBe('admin@example.com');
  });

  it('includes non-default port in default label', () => {
    const t = parseSSHTarget('admin@example.com:2200');
    expect(t.label).toBe('admin@example.com:2200');
  });

  it('throws when @ is missing', () => {
    expect(() => parseSSHTarget('host')).toThrow('expected user@host[:port]');
  });

  it('throws when @ is missing even with port', () => {
    expect(() => parseSSHTarget('host:2222')).toThrow('expected user@host[:port]');
  });

  it('throws when hostname is empty', () => {
    expect(() => parseSSHTarget('user@')).toThrow('missing hostname');
  });

  it('rejects a colon that is neither a port nor part of an IPv6 address', () => {
    expect(() => parseSSHTarget('user@host:notaport')).toThrow('only valid in an IPv6 address');
    expect(() => parseSSHTarget('root@h:22:22')).toThrow('only valid in an IPv6 address');
    expect(() => parseSSHTarget('root@h:')).toThrow('missing port');
    expect(() => parseSSHTarget('a:b@h')).toThrow('may not contain ":"');
    expect(() => parseSSHTarget('u@fe80::1%')).toThrow('invalid host');
    expect(() => parseSSHTarget('u@host%en0')).toThrow('invalid host');
    expect(parseSSHTarget('u@fe80::1%en0')).toMatchObject({ host: 'fe80::1%en0', port: 22 });
  });

  it('reads IPv6 hosts: bare (no port) and bracketed with a port', () => {
    expect(parseSSHTarget('u@::1')).toMatchObject({ host: '::1', port: 22, label: 'u@::1' });
    expect(parseSSHTarget('u@fe80::1')).toMatchObject({ host: 'fe80::1', port: 22 });
    expect(parseSSHTarget('u@[::1]:1')).toMatchObject({ host: '::1', port: 1, label: 'u@[::1]:1' });
    expect(parseSSHTarget('u@[2001:db8::5]')).toMatchObject({ host: '2001:db8::5', port: 22 });
    expect(() => parseSSHTarget('u@[::1')).toThrow(/ipv6/);
    expect(() => parseSSHTarget('u@[::1]x')).toThrow(/ipv6/);
    expect(() => parseSSHTarget('u@[::1]:0')).toThrow(/port must be/);
  });

  it('rejects port 0 instead of reading "host:0" as a host name', () => {
    expect(() => parseSSHTarget('user@host:0')).toThrow(/port must be/);
  });

  it('uses last colon for port when multiple colons present', () => {
    // IPv6-like or unusual hostname
    const result = parseSSHTarget('user@host:2222');
    expect(result.port).toBe(2222);
    expect(result.host).toBe('host');
  });
});

describe('withRetry', () => {
  const noSleep = async () => {};

  it('returns the value when fn succeeds on first try', async () => {
    const fn = vi.fn().mockResolvedValue('ok');
    const out = await withRetry({ retries: 3, fn, sleep: noSleep });
    expect(out).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on failure and returns the eventual success', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('boom-1'))
      .mockRejectedValueOnce(new Error('boom-2'))
      .mockResolvedValueOnce('ok');
    const onRetry = vi.fn();

    const out = await withRetry({ retries: 3, fn, onRetry, sleep: noSleep });

    expect(out).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(3);
    expect(onRetry).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenNthCalledWith(1, 1, expect.objectContaining({ message: 'boom-1' }));
    expect(onRetry).toHaveBeenNthCalledWith(2, 2, expect.objectContaining({ message: 'boom-2' }));
  });

  it('throws the final error after exhausting retries', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('one'))
      .mockRejectedValueOnce(new Error('two'))
      .mockRejectedValueOnce(new Error('three'));

    await expect(withRetry({ retries: 2, fn, sleep: noSleep }))
      .rejects.toThrow('three');
    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it('does not retry when retries is 0', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('first-and-only'));
    await expect(withRetry({ retries: 0, fn, sleep: noSleep }))
      .rejects.toThrow('first-and-only');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('calls sleep before each retry, with the attempt number', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('a'))
      .mockRejectedValueOnce(new Error('b'))
      .mockResolvedValueOnce('ok');
    const sleep = vi.fn().mockResolvedValue(undefined);

    await withRetry({ retries: 2, fn, sleep });

    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenNthCalledWith(1, 1);
    expect(sleep).toHaveBeenNthCalledWith(2, 2);
  });
});

describe('describeConnectFailure', () => {
  const t = { user: 'u', host: 'h' };
  it('reports a spawn timeout (no exit code) as a timeout with the configured seconds', () => {
    expect(describeConnectFailure(t, null, 'SIGTERM', 3000)).toMatch(/u@h timed out after 3s/);
  });
  it('explains ssh exit 255', () => {
    expect(describeConnectFailure(t, 255, null, 60000)).toMatch(/ssh exit 255: connection refused, unknown host, or authentication rejected/);
  });
  it("reports ssh exit 255 after the connect timeout as a timeout (ssh's ConnectTimeout won the race)", () => {
    expect(describeConnectFailure(t, 255, null, 5000, 5004)).toMatch(/u@h timed out after 5s/);
    // Seen with a busy event loop: the exit is handled late, still a timeout.
    expect(describeConnectFailure(t, 255, null, 5000, 22889)).toMatch(/timed out after 5s/);
    // A fast 255 (refused, unknown host, rejected key) keeps its explanation.
    expect(describeConnectFailure(t, 255, null, 5000, 120)).toMatch(/connection refused, unknown host/);
  });
  it('names other signals and exit codes', () => {
    expect(describeConnectFailure(t, null, 'SIGKILL', 60000)).toMatch(/terminated by SIGKILL/);
    expect(describeConnectFailure(t, 1, null, 60000)).toMatch(/failed \(ssh exit 1\)/);
  });
});

describe('assertIdentityFiles', () => {
  it('accepts readable keys and stops on a missing one instead of falling back to other keys', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-key-'));
    const key = join(dir, 'id_test');
    writeFileSync(key, 'not a real key', { mode: 0o600 });
    await expect(assertIdentityFiles([{ user: 'u', host: 'h', port: 22, identity: key }, { user: 'u', host: 'g', port: 22 }])).resolves.toBeUndefined();
    await expect(assertIdentityFiles([{ user: 'u', host: 'h', port: 22, identity: join(dir, 'nope') }])).rejects.toThrow(/SSH key ".*nope" is not readable \(ENOENT\)/);
  });

  it('rejects a directory or an empty file as a key', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-key-'));
    const empty = join(dir, 'empty');
    writeFileSync(empty, '', { mode: 0o600 });
    await expect(assertIdentityFiles([{ user: 'u', host: 'h', port: 22, identity: dir }])).rejects.toThrow('is not a file');
    await expect(assertIdentityFiles([{ user: 'u', host: 'h', port: 22, identity: empty }])).rejects.toThrow('is empty');
  });
});

describe('target identity', () => {
  it('scans Host and host once: host names are case-insensitive', () => {
    const { targets, duplicates } = uniqueTargets([parseSSHTarget('u@Host'), parseSSHTarget('u@host')]);
    expect(targets).toHaveLength(1);
    expect(duplicates).toEqual(['u@host']);
  });

  it('rejects labels that would share baseline and report files', () => {
    const t = (host: string, label?: string) => ({ user: 'root', host, port: 22, ...(label !== undefined ? { label } : {}) });
    expect(() => assertDistinctLabels([t('a', 'prod'), t('b', 'prod')])).toThrow('used by more than one host');
    expect(() => assertDistinctLabels([t('a', 'Prod'), t('b', 'prod')])).toThrow('would name the same files');
    expect(() => assertDistinctLabels([t('a', 'p/1'), t('b', 'p_1')])).toThrow('would name the same files');
    expect(() => assertDistinctLabels([t('a', 'prod'), t('b', 'stage'), t('c')])).not.toThrow();
  });
});

describe('ssh not installed', () => {
  it('fails at once instead of waiting out --ssh-timeout', async () => {
    const path = process.env.PATH;
    process.env.PATH = mkdtempSync(join(tmpdir(), 'vaso-nossh-'));
    const started = Date.now();
    try {
      await expect(executeRemoteProbe({ user: 'u', host: 'h', port: 22 }, { probeBinDir: '/nonexistent', manifest: {} as never, timeout: 30_000 }))
        .rejects.toThrow('not installed or not on PATH');
    } finally {
      process.env.PATH = path;
    }
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('is not retried with backoff', async () => {
    const path = process.env.PATH;
    process.env.PATH = mkdtempSync(join(tmpdir(), 'vaso-nossh-'));
    const sleep = vi.fn(async () => {});
    try {
      await expect(withRetry({
        retries: 5,
        sleep,
        fn: () => executeRemoteProbe({ user: 'u', host: 'h', port: 22 }, { probeBinDir: '/nonexistent', manifest: {} as never, timeout: 30_000 }),
      })).rejects.toThrow('not installed or not on PATH');
    } finally {
      process.env.PATH = path;
    }
    expect(sleep).not.toHaveBeenCalled();
  });
});

describe('temporary files of a remote scan (dt25 g9-F1)', () => {
  // A fake ssh/scp pair: logs each call (argv + the mode of the directory a
  // local file sits in) and answers the commands executeRemoteProbe sends.
  const FAKE = `#!/usr/bin/env node
const fs = require('fs'), path = require('path');
const args = process.argv.slice(2);
const entry = { cmd: path.basename(process.argv[1]), args };
if (entry.cmd === 'scp') {
  const src = args[args.length - 2];
  entry.srcDirMode = (fs.statSync(path.dirname(src)).mode & 0o777).toString(8);
  entry.srcMode = (fs.statSync(src).mode & 0o777).toString(8);
}
const cp = args.find(a => a.startsWith('ControlPath='));
if (cp) entry.controlDirMode = (fs.statSync(path.dirname(cp.slice(12))).mode & 0o777).toString(8);
fs.appendFileSync(process.env.FAKE_SSH_LOG, JSON.stringify(entry) + '\\n');
const last = args[args.length - 1];
if (entry.cmd === 'ssh' && last.includes('uname')) process.stdout.write('Linux\\nx86_64\\n');
else if (entry.cmd === 'ssh' && last.includes('mktemp')) process.stdout.write(process.env.FAKE_MKTEMP);
else if (entry.cmd === 'ssh' && last.includes('--manifest')) process.stdout.write(JSON.stringify({ version: 1, platform: 'linux', hostname: 'h', homedir: '/home/u', files: {}, directories: {}, commandOutputs: {} }));
`;

  async function run(mktempOut: string): Promise<{ log: Array<{ cmd: string; args: string[]; srcDirMode?: string; srcMode?: string; controlDirMode?: string }>; result: unknown }> {
    const bin = mkdtempSync(join(tmpdir(), 'vaso-fakessh-'));
    const probes = mkdtempSync(join(tmpdir(), 'vaso-fakeprobes-'));
    writeFileSync(join(probes, 'vaso-probe-linux-amd64'), 'probe');
    for (const name of ['ssh', 'scp']) writeFileSync(join(bin, name), FAKE, { mode: 0o755 });
    const logPath = join(bin, 'log.jsonl');
    const saved = { PATH: process.env.PATH, FAKE_SSH_LOG: process.env.FAKE_SSH_LOG, FAKE_MKTEMP: process.env.FAKE_MKTEMP };
    process.env.PATH = `${bin}:${saved.PATH}`;
    process.env.FAKE_SSH_LOG = logPath;
    process.env.FAKE_MKTEMP = mktempOut;
    let result: unknown;
    try {
      result = await executeRemoteProbe({ user: 'u', host: 'h', port: 22, sudo: true }, { probeBinDir: probes, manifest: { filePaths: [] } as never, timeout: 30_000 })
        .catch((err: Error) => err);
    } finally {
      process.env.PATH = saved.PATH;
      for (const k of ['FAKE_SSH_LOG', 'FAKE_MKTEMP'] as const) {
        if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
      }
    }
    const log = readFileSync(logPath, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
    return { log, result };
  }

  it('uploads into a private mktemp directory and removes it, and keeps the local side private', async () => {
    const remote = '/tmp/vaso-probe.Ab3dE9fGh1';
    const { log, result } = await run(`${remote}\n`);
    expect(result).not.toBeInstanceOf(Error);
    const all = log.flatMap(e => e.args).join(' ');
    // No fixed, guessable names in a shared /tmp
    expect(all).not.toMatch(/\/tmp\/vaso-(ssh|manifest|probe)-/);
    const controlPath = log[0].args.find(a => a.startsWith('ControlPath='))!.slice(12);
    expect(controlPath.length).toBeLessThanOrEqual(80);
    for (const e of log) if (e.controlDirMode) expect(e.controlDirMode).toBe('700');
    // mktemp comes before any upload
    const mktempAt = log.findIndex(e => e.args.some(a => a.includes('mktemp -d')));
    const firstScp = log.findIndex(e => e.cmd === 'scp');
    expect(mktempAt).toBeGreaterThan(-1);
    expect(firstScp).toBeGreaterThan(mktempAt);
    const scps = log.filter(e => e.cmd === 'scp');
    expect(scps.map(e => e.args[e.args.length - 1])).toEqual([`u@h:${remote}/vaso-probe`, `u@h:${remote}/manifest.json`]);
    // The manifest copy: owner-only file in an owner-only directory
    expect(scps[1].srcDirMode).toBe('700');
    expect(scps[1].srcMode).toBe('600');
    const runCmd = log.find(e => e.args.some(a => a.includes('--manifest')))!;
    expect(runCmd.args[runCmd.args.length - 1]).toBe(`${remote}/vaso-probe --manifest ${remote}/manifest.json --escalate`);
    // The whole remote directory is removed, then the local one
    expect(log.some(e => e.args[e.args.length - 1] === `rm -rf -- ${remote}`)).toBe(true);
    expect(existsSync(dirname(controlPath))).toBe(false);
  });

  it('fails closed when the target cannot make a private directory', async () => {
    for (const out of ['', '/tmp/vaso-probe-fixed', '/tmp/vaso-probe.abcdef/../x', '/tmp/vaso-probe.abcdef\n/tmp/other', 'mktemp: not found']) {
      const { log, result } = await run(out);
      expect(result, JSON.stringify(out)).toBeInstanceOf(Error);
      expect((result as Error).message).toMatch(/could not create a private temporary directory/);
      expect(log.some(e => e.cmd === 'scp')).toBe(false);
      expect(log.some(e => e.args.some(a => a.startsWith('rm ')))).toBe(false);
    }
  });

  it('parseRemoteTempDir accepts only mktemp output for its template', () => {
    expect(parseRemoteTempDir('/tmp/vaso-probe.XyZ123abcd\n', { user: 'u', host: 'h' })).toBe('/tmp/vaso-probe.XyZ123abcd');
    expect(() => parseRemoteTempDir('/tmp/vaso-probe.a b', { user: 'u', host: 'h' })).toThrow(/host not scanned/);
    expect(() => parseRemoteTempDir('/tmp/vaso-probe.$(id)', { user: 'u', host: 'h' })).toThrow(/host not scanned/);
  });

  it('makePrivateLocalDir falls back to /tmp when $TMPDIR is too long for a socket path', async () => {
    const dir = await makePrivateLocalDir('/' + 'x'.repeat(100));
    try {
      expect(dir.startsWith('/tmp/vaso-')).toBe(true);
      expect(statSync(dir).mode & 0o777).toBe(0o700);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
