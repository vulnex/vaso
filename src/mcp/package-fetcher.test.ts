import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
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
});
