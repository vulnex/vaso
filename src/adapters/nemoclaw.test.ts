import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { nemoclawAdapter } from './nemoclaw.js';
import { join } from 'node:path';
import { BLUEPRINT_DIRS, BLUEPRINT_FILES, nemoclawLegacyRoots, PLUGIN_MANIFEST } from './nemoclaw-paths.js';
import { blueprintDirCandidates } from '../checks/config/nemoclaw-state.js';

function makeFs(files: Record<string, string>, dirs: string[] = []): FSProvider {
  const dirSet = new Set(dirs);
  return {
    homedir: () => '/home/t',
    platform: 'linux',
    access: vi.fn(async (p: string) => p in files || dirSet.has(p)),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error(`ENOENT ${p}`);
    }),
    stat: vi.fn(async () => ({ mode: 0o100600, isFile: () => true, isDirectory: () => false })),
    readdirEntries: vi.fn(async () => []),
    realpath: vi.fn(async (p: string) => p),
    execSync: vi.fn(() => { throw new Error('not found'); }),
    getEnv: vi.fn(() => undefined),
  } as unknown as FSProvider;
}

const REGISTRY = JSON.stringify({
  defaultSandbox: 'my-assistant',
  sandboxes: { 'my-assistant': { name: 'my-assistant', provider: 'nvidia-prod', model: 'nvidia/nemotron-3-super-120b-a12b' } },
});
const LEGACY_PKG = JSON.stringify({ name: 'nemoclaw', version: '0.1.0' });

describe('NemoClaw adapter — install generations', () => {
  it('current install: version from source/dist/build-identity.json, binary is the ~/.local/bin shim', async () => {
    const fs = makeFs({
      '/home/t/.nemoclaw/sandboxes.json': REGISTRY,
      '/home/t/.nemoclaw/source/dist/build-identity.json': JSON.stringify({ nemoclawVersion: '0.0.124', sourceRevision: 'x' }),
      '/home/t/.nemoclaw/source/package.json': LEGACY_PKG,
      '/home/t/.local/bin/nemoclaw': '',
      // A stale legacy npm-global install left behind must not win
      '/usr/bin/nemoclaw': '',
      '/usr/lib/node_modules/nemoclaw/package.json': LEGACY_PKG,
    }, ['/home/t/.nemoclaw', '/home/t/.nemoclaw/source']);
    const [inst] = await nemoclawAdapter.detect({ fs });
    expect(inst.version).toBe('0.0.124');
    expect(inst.cliBinary).toBe('/home/t/.local/bin/nemoclaw');
    expect(inst.agentName).toBe('my-assistant');
  });

  it('current install without a build identity falls back to source/.version', async () => {
    const fs = makeFs({
      '/home/t/.nemoclaw/sandboxes.json': REGISTRY,
      '/home/t/.nemoclaw/source/.version': 'v0.0.120\n',
    }, ['/home/t/.nemoclaw', '/home/t/.nemoclaw/source']);
    const [inst] = await nemoclawAdapter.detect({ fs });
    expect(inst.version).toBe('0.0.120');
  });

  it('legacy npm-global install keeps its package.json version and /usr/bin binary', async () => {
    const fs = makeFs({
      '/home/t/.nemoclaw/sandboxes.json': REGISTRY,
      '/usr/bin/nemoclaw': '',
      '/usr/lib/node_modules/nemoclaw/package.json': LEGACY_PKG,
    }, ['/home/t/.nemoclaw']);
    const [inst] = await nemoclawAdapter.detect({ fs });
    expect(inst.version).toBe('0.1.0');
    expect(inst.cliBinary).toBe('/usr/bin/nemoclaw');
  });
});

describe('NemoClaw probe manifest', () => {
  it('collects every blueprint and plugin manifest path CFG-018/019 read', () => {
    const m = nemoclawAdapter.getProbeManifest!();
    const files = new Set([...m.filePaths, ...(m.systemPaths ?? [])]);
    const dirs = new Set([...m.directoryListings, ...(m.systemDirListings ?? [])]);
    // The manifest's `~` is the scanned home the checks join paths onto
    for (const dir of blueprintDirCandidates({ homedir: () => '~' } as FSProvider)) {
      for (const f of BLUEPRINT_FILES) expect(files).toContain(join(dir, f));
      for (const d of BLUEPRINT_DIRS) expect(dirs).toContain(join(dir, d));
    }
    for (const root of nemoclawLegacyRoots('~')) expect(files).toContain(join(root, PLUGIN_MANIFEST));
    expect(files).toContain('~/.npm-global/lib/node_modules/nemoclaw/nemoclaw-blueprint/blueprint.yaml');
  });
});
