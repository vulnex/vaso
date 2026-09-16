import { describe, it, expect, vi } from 'vitest';
import * as vaso from './index.js';
import type { FSProvider } from './core/fs-provider.js';

/** Hermetic provider: nothing exists, nothing runs — detect() finds no agents. */
function emptyFs(): FSProvider {
  return {
    platform: 'linux',
    access: vi.fn(async () => false),
    readFile: vi.fn(async () => { throw new Error('ENOENT'); }),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async () => []),
    stat: vi.fn(async () => { throw new Error('ENOENT'); }),
    exec: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 1 })),
    execSync: vi.fn(() => { throw new Error('not found'); }),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/home/test',
  } as unknown as FSProvider;
}

// Registries are module singletons and re-registration throws — register the
// full built-in set once for every test in this file, exactly like an embedder.
vaso.registerAllAdapters();
vaso.registerAllChecks();

describe('library entry point', () => {
  it('exposes the embedding seams', () => {
    expect(typeof vaso.ScanEngine).toBe('function');
    expect(typeof vaso.LocalFSProvider).toBe('function');
    expect(typeof vaso.SnapshotFSProvider).toBe('function');
    expect(typeof vaso.queryPermissions).toBe('function');
    expect(typeof vaso.defineCheck).toBe('function');
    expect(typeof vaso.loadConfig).toBe('function');
    expect(typeof vaso.getReporter).toBe('function');
    expect(typeof vaso.registerReporter).toBe('function');
    expect(typeof vaso.initIOCDatabase).toBe('function');
    expect(typeof vaso.initAdvisoryDatabase).toBe('function');
    expect(typeof vaso.VERSION).toBe('string');
    expect(vaso.AGENT_TYPES.length).toBeGreaterThan(0);
  });

  it('registers all built-in adapters and checks through the library surface', () => {
    expect(vaso.allAdapters.length).toBe(18);
    expect(vaso.adapterRegistry.getAdapters().length).toBe(18);
    expect(vaso.checkRegistry.getAll().length).toBe(264);
  });

  it('runs a programmatic scan end-to-end against a hermetic provider', async () => {
    const engine = new vaso.ScanEngine(vaso.adapterRegistry, vaso.checkRegistry, emptyFs());
    const result = await engine.scan({});
    expect(Array.isArray(result.agents)).toBe(true);
    expect(result.agents.length).toBe(0);
    expect(typeof result.totalScore).toBe('number');
    const rendered = vaso.getReporter('json').render(result);
    expect(() => JSON.parse(rendered)).not.toThrow();
  });
});
