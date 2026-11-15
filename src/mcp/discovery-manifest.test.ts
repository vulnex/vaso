import { describe, expect, it } from 'vitest';
import { matchesGlob } from 'node:path';
import type { FSProvider } from '../core/fs-provider.js';
import { buildProbeManifest } from '../core/manifest-builder.js';
import { adapterRegistry } from '../adapters/registry.js';
import { registerAllAdapters } from '../adapters/index.js';
import { userConfigLocations } from './discovery.js';

/**
 * Remote scans list an agent's MCP servers from the probe's snapshot, so the
 * probe must collect (with content) every user-level file discovery reads.
 */
describe('probe manifest covers MCP discovery', () => {
  registerAllAdapters();
  const manifest = buildProbeManifest(adapterRegistry.getAdapters());
  const patterns = [...manifest.filePaths, ...manifest.globPatterns, ...(manifest.systemPaths ?? [])];

  const home = '/home/u';
  const fsFor = (platform: NodeJS.Platform): FSProvider => ({
    platform,
    homedir: () => home,
    getEnv: () => undefined,
  } as unknown as FSProvider);

  const covered = (path: string): boolean => {
    const tilde = path.startsWith(home + '/') ? '~' + path.slice(home.length) : path;
    return patterns.some(p => p === tilde || matchesGlob(tilde, p));
  };

  for (const platform of ['linux', 'darwin'] as const) {
    it(`collects every user-level MCP config on ${platform}`, () => {
      const missing = userConfigLocations(platform, home, fsFor(platform))
        // the whole editor config — not shipped (manifest-builder.ts)
        .filter(l => l.source !== 'VS Code (settings.json)')
        .filter(l => !covered(l.path))
        .map(l => `${l.source}: ${l.path}`);
      expect(missing.join('; ')).toBe('');
    });
  }
});
