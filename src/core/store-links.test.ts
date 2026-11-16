import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { foreignAgentDir, foreignStoreTarget, storeHomeOf } from './store-links.js';

interface StoreLinkCase {
  target: string;
  homeRoots: string[];
  storeRoots?: string[];
  storeDir?: string;
  /** A row for foreignAgentDir: the agent folder as written, resolving to `target`. */
  agentDir?: string;
  want: 'sensitive' | 'outside' | 'home' | 'store' | null;
}

describe('foreignStoreTarget', () => {
  it('judges every target of probe/testdata/store-link-cases.json as the probe does', async () => {
    const cases = JSON.parse(await readFile(resolve(import.meta.dirname, '../../probe/testdata/store-link-cases.json'), 'utf-8')) as StoreLinkCase[];
    expect(cases.length).toBeGreaterThan(20);
    expect(cases.filter(c => c.agentDir).length).toBeGreaterThan(15);
    for (const c of cases) {
      const got = c.agentDir !== undefined
        ? foreignAgentDir(c.agentDir, c.target, c.homeRoots)
        : foreignStoreTarget(c.target, { homeRoots: c.homeRoots, storeRoots: c.storeRoots!, storeDir: c.storeDir! });
      expect({ target: c.target, why: got?.why ?? null }).toEqual({ target: c.target, why: c.want });
    }
  });

  it('names the sensitive location', () => {
    expect(foreignStoreTarget('/home/u/.aws', { homeRoots: ['/home/u'], storeRoots: ['/home/u/.copilot'], storeDir: '/home/u/.copilot/session-state' }))
      .toEqual({ why: 'sensitive', label: 'AWS credentials (~/.aws)' });
  });
});

describe('storeHomeOf', () => {
  it('is the parent of another user\'s ~/.copilot, else the scanning home', () => {
    expect(storeHomeOf('/home/u/.copilot', '/home/me', '/home/me/.copilot')).toBe('/home/u');
    expect(storeHomeOf('/opt/cop', '/home/me', '/opt/cop')).toBe('/home/me');
    expect(storeHomeOf('/home/me/.copilot', '/home/me', '/home/me/.copilot')).toBe('/home/me');
  });

  it('is the scanning home for a COPILOT_HOME folder named .copilot, never its parent', () => {
    // ~/x may be a link out of the home: its real path must not count as a home
    expect(storeHomeOf('/home/me/x/.copilot', '/home/me', '/home/me/x/.copilot')).toBe('/home/me');
    expect(storeHomeOf('/home/me/x/a/.copilot', '/home/me', '/home/me/x/a/.copilot')).toBe('/home/me');
    expect(storeHomeOf('/data/.copilot', '/home/me', '/data/.copilot')).toBe('/home/me');
  });
});
