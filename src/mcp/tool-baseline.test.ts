import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  baselineKey,
  diffToolBaseline,
  FileToolBaselineStore,
  InMemoryToolBaselineStore,
  makeBaseline,
} from './tool-baseline.js';
import type { MCPServerSource } from './types.js';

describe('baselineKey', () => {
  it('produces stable, identical keys for the same source on repeat calls', () => {
    const source: MCPServerSource = {
      serverName: 'filesystem',
      localPath: '/projects/foo/server.js',
    };
    expect(baselineKey(source)).toBe(baselineKey(source));
  });

  it('separates baselines by localPath when serverName is identical', () => {
    const a = baselineKey({ serverName: 'fs', localPath: '/host-a/server.js' });
    const b = baselineKey({ serverName: 'fs', localPath: '/host-b/server.js' });
    expect(a).not.toBe(b);
  });

  it('separates baselines by packageName when localPath is absent', () => {
    const a = baselineKey({ serverName: 'fs', packageName: '@scope/pkg-a' });
    const b = baselineKey({ serverName: 'fs', packageName: '@scope/pkg-b' });
    expect(a).not.toBe(b);
  });

  it('falls back to serverName as identity when neither localPath nor packageName is set', () => {
    const a = baselineKey({ serverName: 'a' });
    const b = baselineKey({ serverName: 'b' });
    expect(a).not.toBe(b);
  });

  it('produces a slugified, filesystem-safe key (no special characters)', () => {
    const key = baselineKey({
      serverName: 'weird/name with spaces!',
      localPath: '/x/y',
    });
    expect(key).toMatch(/^[a-zA-Z0-9_-]+$/);
  });

  it('separates baselines by hostname when the source identity is otherwise identical', () => {
    // Fleet scan case: two hosts run an identical config block that names an
    // MCP server with no localPath and no packageName. Without hostname in
    // the key, both hosts collide onto the same baseline file and either
    // host's drift looks like a rug pull on the other.
    const source: MCPServerSource = { serverName: 'fs' };
    const a = baselineKey(source, 'web-1');
    const b = baselineKey(source, 'web-2');
    expect(a).not.toBe(b);
  });

  it('treats undefined hostname as a stable default', () => {
    const source: MCPServerSource = { serverName: 'fs', localPath: '/x/y' };
    expect(baselineKey(source)).toBe(baselineKey(source, undefined));
  });
});

describe('InMemoryToolBaselineStore', () => {
  it('round-trips a saved baseline', async () => {
    const store = new InMemoryToolBaselineStore();
    const source: MCPServerSource = { serverName: 'srv', localPath: '/x/srv.js' };
    const baseline = makeBaseline(source, [{ name: 'tool_a' }]);

    await store.save(baselineKey(source), baseline);
    const loaded = await store.load(baselineKey(source));

    expect(loaded).toEqual(baseline);
  });

  it('returns null for unknown keys', async () => {
    const store = new InMemoryToolBaselineStore();
    expect(await store.load('does-not-exist')).toBeNull();
  });

  it('reports its size and keys', async () => {
    const store = new InMemoryToolBaselineStore();
    await store.save('k1', makeBaseline({ serverName: 's1' }, []));
    await store.save('k2', makeBaseline({ serverName: 's2' }, []));
    expect(store.size()).toBe(2);
    expect(store.keys().sort()).toEqual(['k1', 'k2']);
  });
});

describe('FileToolBaselineStore', () => {
  it('persists baselines to the configured directory and never touches user home', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'vaso-baseline-test-'));
    try {
      const store = new FileToolBaselineStore(tmp);
      const source: MCPServerSource = { serverName: 'srv', localPath: '/x/srv.js' };
      const baseline = makeBaseline(source, [{ name: 'tool_a' }]);

      await store.save(baselineKey(source), baseline);
      const loaded = await store.load(baselineKey(source));

      expect(loaded).toEqual(baseline);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('returns null when the file does not exist', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'vaso-baseline-test-'));
    try {
      const store = new FileToolBaselineStore(tmp);
      expect(await store.load('absent')).toBeNull();
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('diffToolBaseline', () => {
  it('returns isFirstScan and saves baseline when none exists', async () => {
    const store = new InMemoryToolBaselineStore();
    const source: MCPServerSource = { serverName: 's', localPath: '/x/s.js' };
    const { diff, isFirstScan } = await diffToolBaseline(store, source, [
      { name: 'a' },
    ]);
    expect(isFirstScan).toBe(true);
    expect(diff).toEqual({ changed: [], added: [], removed: [] });
    expect(await store.load(baselineKey(source))).not.toBeNull();
  });

  it('detects added, removed, and changed tools across runs', async () => {
    const store = new InMemoryToolBaselineStore();
    const source: MCPServerSource = { serverName: 's', localPath: '/x/s.js' };

    await diffToolBaseline(store, source, [
      { name: 'kept', description: 'stable' },
      { name: 'will_remove' },
      { name: 'will_change', description: 'old' },
    ]);

    const { diff, isFirstScan } = await diffToolBaseline(store, source, [
      { name: 'kept', description: 'stable' },
      { name: 'will_change', description: 'new' },
      { name: 'newly_added' },
    ]);

    expect(isFirstScan).toBe(false);
    expect(diff.added).toEqual(['newly_added']);
    expect(diff.removed).toEqual(['will_remove']);
    expect(diff.changed.map(c => c.name)).toEqual(['will_change']);
  });

  it('does not collide for two servers with the same name but different localPath', async () => {
    const store = new InMemoryToolBaselineStore();
    const a: MCPServerSource = { serverName: 'fs', localPath: '/host-a/s.js' };
    const b: MCPServerSource = { serverName: 'fs', localPath: '/host-b/s.js' };

    await diffToolBaseline(store, a, [{ name: 'read' }]);
    await diffToolBaseline(store, b, [{ name: 'write' }]);

    expect(store.size()).toBe(2);
  });
});
