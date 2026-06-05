import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FileMcpStateStore, InMemoryMcpStateStore } from './mcp-state-store.js';

describe('InMemoryMcpStateStore', () => {
  it('round-trips a value and returns null for missing keys', async () => {
    const store = new InMemoryMcpStateStore();
    expect(await store.load('missing')).toBeNull();
    await store.save('k', { highest: '1.2.3' });
    expect(await store.load('k')).toEqual({ highest: '1.2.3' });
  });

  it('isolates stored values (no shared reference mutation)', async () => {
    const store = new InMemoryMcpStateStore();
    const value = { n: 1 };
    await store.save('k', value);
    value.n = 2;
    expect(await store.load<{ n: number }>('k')).toEqual({ n: 1 });
  });
});

describe('FileMcpStateStore', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-state-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('persists to disk and reloads', async () => {
    const store = new FileMcpStateStore(dir);
    expect(await store.load('nope')).toBeNull();
    await store.save('config-drift', { a: true });
    expect(await new FileMcpStateStore(dir).load('config-drift')).toEqual({ a: true });
  });

  it('sanitizes keys with path-ish characters', async () => {
    const store = new FileMcpStateStore(dir);
    await store.save('version-@scope/pkg', { highest: '1.0.0' });
    expect(await store.load('version-@scope/pkg')).toEqual({ highest: '1.0.0' });
  });
});
