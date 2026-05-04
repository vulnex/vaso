import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseInventory } from './inventory.js';

describe('parseInventory', () => {
  const dirs: string[] = [];

  async function writeTempYAML(content: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-inv-'));
    dirs.push(dir);
    const filePath = join(dir, 'inventory.yaml');
    await writeFile(filePath, content, 'utf-8');
    return filePath;
  }

  afterEach(async () => {
    for (const d of dirs) {
      await rm(d, { recursive: true, force: true }).catch(() => {});
    }
    dirs.length = 0;
  });

  it('parses basic inventory with 2 hosts', async () => {
    const path = await writeTempYAML(`
hosts:
  - host: server1.example.com
    user: admin
  - host: server2.example.com
    user: deploy
`);
    const targets = await parseInventory(path);
    expect(targets).toHaveLength(2);
    expect(targets[0].host).toBe('server1.example.com');
    expect(targets[0].user).toBe('admin');
    expect(targets[1].host).toBe('server2.example.com');
    expect(targets[1].user).toBe('deploy');
  });

  it('defaults user to root when not specified', async () => {
    const path = await writeTempYAML(`
hosts:
  - host: node1.internal
  - host: node2.internal
`);
    const targets = await parseInventory(path);
    expect(targets).toHaveLength(2);
    for (const t of targets) {
      expect(t.user).toBe('root');
      expect(t.port).toBe(22);
    }
  });

  it('uses per-host port and identity', async () => {
    const path = await writeTempYAML(`
hosts:
  - host: special.host
    user: ops
    port: 2222
    identity: /home/ops/.ssh/deploy_key
  - host: normal.host
`);
    const targets = await parseInventory(path);
    expect(targets[0].user).toBe('ops');
    expect(targets[0].port).toBe(2222);
    expect(targets[0].identity).toBe('/home/ops/.ssh/deploy_key');
    expect(targets[1].user).toBe('root');
    expect(targets[1].port).toBe(22);
  });

  it('preserves labels', async () => {
    const path = await writeTempYAML(`
hosts:
  - host: 10.0.0.5
    label: production-db
  - host: 10.0.0.6
    label: staging-web
`);
    const targets = await parseInventory(path);
    expect(targets[0].label).toBe('production-db');
    expect(targets[1].label).toBe('staging-web');
  });

  it('defaults label to user@host when omitted', async () => {
    const path = await writeTempYAML(`
hosts:
  - host: 10.0.0.5
    user: ops
  - host: 10.0.0.6
    user: ops
    port: 2200
  - host: 10.0.0.7
`);
    const targets = await parseInventory(path);
    expect(targets[0].label).toBe('ops@10.0.0.5');
    expect(targets[1].label).toBe('ops@10.0.0.6:2200');
    expect(targets[2].label).toBe('root@10.0.0.7');
  });

  it('throws when host field is missing', async () => {
    const path = await writeTempYAML(`
hosts:
  - user: admin
`);
    await expect(parseInventory(path)).rejects.toThrow('missing required "host" field');
  });

  it('throws when hosts array is missing', async () => {
    const path = await writeTempYAML(`
something_else:
  user: root
`);
    await expect(parseInventory(path)).rejects.toThrow('expected a "hosts" array');
  });

  it('supports sudo flag per host', async () => {
    const path = await writeTempYAML(`
hosts:
  - host: worker1.cluster
    sudo: true
  - host: worker2.cluster
`);
    const targets = await parseInventory(path);
    expect(targets[0].sudo).toBe(true);
    expect(targets[1].sudo).toBeUndefined();
  });
});
