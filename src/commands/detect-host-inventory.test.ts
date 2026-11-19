import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProbeSnapshot } from '../core/snapshot-types.js';

// Multi-host detect probes over SSH: hand back a snapshot instead
const executeRemoteProbeWithRetry = vi.fn();
vi.mock('../transport/ssh.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../transport/ssh.js')>()),
  executeRemoteProbeWithRetry,
}));

import { runDetect } from './detect.js';
import { adapterRegistry } from '../adapters/registry.js';
import { toReportJson } from '../reporting/serialize.js';
import type { AgentInstallation } from '../core/types.js';

const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

/** A Linux host whose VS Code user mcp.json carries a credential in argv, and whose settings.json the probe recorded without content. */
function snapshot(): ProbeSnapshot {
  return {
    version: 1, hostname: 'box', platform: 'linux', homedir: '/home/u', timestamp: 't',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: {
      '/home/u/.config/Code/User/mcp.json': {
        content: JSON.stringify({ servers: { gh: { command: 'gh-mcp', args: ['--token', TOKEN] } } }), mode: 0o644, exists: true,
      },
      '/home/u/.config/Code/User/settings.json': { content: '', mode: 0o644, exists: true, contentOmitted: true, omitted: 'metadata' },
    },
    directories: {}, commandOutputs: {}, env: {},
  } as unknown as ProbeSnapshot;
}

let out: string[];
let dir: string;
beforeEach(async () => {
  out = [];
  vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { out.push(a.map(String).join(' ')); });
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { if (process.env.DBG) process.stderr.write(a.map(String).join(' ') + '\n'); });
  dir = await mkdtemp(join(tmpdir(), 'vaso-detect-hi-'));
});
afterEach(async () => {
  vi.restoreAllMocks();
  executeRemoteProbeWithRetry.mockReset();
  await rm(dir, { recursive: true, force: true });
});

describe('detect --host-inventory', () => {
  it('leaves single-host JSON the bare installations array without the flag', async () => {
    const installs: AgentInstallation[] = [{ agent: 'nanobot', installDir: '/nonexistent-vaso/.nanobot', configFiles: [] }];
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue(installs);
    await runDetect({ format: 'json' });
    // detection attaches inventories to the same objects: the output is exactly them
    expect(out.join('\n')).toBe(toReportJson(installs));
    expect(Array.isArray(JSON.parse(out.join('\n')))).toBe(true);
  });

  it('writes { installations, hostInventory } for a snapshot, masked, with the uncollected settings.json noted', async () => {
    const file = join(dir, 'box.json');
    await writeFile(file, JSON.stringify(snapshot()));
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([]);

    await runDetect({ format: 'json', snapshot: file, hostInventory: true });

    const text = out.join('\n');
    const parsed = JSON.parse(text);
    expect(parsed.installations).toEqual([]);
    expect(parsed.hostInventory.mcpServers.map((s: { name: string }) => s.name)).toEqual(['gh']);
    expect(parsed.hostInventory.incomplete).toEqual([
      expect.stringMatching(/^\/home\/u\/\.config\/Code\/User\/settings\.json: .*not collected by the remote probe/),
    ]);
    expect(text).not.toContain('A1b2C3d4E5f6');

    // without the flag: the bare array, as before
    out.length = 0;
    await runDetect({ format: 'json', snapshot: file });
    expect(JSON.parse(out.join('\n'))).toEqual([]);
  });

  it('terminal output names the uncollected settings.json', async () => {
    const file = join(dir, 'box.json');
    await writeFile(file, JSON.stringify(snapshot()));
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([{ agent: 'nanobot', installDir: '/home/u/.nanobot', configFiles: [] }]);
    await runDetect({ format: 'terminal', snapshot: file });
    expect(out.join('\n')).toMatch(/settings\.json: VS Code settings are not collected/);
  });

  it('multi-host JSON carries hostInventory per host, keeping hostMcp', async () => {
    executeRemoteProbeWithRetry.mockResolvedValue(snapshot());
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([]);

    await runDetect({ format: 'json', host: ['u@10.0.0.1', 'u@10.0.0.2'] });

    const text = out.join('\n');
    const hosts = JSON.parse(text);
    expect(hosts).toHaveLength(2);
    for (const h of hosts) {
      expect(h.hostMcp.map((s: { name: string }) => s.name)).toEqual(['gh']);
      expect(h.hostInventory.mcpServers).toEqual(h.hostMcp);
      expect(h.hostInventory.incomplete).toHaveLength(1);
    }
    expect(text).not.toContain('A1b2C3d4E5f6');
  });

  it('terminal names a shared server\'s project-scope copy apart from the user-scope one', async () => {
    const fsServer = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/data'] };
    const snap = snapshot();
    snap.files = {
      '/home/u/.claude.json': { content: JSON.stringify({ mcpServers: { fs: fsServer }, projects: { '/srv/app': { mcpServers: { files: fsServer } } } }), mode: 0o600, exists: true },
      '/home/u/.cursor/mcp.json': { content: JSON.stringify({ mcpServers: { fs: fsServer } }), mode: 0o644, exists: true },
    };
    const file = join(dir, 'box.json');
    await writeFile(file, JSON.stringify(snap));
    vi.spyOn(adapterRegistry, 'detectAll').mockResolvedValue([
      { agent: 'claude-code', installDir: '/home/u/.claude', configFiles: [] },
      { agent: 'cursor-cli', installDir: '/home/u/.cursor', configFiles: [] },
    ]);
    await runDetect({ format: 'terminal', snapshot: file });
    const line = out.join('\n').split('\n').find(l => l.includes('npm:@modelcontextprotocol/server-filesystem'));
    expect(line).toMatch(/— claude-code, claude-code project \/srv\/app, cursor-cli$/);
  });
});
