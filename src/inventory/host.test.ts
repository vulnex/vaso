import { describe, expect, it } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { McpServerItem } from '../core/types.js';
import { buildHostInventory, hostInventoryGaps, isEmptyHostInventory } from './host.js';

const server: McpServerItem = { name: 'v', configFile: '/h/.config/Code/User/mcp.json', scope: 'user', transport: 'stdio', command: 'node' };
const SETTINGS = '/h/.config/Code/User/settings.json';

function fs(kind: 'local' | 'snapshot', present: string[]): FSProvider {
  return { kind, platform: 'linux', homedir: () => '/h', getEnv: () => undefined, access: async (p: string) => present.includes(p) } as unknown as FSProvider;
}

describe('buildHostInventory', () => {
  it('keeps host servers and notes, dropping both under an agent filter', () => {
    const host = { mcpServers: [server], incomplete: ['note'] };
    expect(buildHostInventory([], host)).toEqual({ mcpServers: [server], incomplete: ['note'] });
    const filtered = buildHostInventory([], host, { agentFilter: true });
    expect(filtered).toEqual({ mcpServers: [] });
    expect(isEmptyHostInventory(filtered)).toBe(true);
    expect(isEmptyHostInventory({ mcpServers: [], incomplete: ['note'] })).toBe(false);
  });

  it('a host inventory present for a note alone still carries its (empty) server list', () => {
    // One shape wherever hostInventory appears (local, snapshot, detect):
    // mcpServers is always there; only an empty inventory is left out
    expect(buildHostInventory([], { mcpServers: [], incomplete: ['note'] })).toEqual({ mcpServers: [], incomplete: ['note'] });
  });
});

describe('hostInventoryGaps', () => {
  it('notes VS Code settings.json on a snapshot that has one, only', async () => {
    expect(await hostInventoryGaps(fs('snapshot', [SETTINGS]))).toEqual([expect.stringContaining(`${SETTINGS}: VS Code settings are not collected`)]);
    expect(await hostInventoryGaps(fs('snapshot', []))).toEqual([]);
    expect(await hostInventoryGaps(fs('local', [SETTINGS]))).toEqual([]);
  });
});
