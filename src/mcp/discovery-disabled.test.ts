import { describe, expect, it } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { MCPDiscovery } from './discovery.js';

function makeFs(files: Record<string, string>): FSProvider {
  return {
    homedir: () => '/home/t',
    access: async (p: string) => p in files,
    readFile: async (p: string) => files[p],
    readdir: async () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
    getEnv: () => undefined,
  } as unknown as FSProvider;
}

const files: Record<string, string> = {
  // map form: enabled:false and disabled:true
  '/home/t/.cursor/mcp.json': JSON.stringify({ mcpServers: { on: { command: 'node', args: ['a.js'] }, off: { command: 'node', args: ['b.js'], enabled: false } } }),
  '/home/t/.codeium/windsurf/mcp_config.json': JSON.stringify({ mcpServers: { ws: { command: 'node', disabled: true } } }),
  '/home/t/.abacusai/mcp.json': JSON.stringify({ mcpServers: { ab: { command: 'node', disabled: true }, ab2: { command: 'node' } } }),
  // whole MCP section off
  '/home/t/.picoclaw/config.json': JSON.stringify({ tools: { mcp: { enabled: false, servers: { pc: { enabled: true, command: 'npx' } } } } }),
  '/home/t/.zeroclaw/config.toml': '[mcp]\nenabled = false\n\n[[mcp.servers]]\nname = "zc"\ncommand = "npx"\n',
  // Atomic Agent array form
  '/home/t/.atomic-agent/config.json': JSON.stringify({ mcp: { servers: [{ name: 'at', enabled: false, transport: { kind: 'stdio', command: 'node' } }] } }),
};

const names = (r: Awaited<ReturnType<MCPDiscovery['discover']>>) =>
  r.configs.flatMap(c => c.servers.map(s => `${s.name}${s.disabled ? ':off' : ''}`)).sort();

describe('MCPDiscovery — disabled servers', () => {
  it('leaves disabled servers out by default (checks never see them)', async () => {
    const result = await new MCPDiscovery(makeFs(files)).discover('linux');
    expect(names(result)).toEqual(['ab2', 'on']);
    expect(result.totalServers).toBe(2);
  });

  it('keeps them, marked, with includeDisabled', async () => {
    const result = await new MCPDiscovery(makeFs(files)).discover('linux', undefined, { includeDisabled: true });
    expect(names(result)).toEqual(['ab2', 'ab:off', 'at:off', 'off:off', 'on', 'pc:off', 'ws:off', 'zc:off']);
  });

  it('reports a --paths file holding only disabled servers as empty', async () => {
    const result = await new MCPDiscovery(makeFs({ '/x.json': JSON.stringify({ mcpServers: { a: { command: 'n', disabled: true } } }) })).discoverFromPaths(['/x.json']);
    expect(result.configs).toEqual([]);
    expect(result.empty).toEqual(['/x.json']);
    expect(result.noServers).toEqual(['/x.json']);
  });
});
