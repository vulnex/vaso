import { describe, it, expect, vi, beforeEach } from 'vitest';
import { resolve } from 'node:path';
import { inferPackageName, resolveLocalPath, resolveServerSources } from './source-resolver.js';
import type { MCPServerEntry } from './types.js';

function makeServer(overrides?: Partial<MCPServerEntry>): MCPServerEntry {
  return {
    name: 'test-server',
    transport: 'stdio',
    ...overrides,
  };
}

describe('inferPackageName', () => {
  it('returns package name for npx command', () => {
    expect(inferPackageName(makeServer({ command: 'npx', args: ['@modelcontextprotocol/server-fs'] })))
      .toBe('@modelcontextprotocol/server-fs');
  });

  it('returns package name for npx with -y flag', () => {
    expect(inferPackageName(makeServer({ command: 'npx', args: ['-y', 'mcp-server-fetch'] })))
      .toBe('mcp-server-fetch');
  });

  it('returns package name for uvx command', () => {
    expect(inferPackageName(makeServer({ command: 'uvx', args: ['mcp-server-git'] })))
      .toBe('mcp-server-git');
  });

  it('returns package name for uvx with run keyword', () => {
    expect(inferPackageName(makeServer({ command: 'uv', args: ['run', 'mcp-server-sqlite'] })))
      .toBe('mcp-server-sqlite');
  });

  it('returns undefined for node command', () => {
    expect(inferPackageName(makeServer({ command: 'node', args: ['/path/to/server.js'] })))
      .toBeUndefined();
  });

  it('returns undefined when no args', () => {
    expect(inferPackageName(makeServer({ command: 'npx' })))
      .toBeUndefined();
  });

  it('returns undefined for unknown command', () => {
    expect(inferPackageName(makeServer({ command: 'python', args: ['server.py'] })))
      .toBeUndefined();
  });
});

describe('resolveLocalPath', () => {
  it('resolves node /path/to/file.js', () => {
    const result = resolveLocalPath(makeServer({ command: 'node', args: ['/path/to/server.js'] }));
    expect(result).toBe('/path/to/server.js');
  });

  it('resolves relative path with node', () => {
    const result = resolveLocalPath(makeServer({ command: 'node', args: ['./local/server.js'] }));
    expect(result).toBe(resolve('./local/server.js'));
  });

  it('resolves absolute direct path', () => {
    const result = resolveLocalPath(makeServer({ command: '/usr/local/bin/my-server', args: ['--port', '3000'] }));
    expect(result).toBe('/usr/local/bin/my-server');
  });

  it('resolves relative direct path with ./', () => {
    const result = resolveLocalPath(makeServer({ command: './my-server', args: ['--port', '3000'] }));
    expect(result).toBe(resolve('./my-server'));
  });

  it('returns undefined for npx command', () => {
    expect(resolveLocalPath(makeServer({ command: 'npx', args: ['some-pkg'] }))).toBeUndefined();
  });

  it('returns undefined when no args for node', () => {
    expect(resolveLocalPath(makeServer({ command: 'node' }))).toBeUndefined();
  });
});

describe('resolveServerSources', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('sets packageName for npx server', async () => {
    const servers = [makeServer({ command: 'npx', args: ['-y', '@mcp/server-fs'] })];
    const sources = await resolveServerSources(servers);
    expect(sources).toHaveLength(1);
    expect(sources[0].packageName).toBe('@mcp/server-fs');
    expect(sources[0].localPath).toBeUndefined();
  });

  it('returns serverName in result', async () => {
    const servers = [makeServer({ name: 'my-mcp-server', command: 'npx', args: ['pkg'] })];
    const sources = await resolveServerSources(servers);
    expect(sources[0].serverName).toBe('my-mcp-server');
  });

  it('handles empty server list', async () => {
    const sources = await resolveServerSources([]);
    expect(sources).toEqual([]);
  });

  it('sets localPath for node command', async () => {
    const servers = [makeServer({ command: 'node', args: ['/tmp/server.js'] })];
    const sources = await resolveServerSources(servers);
    expect(sources).toHaveLength(1);
    expect(sources[0].localPath).toBe('/tmp/server.js');
    expect(sources[0].packageName).toBeUndefined();
  });

  it('handles multiple servers', async () => {
    const servers = [
      makeServer({ name: 'srv1', command: 'npx', args: ['pkg1'] }),
      makeServer({ name: 'srv2', command: 'npx', args: ['pkg2'] }),
    ];
    const sources = await resolveServerSources(servers);
    expect(sources).toHaveLength(2);
    expect(sources[0].packageName).toBe('pkg1');
    expect(sources[1].packageName).toBe('pkg2');
  });
});
