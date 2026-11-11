import { describe, expect, it } from 'vitest';
import type { ScanContext } from '../../core/types.js';
import type { MCPConfig, MCPServer } from '../../mcp/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { mcp003 } from './mcp-003-credential-exposure.js';

const V = 'oNZYW2mZp0zVZomHFwUbbYrEqmSM9w';
function run(servers: MCPServer[]) {
  const mcpConfigs: MCPConfig[] = [{ source: 'Claude Desktop', filePath: '/h/claude_desktop_config.json', servers }];
  const ctx: ScanContext = { installation: { agent: 'mcp', installDir: '/h', configFiles: [] }, configs: [], platform: 'darwin', fs: new LocalFSProvider(), mcpConfigs };
  return mcp003.run(ctx);
}

describe('MCP-003 — dt21', () => {
  it('reports connection-string, header-argument and cookie credentials (g3-F4)', async () => {
    const result = await run([
      { name: 'pg', command: 'npx', args: ['-y', 'x@1.0.0', `postgresql://admin:${V}a@db.example/prod`], transport: 'stdio' },
      { name: 'redis', command: 'npx', args: ['-y', 'x@1.0.0', `redis://:${V}b@cache.example:6379`], transport: 'stdio' },
      { name: 'mssql', command: 'npx', args: ['-y', 'x@1.0.0', `--connection-string=Server=db;User Id=sa;Password=${V}c;`], transport: 'stdio' },
      { name: 'h1', command: 'npx', args: ['-y', 'mcp-remote@0.1.37', 'https://a.example/mcp', `--header=Authorization: Bearer ${V}d`], transport: 'stdio' },
      { name: 'ck', command: 'npx', args: ['-y', 'x@1.0.0', '--header', `Cookie: session=${V}e`], transport: 'stdio' },
      { name: 'env', command: 'npx', args: ['-y', 'x@1.0.0'], env: { DATABASE_URL: `mysql://app:${V}f@db/x`, MDB_MCP_CONNECTION_STRING: `mongodb+srv://u:${V}g@c0.abcde.mongodb.net/` }, transport: 'stdio' },
      { name: 'cookie-hdr', url: 'https://a.example/mcp', headers: { Cookie: `session=${V}h` }, transport: 'streamable-http' },
      { name: 'camel', command: 'npx', args: ['-y', 'x@1.0.0', '--oauth2Bearer', `${V}i`], transport: 'stdio' },
    ]);
    expect(result.passed).toBe(false);
    const snippets = (result.evidence ?? []).map(e => e.snippet ?? '');
    for (const suffix of 'abcdefghi') {
      expect(snippets.some(s => s.includes('***')), suffix).toBe(true);
    }
    expect(result.evidence).toHaveLength(9);
    expect(JSON.stringify(result.evidence)).not.toContain(V);
  });

  it('reports an env API key that starts with / (g8-F15)', async () => {
    const result = await run([{ name: 'slash', command: 'node', args: ['/opt/x.js'], env: { API_KEY: '/eoa6ucfjvkSgG0YzP1zy4LG3iGSw' }, transport: 'stdio' }]);
    expect(result.passed).toBe(false);
  });

  it('stays quiet on credential-free connection URLs and real key paths', async () => {
    const result = await run([
      { name: 'r', command: 'npx', args: ['-y', 'x@1.0.0', 'redis://cache.example:6379/0'], env: { DATABASE_URL: 'postgres://app@db/x', KEY_FILE: '/home/u/.keys/api.key' }, transport: 'stdio' },
    ]);
    expect(result.passed).toBe(true);
  });
});
