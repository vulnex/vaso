import { describe, expect, it, vi } from 'vitest';
import type { ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { cd010 } from './cd-010-credentials-in-url.js';

const V = 'oNZYW2mZp0zVZomHFwUbbYrEqmSM9w';
function run(mcpServers: Record<string, unknown>) {
  const config = { raw: '', format: 'json' as const, filePath: '/h/claude_desktop_config.json', data: { mcpServers } };
  const fs = { getEnv: vi.fn(() => undefined), homedir: () => '/h', platform: 'darwin' } as unknown as FSProvider;
  const ctx: ScanContext = { installation: { agent: 'claude-desktop', installDir: '/h', configFiles: [config] }, configs: [config], platform: 'darwin', fs };
  return cd010.run(ctx);
}

describe('CD-010 — dt21 g3-F4', () => {
  it('reports header arguments, connection URLs and connection strings', async () => {
    const result = await run({
      remote: { command: 'npx', args: ['-y', 'mcp-remote@0.1.37', 'https://a.example/mcp', '--header', `Authorization: Bearer ${V}a`] },
      apikey: { command: 'npx', args: ['-y', 'mcp-remote@0.1.37', 'https://a.example/mcp', '-H', `X-API-Key: ${V}b`] },
      pg: { command: 'npx', args: ['-y', 'x@1.0.0', `postgresql://admin:${V}c@db.acme.io/prod`] },
      mssql: { command: 'npx', args: ['-y', 'x@1.0.0', `--connection-string=Server=db;Password=${V}d;`] },
      env: { command: 'npx', args: ['-y', 'x@1.0.0'], env: { DATABASE_URL: `mysql://app:${V}e@db/x` } },
    });
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(5);
    expect(JSON.stringify(result.evidence)).not.toContain(V);
  });

  it('leaves argv credentials outside URLs and headers to other checks', async () => {
    const result = await run({ t: { command: 'npx', args: ['-y', 'x@1.0.0', '--token', V] }, ok: { command: 'npx', args: ['-y', 'mcp-remote@0.1.37', 'https://a.example/mcp', '--header', 'Authorization: Bearer ${TOKEN}'] } });
    expect(result.passed).toBe(true);
  });
});
