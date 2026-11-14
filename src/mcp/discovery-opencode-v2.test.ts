import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { MCPDiscovery } from './discovery.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

describe('MCP discovery: OpenCode V2 `mcp.servers`', () => {
  let home: string;
  class HomeFS extends LocalFSProvider { homedir() { return home; } getEnv() { return undefined; } }

  beforeAll(async () => {
    home = await mkdtemp(join(tmpdir(), 'vaso-mcp-oc2-'));
    await mkdir(join(home, '.config/opencode'), { recursive: true });
    await writeFile(join(home, '.config/opencode/opencode.json'), JSON.stringify({ mcp: { servers: {
      loc: { type: 'local', command: ['npx', '-y', 'oc-mcp'] },
      rem: { type: 'remote', url: 'https://oc.example/mcp' },
      off: { type: 'local', command: ['x'], disabled: true },
    } } }));
  });
  afterAll(() => rm(home, { recursive: true, force: true }));

  it('lists the nested servers, not "servers" itself, and skips disabled ones', async () => {
    const result = await new MCPDiscovery(new HomeFS()).discover('linux');
    const oc = result.configs.find(c => c.source === 'OpenCode')!;
    expect(oc.servers.map(s => `${s.name}:${s.transport}`)).toEqual(['loc:stdio', 'rem:streamable-http']);
  });
});
