import { describe, expect, it } from 'vitest';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { AgentInventory, CheckResult, McpServerItem } from '../core/types.js';
import { recordServerSpans, serverSpan } from './spans.js';
import { linkInventoryFindings } from './findings.js';

function fsWith(files: Record<string, string>): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: 't',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: Object.fromEntries(Object.entries(files).map(([p, content]) => [p, { content, mode: 0o100644, exists: true }])),
    directories: {}, commandOutputs: {}, env: {},
  });
}

const item = (name: string, configFile: string): McpServerItem => ({ name, configFile, scope: 'user', transport: 'stdio' });

describe('MCP server line spans', () => {
  it('spans JSON entries, YAML mappings and TOML tables', async () => {
    const json = JSON.stringify({ mcpServers: { a: { command: 'x', env: { K: 'v' } }, b: { url: 'http://evil.example/mcp' } } }, null, 2);
    const yaml = 'mcp_servers:\n  a:\n    command: x\n    args: []\n  b:\n    url: http://evil.example/mcp\nother: 1\n';
    const toml = '[mcp_servers.a]\ncommand = "x"\n\n[mcp_servers.a.env]\nK = "v"\n\n[mcp_servers.b]\nurl = "http://evil.example/mcp"\n\n[other]\nk = 1\n';
    const items = ['/c.json', '/c.yaml', '/c.toml'].flatMap(f => [item('a', f), item('b', f)]);
    await recordServerSpans(items, fsWith({ '/c.json': json, '/c.yaml': yaml, '/c.toml': toml }));
    expect(items.map(serverSpan)).toEqual([[3, 8], [9, 11], [2, 4], [5, 6], [1, 5], [7, 8]]);
  });

  it('gives no span to a minified file or a name found twice', async () => {
    const items = [item('a', '/m.json'), item('dup', '/d.json')];
    await recordServerSpans(items, fsWith({
      '/m.json': '{"mcpServers":{"a":{"command":"x"},"b":{"command":"y"}}}',
      '/d.json': JSON.stringify({ mcpServers: { dup: {} }, projects: { '/p': { mcpServers: { dup: {} } } } }, null, 2),
    }));
    // one line: a span of one line is kept, but ties with its neighbour are never linked
    expect(serverSpan(items[0])).toEqual([1, 1]);
    expect(serverSpan(items[1])).toBeUndefined();
  });

  it('links a bare-line finding to the entry holding the line', async () => {
    const json = JSON.stringify({ mcpServers: { a: { command: 'x' }, b: { url: 'http://evil.example/mcp' } } }, null, 2);
    const inv: AgentInventory = { skillsDirs: [], skills: [], otherEntries: [], mcpServers: [item('a', '/c.json'), item('b', '/c.json')] };
    await recordServerSpans(inv.mcpServers!, fsWith({ '/c.json': json }));
    const ioc: CheckResult = {
      id: 'IOC-001', name: '', category: 'ioc', severity: 'critical', passed: false, message: '',
      evidence: [{ file: '/c.json', line: 7, snippet: '"url": "http://evil.example/mcp"' }],
    };
    linkInventoryFindings(inv, [ioc]);
    expect(inv.mcpServers!.map(s => s.findings)).toEqual([undefined, ['IOC-001']]);
  });

  it('links nothing on a minified line several entries share', async () => {
    const inv: AgentInventory = { skillsDirs: [], skills: [], otherEntries: [], mcpServers: [item('a', '/m.json'), item('b', '/m.json')] };
    await recordServerSpans(inv.mcpServers!, fsWith({ '/m.json': '{"mcpServers":{"a":{"command":"x"},"b":{"url":"http://evil.example"}}}' }));
    linkInventoryFindings(inv, [{
      id: 'IOC-001', name: '', category: 'ioc', severity: 'critical', passed: false, message: '',
      evidence: [{ file: '/m.json', line: 1, snippet: 'http://evil.example' }],
    }]);
    expect(inv.mcpServers!.map(s => s.findings)).toEqual([undefined, undefined]);
  });
});
