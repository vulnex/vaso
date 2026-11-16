import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { opencodeChecks } from './index.js';
import { opencodeMcpServers, v2CatchAll, v2PermissionRules } from './schema.js';

const FILE = '/home/test/.config/opencode/opencode.json';

function ctx(data: Record<string, unknown>): ScanContext {
  const configs: ParsedConfig[] = [{ raw: '', format: 'json', filePath: FILE, data }];
  const fs = {
    access: vi.fn(async () => false),
    readdir: vi.fn(async () => { throw new Error('ENOENT'); }),
    readFile: vi.fn(async () => { throw new Error('ENOENT'); }),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/home/test',
    platform: 'linux',
  } as unknown as FSProvider;
  const installation: AgentInstallation = { agent: 'opencode', installDir: '/home/test/.config/opencode', configFiles: configs };
  return { installation, configs, platform: 'linux', fs };
}

const run = (id: string, data: Record<string, unknown>) => opencodeChecks.find(c => c.id === id)!.run(ctx(data));

describe('OpenCode V2 schema', () => {
  it('reads mcp.servers.<name> (V2) and mcp.<name> (V1), including a V1 server named "servers"', () => {
    expect(opencodeMcpServers({ mcp: { servers: { x: { command: ['a'] } } } }).map(s => s.path)).toEqual(['mcp.servers.x']);
    expect(opencodeMcpServers({ mcp: { x: { type: 'local', command: ['a'] } } }).map(s => s.path)).toEqual(['mcp.x']);
    expect(opencodeMcpServers({ mcp: { servers: { type: 'local', command: ['a'] } } }).map(s => s.path)).toEqual(['mcp.servers']);
  });

  it('applies "last match wins" with the documented allow-all default', () => {
    const rules = v2PermissionRules([
      { action: '*', resource: '*', effect: 'allow' },
      { action: 'shell', resource: '*', effect: 'ask' },
      { action: 'shell', resource: 'git status *', effect: 'allow' },
    ])!;
    expect(v2CatchAll(rules, 'shell').effect).toBe('ask');
    expect(v2CatchAll(rules, 'edit').effect).toBe('allow');
    expect(v2CatchAll([], 'edit')).toEqual({ effect: 'allow', index: -1 });
  });

  it('reads ? in an action as exactly one character', () => {
    const gate = { action: 'shell', resource: '*', effect: 'ask' };
    expect(v2CatchAll(v2PermissionRules([gate, { action: 'shel?', resource: '*', effect: 'allow' }])!, 'shell').effect).toBe('allow');
    expect(v2CatchAll(v2PermissionRules([gate, { action: 's?ell*', resource: '*', effect: 'allow' }])!, 'shell').effect).toBe('allow');
    expect(v2CatchAll(v2PermissionRules([gate, { action: 'shel??', resource: '*', effect: 'allow' }])!, 'shell').effect).toBe('ask');
    expect(v2CatchAll(v2PermissionRules([gate, { action: 'she?', resource: '*', effect: 'allow' }])!, 'shell').effect).toBe('ask');
  });

  it('OPC-002: gated V2 shell/edit pass; a dangerous scoped allow after the gate is critical', async () => {
    const gated = await run('OPC-002', { permissions: [
      { action: '*', resource: '*', effect: 'ask' },
      { action: 'shell', resource: 'git status *', effect: 'allow' },
      { action: 'read', resource: '*', effect: 'allow' },
    ] });
    expect(gated.passed).toBe(true);

    const open = await run('OPC-002', { permissions: [{ action: '*', resource: '*', effect: 'allow' }] });
    expect(open.severity).toBe('info');

    const curl = await run('OPC-002', { permissions: [
      { action: 'shell', resource: '*', effect: 'ask' },
      { action: 'shell', resource: 'curl *', effect: 'allow' },
      { action: 'external_directory', resource: '*', effect: 'ask' },
      { action: 'external_directory', resource: '~/**', effect: 'allow' },
    ] });
    expect(curl.severity).toBe('critical');
    expect(curl.evidence?.filter(e => !e.snippet?.startsWith('permission:')).map(e => e.snippet)).toEqual([
      'permissions[1] = { action: "shell", resource: "curl *", effect: "allow" }',
      'permissions[3] = { action: "external_directory", resource: "~/**", effect: "allow" }',
    ]);

    // An allow before the catch-all ask is overridden by it
    const overridden = await run('OPC-002', { permissions: [
      { action: 'shell', resource: 'curl *', effect: 'allow' },
      { action: '*', resource: '*', effect: 'ask' },
    ] });
    expect(overridden.passed).toBe(true);
  });

  it('OPC-003: V2 servers — unpinned package and plaintext URL; disabled skipped', async () => {
    const r = await run('OPC-003', { mcp: { servers: {
      x: { command: ['npx', '-y', 'some-unpinned-mcp'] },
      r: { type: 'remote', url: 'http://mcp.example.net/mcp' },
      off: { type: 'local', command: ['npx', '-y', 'other-unpinned'], disabled: true },
    } } });
    expect(r.evidence?.map(e => e.snippet?.split(' =')[0])).toEqual(['mcp.servers.x.command', 'mcp.servers.r.url']);
  });

  it('OPC-005 / OPC-010: V2 plugins strings and { package } objects', async () => {
    const plugins = { plugins: ['http://plugins.example.net/p.js', { package: './local-plugin.ts', options: {} }] };
    expect((await run('OPC-005', plugins)).evidence?.[0].snippet).toBe('plugins entry: http://plugins.example.net/p.js');
    expect((await run('OPC-010', plugins)).evidence?.[0].snippet).toBe('plugins entry: ./local-plugin.ts');
  });

  it('OPC-011 / OPC-012: snapshots = false and update = "disable"', async () => {
    expect((await run('OPC-011', { snapshots: false })).passed).toBe(false);
    expect((await run('OPC-011', { snapshots: true })).passed).toBe(true);
    expect((await run('OPC-012', { update: 'disable' })).passed).toBe(false);
    for (const update of ['notify', 'auto']) expect((await run('OPC-012', { update })).passed).toBe(true);
  });

  it('OPC-006: agents.<id>.permissions loosening the global rules', async () => {
    const r = await run('OPC-006', {
      permissions: [{ action: 'shell', resource: '*', effect: 'ask' }],
      agents: {
        review: { permissions: [{ action: 'shell', resource: '*', effect: 'allow' }] },
        plan: { permissions: [{ action: 'edit', resource: '*', effect: 'deny' }] },
      },
    });
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence?.[0].detail).toMatch(/"review" upgrades shell from "ask" to "allow"/);
  });
});
