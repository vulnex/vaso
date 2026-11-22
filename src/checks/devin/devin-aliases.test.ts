import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { devinChecks } from './index.js';

const USER = '/home/test/.config/devin/config.json';

function ctx(data: Record<string, unknown>): ScanContext {
  const configs: ParsedConfig[] = [{ raw: '', format: 'json', filePath: USER, data }];
  const fs = {
    access: vi.fn(async () => false),
    readFile: vi.fn(async () => { throw new Error('ENOENT'); }),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/home/test',
    platform: 'linux',
  } as unknown as FSProvider;
  const installation: AgentInstallation = { agent: 'devin', installDir: '/home/test/.config/devin', configFiles: configs };
  return { installation, configs, platform: 'linux', fs };
}

const byId = (id: string) => devinChecks.find(c => c.id === id)!;

describe('Devin aliases and URL keys (dt24)', () => {
  it('DEV-001 treats "yolo" and "bypass" as Bypass mode', async () => {
    for (const mode of ['yolo', 'bypass', 'Bypass']) {
      const r = await byId('DEV-001').run(ctx({ permission_mode: mode }));
      expect(r.severity, mode).toBe('critical');
    }
  });

  it('DEV-005 reads serverUrl as well as url', async () => {
    const r = await byId('DEV-005').run(ctx({ mcpServers: { a: { serverUrl: 'http://mcp.corp.example.com/mcp' }, b: { serverUrl: 'http://127.0.0.1:3000/mcp' } } }));
    expect(r.evidence?.map(e => e.snippet)).toEqual(['mcpServers.a.serverUrl: http://mcp.corp.example.com/mcp']);
  });

  it('DEV-003 flags tokens in args and in the URL, never quoting them', async () => {
    const gh = 'ghp_Jr5Qw8Mt2Zk7Vn4Hb9Lc3Ys6Fd1Gp0Ue2Wax';
    const key = 'sk-proj-Hk3Lq9Zm2Vx7Rt5Wb8Nc4Py1Jd6Gs0Fa';
    const r = await byId('DEV-003').run(ctx({ mcpServers: {
      a: { command: 'npx', args: ['-y', 'srv@1.0.0', '--token', gh] },
      b: { serverUrl: `https://mcp.example.com/mcp?api_key=${key}` },
      c: { command: 'npx', args: ['-y', 'srv@1.0.0', '--token', '${env:GH_TOKEN}'] },
    } }));
    expect(r.passed).toBe(false);
    expect(r.evidence?.map(e => e.snippet?.split(' = ')[0])).toEqual(['mcpServers.a.args[3]', 'mcpServers.b.serverUrl']);
    const text = JSON.stringify(r.evidence);
    expect(text).not.toContain(gh.slice(4, 12));
    expect(text).not.toContain(key.slice(8, 16));
  });

  it('DEV-010 normalises versioned interpreters (python3)', async () => {
    const r = await byId('DEV-010').run(ctx({ sandbox: { excluded: { allow: ['Exec(python3)', 'Exec(ls -la)'] } } }));
    expect(r.passed).toBe(false);
    expect(r.evidence?.map(e => e.snippet)).toEqual(['sandbox.excluded.allow: "Exec(python3)"']);
  });
});
