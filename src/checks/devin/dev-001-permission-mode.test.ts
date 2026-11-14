import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { devinChecks } from './index.js';

const USER = '/home/test/.config/devin/config.json';

function ctx(data: Record<string, unknown>, opts: { project?: boolean; agent?: 'devin' | 'windsurf' } = {}): ScanContext {
  const filePath = opts.project ? '/work/app/.devin/config.json' : USER;
  const configs: ParsedConfig[] = [{ raw: '', format: 'json', filePath, data }];
  const fs = {
    access: vi.fn(async () => false),
    readFile: vi.fn(async () => { throw new Error('ENOENT'); }),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/home/test',
    platform: 'linux',
  } as unknown as FSProvider;
  const installation: AgentInstallation = opts.project
    ? { agent: 'devin', installDir: '/work/app/.devin', configFiles: configs, profile: 'project' }
    : { agent: opts.agent ?? 'devin', installDir: '/home/test/.config/devin', configFiles: configs };
  return { installation, configs, platform: 'linux', fs };
}

const dev001 = devinChecks.find(c => c.id === 'DEV-001')!;

describe('DEV-001 permission mode', () => {
  it('is critical when sessions start in Bypass mode (permission_mode "dangerous")', async () => {
    const r = await dev001.run(ctx({ permission_mode: 'dangerous' }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].snippet).toBe('permission_mode: "dangerous"');
  });

  it('passes the other modes', async () => {
    for (const mode of ['normal', 'accept-edits', 'smart', null]) {
      expect((await dev001.run(ctx({ permission_mode: mode }))).passed, String(mode)).toBe(true);
    }
  });

  it('warns on local_tools_bypass_permissions', async () => {
    const r = await dev001.run(ctx({ local_tools_bypass_permissions: true }));
    expect(r.severity).toBe('warning');
    expect((await dev001.run(ctx({ local_tools_bypass_permissions: false }))).passed).toBe(true);
  });

  it('ignores the user-only keys in a project config and on the Devin Desktop installation', async () => {
    expect((await dev001.run(ctx({ permission_mode: 'dangerous', local_tools_bypass_permissions: true }, { project: true }))).passed).toBe(true);
    expect((await dev001.run(ctx({ permission_mode: 'dangerous' }, { agent: 'windsurf' }))).passed).toBe(true);
  });
});
