import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation, ParsedConfig } from '../core/types.js';
import { scanCwd, withoutLoadedConfigs } from './project-configs.js';

const cfg = (filePath: string): ParsedConfig => ({ raw: '', format: 'json', filePath, data: {} });

/** realpath that resolves /var → /private/var, as on macOS */
const fs = {
  realpath: async (p: string) => (p.startsWith('/var/') ? `/private${p}` : p),
} as unknown as FSProvider;

describe('withoutLoadedConfigs', () => {
  const user: AgentInstallation = {
    agent: 'claude-code',
    installDir: '/home/u/.claude',
    configFiles: [cfg('/home/u/.claude/settings.json'), cfg('/home/u/.claude.json')],
  };

  it('drops project configs that are the user configs (scan run from $HOME)', async () => {
    expect(await withoutLoadedConfigs([cfg('/home/u/.claude/settings.json')], [user], fs)).toEqual([]);
  });

  it('keeps genuine project configs', async () => {
    const project = [cfg('/work/app/.claude/settings.json'), cfg('/home/u/.claude/settings.json')];
    expect((await withoutLoadedConfigs(project, [user], fs)).map(c => c.filePath)).toEqual(['/work/app/.claude/settings.json']);
  });

  it('matches a $HOME spelled through a symlink against the real working directory', async () => {
    const linked: AgentInstallation = { agent: 'claude-code', installDir: '/var/h/.claude', configFiles: [cfg('/var/h/.claude/settings.json')] };
    expect(await withoutLoadedConfigs([cfg('/private/var/h/.claude/settings.json')], [linked], fs)).toEqual([]);
  });
});

describe('scanCwd', () => {
  it('is the working directory for a local scan', () => {
    expect(scanCwd({ kind: 'local' } as FSProvider)).toBe(process.cwd());
    expect(scanCwd({} as FSProvider)).toBe(process.cwd());
  });

  it('is undefined for a remote/snapshot scan — this process\'s cwd says nothing about that host', () => {
    expect(scanCwd({ kind: 'snapshot' } as FSProvider)).toBeUndefined();
  });
});
