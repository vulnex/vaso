import { describe, it, expect } from 'vitest';
import type { AgentInstallation, ParsedConfig } from '../core/types.js';
import { withoutLoadedConfigs } from './project-configs.js';

const cfg = (filePath: string): ParsedConfig => ({ raw: '', format: 'json', filePath, data: {} });

describe('withoutLoadedConfigs', () => {
  const user: AgentInstallation = {
    agent: 'claude-code',
    installDir: '/home/u/.claude',
    configFiles: [cfg('/home/u/.claude/settings.json'), cfg('/home/u/.claude.json')],
  };

  it('drops project configs that are the user configs (scan run from $HOME)', () => {
    expect(withoutLoadedConfigs([cfg('/home/u/.claude/settings.json')], [user])).toEqual([]);
  });

  it('keeps genuine project configs', () => {
    const project = [cfg('/work/app/.claude/settings.json'), cfg('/home/u/.claude/settings.json')];
    expect(withoutLoadedConfigs(project, [user]).map(c => c.filePath)).toEqual(['/work/app/.claude/settings.json']);
  });
});
