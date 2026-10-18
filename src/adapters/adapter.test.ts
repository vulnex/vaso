import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { AgentInstallation } from '../core/types.js';
import { credentialPathsFor } from './adapter.js';
import { copilotCliAdapter } from './copilot-cli.js';
import { cursorCliAdapter } from './cursor-cli.js';

const fs = { homedir: () => '/home/u', platform: 'linux', getEnv: () => undefined } as unknown as FSProvider;

describe('credentialPathsFor', () => {
  it('declares the user installation\'s credential stores', () => {
    const user: AgentInstallation = { agent: 'copilot-cli', installDir: '/home/u/.copilot', configFiles: [] };
    expect(credentialPathsFor(copilotCliAdapter, user, fs)).toContain('/home/u/.copilot/config.json');
  });

  it('declares none for a project installation — repo files are not credential stores (dt15 CB2)', () => {
    const copilot: AgentInstallation = { agent: 'copilot-cli', installDir: '/work/repo', configFiles: [], profile: 'project' };
    const cursor: AgentInstallation = { agent: 'cursor-cli', installDir: '/work/repo/.cursor', configFiles: [], profile: 'project' };
    expect(credentialPathsFor(copilotCliAdapter, copilot, fs)).toBeUndefined();
    expect(credentialPathsFor(cursorCliAdapter, cursor, fs)).toBeUndefined();
  });
});
