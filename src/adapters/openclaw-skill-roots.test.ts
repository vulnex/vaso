import { describe, it, expect } from 'vitest';
import { openclawAdapter } from './openclaw.js';


describe('OpenClaw skill roots', () => {
  it('adds the workspace skills/ and skills.load.extraDirs that exist', async () => {
    const { SnapshotFSProvider } = await import('../core/snapshot-fs-provider.js');
    const f = (content: string) => ({ exists: true, mode: 0o600, content });
    const fs = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: 't',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: {
        '/home/u/.openclaw/openclaw.json': f(JSON.stringify({ agents: { defaults: { workspace: '~/ws' } }, skills: { load: { extraDirs: ['/srv/packs', '/missing'] } } })),
        '/home/u/ws/skills/a/SKILL.md': f('x'),
        '/home/u/.openclaw/skills/b/SKILL.md': f('x'),
        '/srv/packs/c/SKILL.md': f('x'),
      },
      directories: {}, commandOutputs: {}, env: {},
    });
    const [install] = (await openclawAdapter.detect({ fs })).filter(i => !i.agentName);
    expect(install.skillsDirs).toEqual(['/home/u/.openclaw/skills', '/home/u/ws/skills', '/srv/packs']);
  });
});
