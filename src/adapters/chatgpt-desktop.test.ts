import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { chatgptDesktopAdapter } from './chatgpt-desktop.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';

function makeFs(existing: string[], versions: Record<string, string>): FSProvider {
  return {
    platform: 'darwin',
    homedir: () => '/Users/t',
    getEnv: () => undefined,
    access: async (p: string) => existing.includes(p),
    readdirEntries: async () => [],
    exec: vi.fn(async (cmd: string, args: string[]) => {
      if (cmd === 'defaults') {
        const v = versions[args[1].replace('/Contents/Info.plist', '')];
        return v ? { exitCode: 0, stdout: `${v}\n`, stderr: '' } : { exitCode: 1, stdout: '', stderr: '' };
      }
      return { exitCode: 1, stdout: '', stderr: '' };
    }),
  } as unknown as FSProvider;
}

describe('ChatGPT Desktop adapter — current and Classic apps', () => {
  it('reports ChatGPT.app as primary and ChatGPT (Classic).app as another copy', async () => {
    const fs = makeFs(
      ['/Applications/ChatGPT.app', '/Applications/ChatGPT (Classic).app', '/Users/t/Library/Application Support/com.openai.chat'],
      { '/Applications/ChatGPT.app': '26.930.31730', '/Applications/ChatGPT (Classic).app': '1.2026.184' },
    );
    const [inst] = await chatgptDesktopAdapter.detect({ fs });
    expect(inst.appBundle).toBe('/Applications/ChatGPT.app');
    expect(inst.version).toBe('26.930.31730');
    expect(inst.otherInstalls).toEqual([{ path: '/Applications/ChatGPT (Classic).app', version: '1.2026.184' }]);
  });

  it('falls back to the Classic app when it is the only one installed', async () => {
    const fs = makeFs(['/Applications/ChatGPT (Classic).app'], { '/Applications/ChatGPT (Classic).app': '1.2026.184' });
    const [inst] = await chatgptDesktopAdapter.detect({ fs });
    expect(inst.appBundle).toBe('/Applications/ChatGPT (Classic).app');
    expect(inst.version).toBe('1.2026.184');
    expect(inst.otherInstalls).toBeUndefined();
  });
});

describe('ChatGPT Desktop adapter — preference plists on a snapshot', () => {
  it('lists the workspace RemoteFeatureFlags plist the probe recorded without plutil output, as a local scan does', async () => {
    const prefs = '/Users/t/Library/Preferences';
    const flags = `${prefs}/com.openai.chat.RemoteFeatureFlags.0a1b2c3d-1111-2222-3333-444455556666.plist`;
    const statsig = `${prefs}/com.openai.chat.StatsigService.plist`;
    const meta = { content: '', mode: 0o600, exists: true, contentOmitted: true, omitted: 'metadata' as const };
    const fs = new SnapshotFSProvider({
      version: 1, hostname: 'mac', platform: 'darwin', homedir: '/Users/t', timestamp: 't',
      privilege: { uid: 501, username: 't', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['t'], skippedPaths: [] },
      files: { [flags]: meta, [statsig]: meta },
      directories: { [prefs]: [flags.split('/').pop()!, 'com.openai.chat.StatsigService.plist'], '/Users/t/Library/Application Support/com.openai.chat': [] },
      commandOutputs: {
        [`plutil -convert xml1 -o - ${statsig}`]: { stdout: '<?xml version="1.0"?><plist version="1.0"><dict><key>k</key><string>v</string></dict></plist>', stderr: '', exitCode: 0 },
      },
      env: {},
    } as unknown as ProbeSnapshot);
    const [inst] = await chatgptDesktopAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([statsig, flags]);
    expect(inst.configFiles[1].data).toEqual({});
  });
});
