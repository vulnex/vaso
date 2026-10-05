import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { chatgptDesktopAdapter } from './chatgpt-desktop.js';

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
