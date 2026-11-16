import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';
import { loadPlistAsConfig } from './plist-config.js';
import { cfg002 } from '../checks/config/cfg-002-api-key-exposure.js';
import type { ScanContext } from '../core/types.js';

const XML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>userEmail</key><string>jane.doe@example.com</string>
<key>apiKey</key><string>sk-proj-Ab3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5pR7tV9xZ1bD3fH5</string>
</dict></plist>
`;

function fsWith(result: { exitCode: number; stdout: string; stderr: string }): FSProvider {
  return {
    kind: 'local',
    exists: async () => true,
    access: async () => true,
    stat: async () => ({ isFile: () => true, isDirectory: () => false }),
    exec: async () => result,
  } as unknown as FSProvider;
}

describe('plist configs', () => {
  it('one key per line: a finding quotes the key it found, not the account email', async () => {
    const config = await loadPlistAsConfig('/h/Library/Preferences/com.openai.chat.StatsigService.plist', fsWith({ exitCode: 0, stdout: XML, stderr: '' }));
    expect(config).toBeDefined();
    const ctx = { configs: [config!], installation: { agent: 'chatgpt-desktop', installDir: '/Applications/ChatGPT.app', configFiles: [] }, platform: 'darwin', fs: fsWith({ exitCode: 0, stdout: '', stderr: '' }) } as unknown as ScanContext;
    const result = await cfg002.run(ctx);
    expect(result.passed).toBe(false);
    const snippets = (result.evidence ?? []).map(e => e.snippet ?? '').join('\n');
    expect(snippets).toContain('apiKey');
    expect(snippets).not.toContain('jane.doe');
  });

  it("plutil's parse error is reported without the file's text", async () => {
    const { loadErrors } = await captureConfigLoadErrors(async () => {
      await loadPlistAsConfig('/h/x.plist', fsWith({ exitCode: 1, stdout: '', stderr: '/h/x.plist: Property List error: Encountered unknown tag hunter2PLANTED on line 3' }));
    });
    expect(loadErrors).toHaveLength(1);
    expect(loadErrors[0].message).toBe('not a valid property list (plutil exited with 1)');
  });
});
