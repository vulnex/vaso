import { describe, it, expect, vi } from 'vitest';
import type { Evidence, ParsedConfig, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';

// dt21 g6-F9: a memory file with 100k+ findings errored the check
// ("Maximum call stack size exceeded") — `evidence.push(...found)` passes
// every item as an argument. The scan itself is stubbed to stay fast.
const HUGE = 300_000;
vi.mock('../analyzers/memory-secrets.js', async (orig) => ({
  ...(await orig<typeof import('../analyzers/memory-secrets.js')>()),
  scanMemorySecrets: (file: string): Evidence[] => Array.from({ length: HUGE }, (_, i) => ({ file, line: i + 1, detail: 'secret' })),
}));

const { qc010 } = await import('./qwen-code/qc-010-memory-secrets.js');
const { gem010 } = await import('./gemini-cli/gem-010-memory-secrets.js');
const { dev007 } = await import('./devin/dev-007-agents-md-secrets.js');

function run(check: typeof qc010, agent: ScanContext['installation']['agent'], installDir: string, file: string) {
  const fs = {
    platform: 'linux',
    homedir: () => '/home/test',
    getEnv: () => undefined,
    access: vi.fn(async (p: string) => p === file),
    readFile: vi.fn(async () => 'Password: x\n'),
    stat: vi.fn(async () => ({ mode: 0o100600, isFile: () => true, isDirectory: () => false })),
    readdirEntries: vi.fn(async () => []),
  } as unknown as FSProvider;
  const config: ParsedConfig = { raw: '{}', format: 'json', filePath: `${installDir}/settings.json`, data: {} };
  return check.run({ installation: { agent, installDir, configFiles: [config], profile: 'project' }, configs: [config], platform: 'linux', fs });
}

describe('memory checks with a huge number of findings (dt21 g6-F9)', () => {
  for (const [check, agent, dir, file] of [
    [qc010, 'qwen-code', '/home/test/.qwen', '/home/test/.qwen/QWEN.md'],
    [gem010, 'gemini-cli', '/home/test/.gemini', '/home/test/.gemini/GEMINI.md'],
    [dev007, 'devin', '/repo/.devin', '/repo/AGENTS.md'],
  ] as const) {
    it(`${check.id} reports them all instead of erroring`, async () => {
      const r = await run(check, agent, dir, file);
      expect(r.errored).toBeFalsy();
      expect(r.evidence).toHaveLength(HUGE);
    });
  }
});
