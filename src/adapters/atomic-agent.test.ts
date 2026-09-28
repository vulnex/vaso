import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig } from '../core/types.js';
import { atomicAgentAdapter } from './atomic-agent.js';

interface FakeFs {
  files?: Record<string, string>;
  dirs?: string[];
  env?: Record<string, string>;
  which?: string;
  version?: string;
}

function makeFs(o: FakeFs = {}): FSProvider {
  const files = o.files ?? {};
  const dirs = new Set(o.dirs ?? []);
  return {
    homedir: () => '/home/t',
    platform: 'linux',
    access: vi.fn(async (p: string) => p in files || dirs.has(p)),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error(`ENOENT ${p}`);
    }),
    stat: vi.fn(async (p: string) => ({ mode: 0o100600, isFile: () => p in files, isDirectory: () => dirs.has(p) })),
    readdirEntries: vi.fn(async () => []),
    realpath: vi.fn(async (p: string) => p),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] === 'atomic-agent' && o.which) return o.which;
      if (args[0] === '--version' && o.version) return o.version;
      throw new Error('not found');
    }),
    getEnv: vi.fn((k: string) => o.env?.[k]),
  } as unknown as FSProvider;
}

const CONFIG = JSON.stringify({
  version: 72,
  localModels: { mode: 'managed', managed: { modelId: 'gemma-4-12b' } },
  agent: { approvalLevel: 1, readScope: 'working-dir' },
});

describe('Atomic Agent adapter', () => {
  it('returns nothing when the state dir is absent', async () => {
    expect(await atomicAgentAdapter.detect({ fs: makeFs() })).toEqual([]);
  });

  it('requires config.json or .env — a bare state dir is not an install', async () => {
    const fs = makeFs({ dirs: ['/home/t/.atomic-agent'] });
    expect(await atomicAgentAdapter.detect({ fs })).toEqual([]);
  });

  it('detects ~/.atomic-agent with config.json, .env, version and binary', async () => {
    const fs = makeFs({
      dirs: ['/home/t/.atomic-agent'],
      files: {
        '/home/t/.atomic-agent/config.json': CONFIG,
        '/home/t/.atomic-agent/.env': 'OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxx\n',
        '/home/t/.local/bin/atomic-agent': '',
      },
      version: 'atomic-agent 0.6.5',
    });
    const [inst] = await atomicAgentAdapter.detect({ fs });
    expect(inst.agent).toBe('atomic-agent');
    expect(inst.installDir).toBe('/home/t/.atomic-agent');
    expect(inst.version).toBe('0.6.5');
    expect(inst.cliBinary).toBe('/home/t/.local/bin/atomic-agent');
    expect(inst.skillsDir).toBe('/home/t/.atomic-agent/skills');
    expect(inst.configFiles.map(c => c.format)).toEqual(['json', 'env']);
    expect(inst.models).toEqual([{ id: 'gemma-4-12b', provider: 'llama-server' }]);
    expect(inst.gateway).toBeUndefined();
  });

  it('honours ATOMIC_AGENT_STATE_DIR from the scanned host', async () => {
    const fs = makeFs({
      dirs: ['/srv/atomic'],
      files: { '/srv/atomic/config.json': CONFIG },
      env: { ATOMIC_AGENT_STATE_DIR: '/srv/atomic' },
    });
    const [inst] = await atomicAgentAdapter.detect({ fs });
    expect(inst.installDir).toBe('/srv/atomic');
  });

  it('declares .env as the credential file and the sqlite stores as memory', () => {
    expect(atomicAgentAdapter.getCredentialPaths!('/s')).toEqual(['/s/.env']);
    expect(atomicAgentAdapter.getMemoryFiles!('/s')).toContain('/s/memory.sqlite');
  });

  it('keeps private stores metadata-only in the probe manifest', () => {
    const m = atomicAgentAdapter.getProbeManifest!();
    expect(m.filePaths.some(p => p.endsWith('.sqlite'))).toBe(false);
    expect(m.metadataGlobPatterns).toContain('~/.atomic-agent/*.sqlite');
    expect(m.metadataGlobPatterns).toContain('~/.atomic-agent/traces/*');
  });
});

describe('Atomic Agent getModels', () => {
  const cfg = (data: Record<string, unknown>): ParsedConfig[] =>
    [{ raw: '', format: 'json', filePath: '/s/config.json', data }];

  it('lists the active provider first, other providers as slots, then the managed local model', () => {
    const models = atomicAgentAdapter.getModels!(cfg({
      llm: {
        activeTextProvider: 'or',
        providers: [
          { id: 'local', kind: 'llama-server' },
          { id: 'gem', kind: 'gemini', model: 'gemini-3-pro' },
          { id: 'or', kind: 'openrouter', defaultChatModel: 'anthropic/claude-opus-5' },
        ],
      },
      localModels: { managed: { modelId: 'qwen-3.5-4b' } },
    }));
    expect(models).toEqual([
      { id: 'anthropic/claude-opus-5', provider: 'openrouter' },
      { id: 'gemini-3-pro', provider: 'gemini', via: 'gem' },
      { id: 'qwen-3.5-4b', provider: 'llama-server', via: 'localModels' },
    ]);
  });

  it('returns nothing without config.json', () => {
    expect(atomicAgentAdapter.getModels!([])).toEqual([]);
  });
});
