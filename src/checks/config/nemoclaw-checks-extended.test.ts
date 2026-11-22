import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';

vi.mock('node:os', () => ({ homedir: () => '/mock-home' }));
vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
  readFile: vi.fn(),
  readdir: vi.fn(),
  stat: vi.fn(),
  realpath: vi.fn(),
}));

import { access, readFile, stat } from 'node:fs/promises';
import { cfg020 } from './cfg-020-nemoclaw-api-key-exposure.js';
import { cfg021 } from './cfg-021-nemoclaw-gpu-isolation.js';
import { cfg022 } from './cfg-022-nemoclaw-policy-scope.js';
import { cfg023 } from './cfg-023-nemoclaw-model-pinning.js';
import { cfg024 } from './cfg-024-nemoclaw-default-sandbox.js';

const mockAccess = vi.mocked(access);
const mockReadFile = vi.mocked(readFile);
const mockStat = vi.mocked(stat);

function makeContext(): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: 'linux', fs: new LocalFSProvider() };
}

function allowPath(...paths: string[]) {
  mockAccess.mockImplementation(async (p) => {
    if (paths.some(allowed => (p as string).startsWith(allowed))) return;
    throw new Error('ENOENT');
  });
}

const SANDBOXES_VALID = JSON.stringify({
  sandboxes: {
    'my-assistant': {
      name: 'my-assistant',
      model: 'nvidia/nemotron-3-super-120b-a12b',
      nimContainer: null,
      provider: 'nvidia-nim',
      gpuEnabled: true,
      policies: ['pypi', 'npm'],
    },
  },
  defaultSandbox: 'my-assistant',
});

beforeEach(() => {
  vi.clearAllMocks();
  mockAccess.mockRejectedValue(new Error('ENOENT'));
  mockReadFile.mockRejectedValue(new Error('ENOENT'));
  mockStat.mockRejectedValue(new Error('ENOENT'));
});

// --- CFG-020: NemoClaw API Key Exposure ---

describe('CFG-020: NemoClaw API Key Exposure', () => {
  it('passes when no credentials file exists', async () => {
    const result = await cfg020.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('No NemoClaw credentials file found');
  });

  it('detects a plaintext API key — a warning in an owner-only file (NemoClaw writes it 0600 in a 0700 dir)', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      NVIDIA_API_KEY: 'nvapi-FAKETESTKEYDONOTUSE00000000000000000000000000000000000000000',
    }));
    mockStat.mockImplementation((async (p: string) => ({ mode: p.endsWith('.json') ? 0o100600 : 0o40700 })) as never);
    const result = await cfg020.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.message).toContain('plaintext API keys');
    expect(result.evidence).toBeDefined();
    expect(result.evidence!.some(e => e.detail!.includes('nvapi-FA'))).toBe(false);
    expect(result.evidence!.some(e => /<literal, \d+ chars>/.test(e.detail!))).toBe(true);
  });

  it('is critical when other users can read the plaintext key', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      NVIDIA_API_KEY: 'nvapi-FAKETESTKEYDONOTUSE00000000000000000000000000000000000000000',
    }));
    mockStat.mockImplementation((async (p: string) => ({ mode: p.endsWith('.json') ? 0o100644 : 0o40755 })) as never);
    const result = await cfg020.run(makeContext());
    expect(result.severity).toBe('critical');
    expect(result.message).toContain('overly permissive');
  });

  it('is a warning when the readable file sits in a private directory', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({ NVIDIA_API_KEY: 'nvapi-FAKETESTKEYDONOTUSE000000000000000000000000' }));
    mockStat.mockImplementation((async (p: string) => ({ mode: p.endsWith('.json') ? 0o100644 : p.endsWith('.nemoclaw') ? 0o40700 : 0o40755 })) as never);
    expect((await cfg020.run(makeContext())).severity).toBe('warning');
  });

  it('detects overly permissive file permissions', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({}));
    mockStat.mockResolvedValue({ mode: 0o100644 } as any);
    const result = await cfg020.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('overly permissive');
    expect(result.evidence!.some(e => e.detail!.includes('644'))).toBe(true);
  });

  it('passes when credentials file has no keys and secure perms', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({ note: 'placeholder' }));
    mockStat.mockResolvedValue({ mode: 0o100600 } as any);
    const result = await cfg020.run(makeContext());
    expect(result.passed).toBe(true);
  });

  it('detects sk- prefixed keys', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      openai_token: 'sk-1234567890abcdef1234567890abcdef',
    }));
    const result = await cfg020.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail!.includes('sk-12345'))).toBe(false);
  });

  it('is fixable when permissions are loose', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({ NVIDIA_API_KEY: 'nvapi-test1234' }));
    mockStat.mockResolvedValue({ mode: 0o100644 } as any);
    const result = await cfg020.run(makeContext());
    expect(result.fixable).toBe(true);
  });

  it('has correct metadata', () => {
    expect(cfg020.id).toBe('CFG-020');
    expect(cfg020.severity).toBe('critical');
    expect(cfg020.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
    expect(cfg020.fix).toBeDefined();
  });
});

// --- CFG-021: NemoClaw GPU Isolation ---

describe('CFG-021: NemoClaw GPU Isolation', () => {
  it('passes when no sandboxes file exists', async () => {
    const result = await cfg021.run(makeContext());
    expect(result.passed).toBe(true);
  });

  it('fails when the host GPU is passed into the sandbox', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(SANDBOXES_VALID);
    const result = await cfg021.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('host GPU passed through');
    expect(result.evidence!.some(e => e.detail!.includes('my-assistant'))).toBe(true);
  });

  // nimContainer is the local NIM inference server, not GPU isolation
  it('a NIM inference container does not make GPU passthrough safe', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: { box: { gpuEnabled: true, sandboxGpuEnabled: true, sandboxGpuMode: '1', nimContainer: 'nvcr.io/nim/nemotron:0.1.0' } },
    }));
    expect((await cfg021.run(makeContext())).passed).toBe(false);
  });

  it('reads the effective sandboxGpuEnabled (NemoClaw status: sandboxGpuEnabled ?? gpuEnabled)', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: { box: { gpuEnabled: false, hostGpuDetected: true, sandboxGpuEnabled: false, sandboxGpuMode: '0', nimContainer: null } },
    }));
    expect((await cfg021.run(makeContext())).passed).toBe(true);
  });

  it('passes when no sandboxes defined', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({ sandboxes: {} }));
    const result = await cfg021.run(makeContext());
    expect(result.passed).toBe(true);
  });

  it('handles corrupt JSON', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue('not json{{{');
    const result = await cfg021.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('could not be parsed');
  });

  it('has correct metadata', () => {
    expect(cfg021.id).toBe('CFG-021');
    expect(cfg021.severity).toBe('warning');
    expect(cfg021.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});

// --- CFG-022: NemoClaw Policy Scope ---

describe('CFG-022: NemoClaw Policy Scope', () => {
  it('passes when no sandboxes file exists', async () => {
    const result = await cfg022.run(makeContext());
    expect(result.passed).toBe(true);
  });

  // NemoClaw presets are egress allowances (npm, pypi, docker, slack, …):
  // there is no filesystem/network/syscall preset to be "missing"
  it('reports recorded presets as egress allowances, without failing', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(SANDBOXES_VALID);
    const result = await cfg022.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence!.every(e => e.detail!.includes('egress presets'))).toBe(true);
    expect(result.evidence!.some(e => e.detail!.includes('missing'))).toBe(false);
  });

  it('an empty preset list (default-deny egress) passes', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: {
        'bare-box': { policies: [] },
      },
    }));
    const result = await cfg022.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence![0].detail).toContain('[none]');
  });

  it('has correct metadata', () => {
    expect(cfg022.id).toBe('CFG-022');
    expect(cfg022.severity).toBe('warning');
    expect(cfg022.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});

// --- CFG-023: NemoClaw Model Pinning ---

describe('CFG-023: NemoClaw Model Pinning', () => {
  it('passes when no sandboxes file exists', async () => {
    const result = await cfg023.run(makeContext());
    expect(result.passed).toBe(true);
  });

  it('passes when model has version specifier', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(SANDBOXES_VALID);
    const result = await cfg023.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence!.some(e => e.detail!.includes('version-pinned'))).toBe(true);
  });

  it('fails when model uses latest tag', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: {
        'risky-box': {
          model: 'nvidia/nemotron:latest',
        },
      },
    }));
    const result = await cfg023.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('unpinned or mutable');
    expect(result.evidence!.some(e => e.detail!.includes('mutable tag'))).toBe(true);
  });

  it('fails when no model specified', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: {
        'no-model': {},
      },
    }));
    const result = await cfg023.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail!.includes('no model specified'))).toBe(true);
  });

  it('detects nightly mutable tag', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: {
        'dev-box': {
          model: 'nvidia/nemotron:nightly',
        },
      },
    }));
    const result = await cfg023.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail!.includes('nightly'))).toBe(true);
  });

  it('has correct metadata', () => {
    expect(cfg023.id).toBe('CFG-023');
    expect(cfg023.severity).toBe('info');
    expect(cfg023.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});

// --- CFG-024: NemoClaw Default Sandbox ---

describe('CFG-024: NemoClaw Default Sandbox', () => {
  it('passes when no sandboxes file exists', async () => {
    const result = await cfg024.run(makeContext());
    expect(result.passed).toBe(true);
  });

  it('passes when defaultSandbox references valid sandbox', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(SANDBOXES_VALID);
    const result = await cfg024.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('my-assistant');
  });

  it('fails when defaultSandbox is missing', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: { 'box-a': {} },
    }));
    const result = await cfg024.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('No defaultSandbox set');
  });

  it('fails when defaultSandbox references nonexistent sandbox', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: { 'box-a': {} },
      defaultSandbox: 'deleted-sandbox',
    }));
    const result = await cfg024.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('does not match');
    expect(result.evidence!.some(e => e.detail!.includes('Dangling'))).toBe(true);
  });

  it('passes (CFG-017 reports it) when no sandbox is registered, even with a defaultSandbox', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      sandboxes: {},
      defaultSandbox: 'orphan',
    }));
    const result = await cfg024.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('CFG-017');
  });

  it('handles corrupt JSON', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue('}{bad json');
    const result = await cfg024.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('could not be parsed');
  });

  it('has correct metadata', () => {
    expect(cfg024.id).toBe('CFG-024');
    expect(cfg024.severity).toBe('warning');
    expect(cfg024.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});
