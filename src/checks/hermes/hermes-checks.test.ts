import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider, DirentInfo } from '../../core/fs-provider.js';
import { hermesChecks } from './index.js';

function makeYaml(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return { raw: '', format: 'yaml', filePath, data };
}

function makeEnv(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return {
    raw: Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n'),
    format: 'env',
    filePath,
    data,
  };
}

interface FsOverrides {
  modes?: Record<string, number>;
  dirEntries?: Record<string, DirentInfo[]>;
  whichResults?: Record<string, string>;
}

function makeFs(o: FsOverrides = {}): FSProvider {
  return {
    access: vi.fn(async (p: string) => p in (o.modes ?? {}) || p in (o.dirEntries ?? {})),
    stat: vi.fn(async (p: string) => {
      if (p in (o.modes ?? {})) {
        return {
          mode: o.modes![p],
          isFile: () => !(p in (o.dirEntries ?? {})),
          isDirectory: () => p in (o.dirEntries ?? {}),
        };
      }
      throw new Error(`ENOENT ${p}`);
    }),
    readFile: vi.fn(async () => { throw new Error('not used'); }),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async (p: string) => o.dirEntries?.[p] ?? []),
    realpath: vi.fn(async (p: string) => p),
    exec: vi.fn(),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] && o.whichResults?.[args[0]]) return o.whichResults[args[0]];
      throw new Error('not found');
    }),
    homedir: () => '/home/test',
    getEnv: vi.fn(() => undefined),
    platform: 'linux',
  } as FSProvider;
}

function makeCtx(configs: ParsedConfig[], opts: { fs?: FSProvider; installDir?: string } = {}): ScanContext {
  const installDir = opts.installDir ?? '/home/test/.hermes';
  const installation: AgentInstallation = {
    agent: 'hermes',
    installDir,
    skillsDir: `${installDir}/skills`,
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: opts.fs ?? makeFs() };
}

describe('Hermes checks', () => {
  it('exports 10 checks', () => {
    expect(hermesChecks).toHaveLength(10);
  });
  it('all in hermes category targeting hermes agent', () => {
    for (const c of hermesChecks) {
      expect(c.category).toBe('hermes');
      expect(c.supportedAgents).toContain('hermes');
      expect(c.id).toMatch(/^HM-0\d{2}$/);
    }
  });
});

describe('HM-001 plaintext API keys', () => {
  const check = hermesChecks.find(c => c.id === 'HM-001')!;
  it('flags inline api_key in cli-config.yaml', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { default: 'gpt-5.5', api_key: 'sk-ant-abc1234567890abcdefghijklmnop' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes when api_key is an env reference', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { default: 'gpt-5.5', api_key: '${HERMES_API_KEY}' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
  it('flags Telegram bot token in mcp_servers.<n>.env', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      mcp_servers: { tg: { env: { TELEGRAM_BOT_TOKEN: '12345678:abcdefghijklmnopqrstuvwxyzABCDE12345' } } },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
});

describe('HM-002 .env permissions', () => {
  const check = hermesChecks.find(c => c.id === 'HM-002')!;
  it('flags .env with secrets at mode 0644', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { HERMES_API_KEY: 'sk-...' });
    const result = await check.run(makeCtx([cfg], {
      fs: makeFs({ modes: { '/h/.hermes/.env': 0o644 } }),
    }));
    expect(result.passed).toBe(false);
  });
  it('passes at mode 0600', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { HERMES_API_KEY: 'sk-...' });
    const result = await check.run(makeCtx([cfg], {
      fs: makeFs({ modes: { '/h/.hermes/.env': 0o600 } }),
    }));
    expect(result.passed).toBe(true);
  });
  it('passes when .env has no secrets', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { HERMES_DEBUG: '1' });
    const result = await check.run(makeCtx([cfg], {
      fs: makeFs({ modes: { '/h/.hermes/.env': 0o644 } }),
    }));
    expect(result.passed).toBe(true);
  });
});

describe('HM-003 credential file permissions', () => {
  const check = hermesChecks.find(c => c.id === 'HM-003')!;
  it('flags credentials.json mode 0644', async () => {
    const result = await check.run(makeCtx([], {
      fs: makeFs({ modes: { '/home/test/.hermes/credentials.json': 0o644 } }),
    }));
    expect(result.passed).toBe(false);
  });
  it('passes at mode 0600', async () => {
    const result = await check.run(makeCtx([], {
      fs: makeFs({ modes: { '/home/test/.hermes/credentials.json': 0o600 } }),
    }));
    expect(result.passed).toBe(true);
  });
});

describe('HM-004 API server bind without auth', () => {
  const check = hermesChecks.find(c => c.id === 'HM-004')!;
  it('fails when host=0.0.0.0 and key empty', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes when host=0.0.0.0 with key set', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0', API_SERVER_KEY: 'secret-token' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
  it('passes when bound to loopback', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '127.0.0.1' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
});

describe('HM-005 permissive CORS', () => {
  const check = hermesChecks.find(c => c.id === 'HM-005')!;
  it('flags non-loopback bind with empty CORS', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('flags wildcard CORS', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0', API_SERVER_CORS_ORIGINS: '*' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes when CORS is explicit', async () => {
    const cfg = makeEnv('/h/.hermes/.env', {
      API_SERVER_HOST: '0.0.0.0',
      API_SERVER_CORS_ORIGINS: 'https://app.example.com',
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
});

describe('HM-006 plaintext http endpoint', () => {
  const check = hermesChecks.find(c => c.id === 'HM-006')!;
  it('flags http:// in model.base_url', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { base_url: 'http://attacker.example/v1' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes for loopback http', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { base_url: 'http://127.0.0.1:11434/v1' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
  it('passes for https', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { base_url: 'https://api.openai.com/v1' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
});

describe('HM-007 untrusted custom endpoint', () => {
  const check = hermesChecks.find(c => c.id === 'HM-007')!;
  it('flags unknown host', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { base_url: 'https://attacker.evil/v1' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes for known provider (chatgpt.com)', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { base_url: 'https://chatgpt.com/backend-api/codex' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
  it('passes for loopback (HM-006 territory, not HM-007)', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      model: { base_url: 'http://localhost:11434' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
});

describe('HM-008 approvals disabled', () => {
  const check = hermesChecks.find(c => c.id === 'HM-008')!;
  it('flags approvals.mode: off', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', { approvals: { mode: 'off' } });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('flags HERMES_YOLO_MODE=1', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { HERMES_YOLO_MODE: '1' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes for approvals.mode: manual', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', { approvals: { mode: 'manual' } });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
});

describe('HM-009 Tirith disabled', () => {
  const check = hermesChecks.find(c => c.id === 'HM-009')!;
  it('flags tirith_enabled: false', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', { security: { tirith_enabled: false } });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('flags fail-open without binary', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      security: { tirith_enabled: true, tirith_fail_open: true },
    });
    const result = await check.run(makeCtx([cfg], { fs: makeFs({}) }));
    expect(result.passed).toBe(false);
  });
  it('passes when fail-open and binary present', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      security: { tirith_enabled: true, tirith_fail_open: true },
    });
    const result = await check.run(makeCtx([cfg], {
      fs: makeFs({ whichResults: { tirith: '/usr/local/bin/tirith' } }),
    }));
    expect(result.passed).toBe(true);
  });
});

describe('HM-010 MCP server hardening', () => {
  const check = hermesChecks.find(c => c.id === 'HM-010')!;
  it('flags shell-c invocation', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      mcp_servers: { foo: { command: 'bash', args: ['-c', 'curl -s …'] } },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('flags unpinned npx package', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      mcp_servers: { foo: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-foo'] } },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
  });
  it('passes for pinned package', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      mcp_servers: { foo: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-foo@1.2.3'] } },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
});
