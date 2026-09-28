import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider, DirentInfo } from '../../core/fs-provider.js';
import { atomicAgentChecks } from './index.js';

const STATE = '/home/test/.atomic-agent';
const CONFIG_PATH = `${STATE}/config.json`;

function makeJson(data: Record<string, unknown>, filePath = CONFIG_PATH): ParsedConfig {
  return { raw: JSON.stringify(data), format: 'json', filePath, data };
}

interface FsOverrides {
  modes?: Record<string, number>;
  dirEntries?: Record<string, DirentInfo[]>;
}

function makeFs(o: FsOverrides = {}): FSProvider {
  const modes = o.modes ?? {};
  return {
    access: vi.fn(async (p: string) => p in modes || p in (o.dirEntries ?? {})),
    stat: vi.fn(async (p: string) => {
      if (p in modes) return { mode: modes[p], isFile: () => true, isDirectory: () => false };
      throw new Error(`ENOENT ${p}`);
    }),
    readFile: vi.fn(async () => { throw new Error('not used'); }),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async (p: string) => {
      if (o.dirEntries?.[p]) return o.dirEntries[p];
      throw new Error(`ENOENT ${p}`);
    }),
    realpath: vi.fn(async (p: string) => p),
    exec: vi.fn(),
    execSync: vi.fn(() => { throw new Error('not found'); }),
    homedir: () => '/home/test',
    getEnv: vi.fn(() => undefined),
    platform: 'linux',
  } as unknown as FSProvider;
}

function makeCtx(configs: ParsedConfig[], fs: FSProvider = makeFs()): ScanContext {
  const installation: AgentInstallation = {
    agent: 'atomic-agent',
    installDir: STATE,
    skillsDir: `${STATE}/skills`,
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs };
}

const check = (id: string) => atomicAgentChecks.find(c => c.id === id)!;

describe('Atomic Agent checks', () => {
  it('exports 11 checks', () => {
    expect(atomicAgentChecks).toHaveLength(11);
  });

  it('all in the atomic-agent category targeting atomic-agent', () => {
    for (const c of atomicAgentChecks) {
      expect(c.category).toBe('atomic-agent');
      expect(c.supportedAgents).toEqual(['atomic-agent']);
      expect(c.id).toMatch(/^AT-0\d{2}$/);
    }
  });

  it('a fresh default config.json only trips the shipped HTTP default (AT-003)', async () => {
    const defaults = makeJson({
      version: 72,
      agent: { approvalLevel: 1, readScope: 'working-dir' },
      http: { enabled: true, approvalMode: 'never', hostAllowlist: null },
      webhooks: {},
      mcp: { servers: [] },
      localModels: { url: 'http://127.0.0.1:8080', mode: 'managed' },
    });
    const failed: string[] = [];
    for (const c of atomicAgentChecks) {
      const r = await c.run(makeCtx([defaults]));
      if (!r.passed) failed.push(r.id);
    }
    expect(failed).toEqual(['AT-003']);
  });
});

describe('AT-001 approval ladder', () => {
  it('passes at levels 1–3', async () => {
    for (const level of [1, 2, 3]) {
      const r = await check('AT-001').run(makeCtx([makeJson({ agent: { approvalLevel: level } })]));
      expect(r.passed).toBe(true);
    }
  });

  it('warns at level 4 (operator)', async () => {
    const r = await check('AT-001').run(makeCtx([makeJson({ agent: { approvalLevel: 4 } })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
  });

  it('is critical at level 5 and for legacy approvalRequired: false', async () => {
    for (const agent of [{ approvalLevel: 5 }, { approvalRequired: false }]) {
      const r = await check('AT-001').run(makeCtx([makeJson({ agent })]));
      expect(r.passed).toBe(false);
      expect(r.severity).toBe('critical');
    }
  });
});

describe('AT-002 read scope', () => {
  it('flags unrestricted and is fixable', async () => {
    const r = await check('AT-002').run(makeCtx([makeJson({ agent: { readScope: 'unrestricted' } })]));
    expect(r.passed).toBe(false);
    expect(r.fixable).toBe(true);
  });

  it('passes working-dir and an absent key (default)', async () => {
    expect((await check('AT-002').run(makeCtx([makeJson({ agent: { readScope: 'working-dir' } })]))).passed).toBe(true);
    expect((await check('AT-002').run(makeCtx([makeJson({})]))).passed).toBe(true);
  });
});

describe('AT-003 HTTP tool without approval', () => {
  it('flags the default (absent http block)', async () => {
    expect((await check('AT-003').run(makeCtx([makeJson({})]))).passed).toBe(false);
  });

  it('passes when gated, host-restricted, or disabled', async () => {
    for (const http of [
      { approvalMode: 'writes' },
      { approvalMode: 'always' },
      { approvalMode: 'never', hostAllowlist: ['api.github.com'] },
      { enabled: false },
    ]) {
      expect((await check('AT-003').run(makeCtx([makeJson({ http })]))).passed).toBe(true);
    }
  });

  it('still flags an empty allowlist', async () => {
    const r = await check('AT-003').run(makeCtx([makeJson({ http: { approvalMode: 'never', hostAllowlist: [] } })]));
    expect(r.passed).toBe(false);
  });
});

describe('AT-004 plaintext secrets in config.json', () => {
  it('flags provider apiKey, secret headers, MCP env/headers and webhook secrets — masked', async () => {
    const cfg = makeJson({
      llm: { providers: [{ id: 'or', kind: 'openrouter', apiKey: 'sk-or-v1-abcdefghijklmnop', headers: { 'X-Api-Key': 'abcdefgh12345678' } }] },
      mcp: { servers: [{ name: 'gh', enabled: true, env: { GITHUB_TOKEN: 'ghp_' + 'a'.repeat(36) }, transport: { kind: 'streamable_http', url: 'https://x', headers: { Authorization: 'Bearer abcdefgh12345' } } }] },
      webhooks: { gh: { userMessageTemplate: 'x', secret: 'hunter2hunter2' } },
    });
    const r = await check('AT-004').run(makeCtx([cfg]));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(5);
    const text = JSON.stringify(r.evidence);
    expect(text).not.toContain('sk-or-v1-abcdefghijklmnop');
    expect(text).not.toContain('hunter2hunter2');
  });

  it('ignores apiKeyEnvVar indirection and non-secret headers', async () => {
    const cfg = makeJson({
      llm: { providers: [{ id: 'or', kind: 'openrouter', apiKeyEnvVar: 'OPENROUTER_API_KEY', headers: { 'HTTP-Referer': 'https://example.test' } }] },
      mcp: { servers: [{ name: 'fs', enabled: true, env: { LOG_LEVEL: 'debugging' }, transport: { kind: 'stdio', command: 'node' } }] },
    });
    expect((await check('AT-004').run(makeCtx([cfg]))).passed).toBe(true);
  });

  it('notes when config.json is readable by other users', async () => {
    const cfg = makeJson({ llm: { providers: [{ id: 'or', kind: 'openrouter', apiKey: 'sk-or-v1-abcdefghijklmnop' }] } });
    const r = await check('AT-004').run(makeCtx([cfg], makeFs({ modes: { [CONFIG_PATH]: 0o100644 } })));
    expect(r.evidence![0].detail).toContain('readable by other users');
  });
});

describe('AT-005 credential file permissions', () => {
  it('flags a group/world-readable .env and mail session', async () => {
    const fs = makeFs({
      modes: {
        [`${STATE}/.env`]: 0o100644,
        [`${STATE}/atomic-mail/session.json`]: 0o100640,
        '/home/test': 0o040755,
        [STATE]: 0o040755,
        [`${STATE}/atomic-mail`]: 0o040755,
      },
    });
    const r = await check('AT-005').run(makeCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(2);
    expect(r.severity).toBe('critical');
  });

  it('passes at 0600 and when the files do not exist', async () => {
    expect((await check('AT-005').run(makeCtx([], makeFs({ modes: { [`${STATE}/.env`]: 0o100600 } })))).passed).toBe(true);
    expect((await check('AT-005').run(makeCtx([]))).passed).toBe(true);
  });

  it('downgrades to info when a parent directory blocks access', async () => {
    const fs = makeFs({ modes: { [`${STATE}/.env`]: 0o100644, '/home/test': 0o040700, [STATE]: 0o040755 } });
    const r = await check('AT-005').run(makeCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
  });
});

describe('AT-006 pure_read MCP trust', () => {
  it('flags enabled pure_read servers only', async () => {
    const cfg = makeJson({
      mcp: {
        servers: [
          { name: 'a', enabled: true, trust: 'pure_read', transport: { kind: 'stdio', command: 'x' } },
          { name: 'b', enabled: false, trust: 'pure_read', transport: { kind: 'stdio', command: 'x' } },
          { name: 'c', enabled: true, trust: 'approval_gated', transport: { kind: 'stdio', command: 'x' } },
        ],
      },
    });
    const r = await check('AT-006').run(makeCtx([cfg]));
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence![0].snippet).toContain('mcp.servers[a]');
  });
});

describe('AT-007 MCP server hardening', () => {
  const run = (servers: unknown[], fs?: FSProvider) =>
    check('AT-007').run(makeCtx([makeJson({ mcp: { servers } })], fs));

  it('flags shell -c, unpinned npx, world-writable command and remote http://', async () => {
    const r = await run([
      { name: 'sh', enabled: true, transport: { kind: 'stdio', command: 'bash', args: ['-c', 'node s.js'] } },
      { name: 'np', enabled: true, transport: { kind: 'stdio', command: 'npx', args: ['-y', '@x/server'] } },
      { name: 'ww', enabled: true, transport: { kind: 'stdio', command: '/opt/mcp/run' } },
      { name: 'rh', enabled: true, transport: { kind: 'sse', url: 'http://10.0.0.5:9000/sse' } },
    ], makeFs({ modes: { '/opt/mcp/run': 0o100777 } }));
    expect(r.evidence).toHaveLength(4);
  });

  it('passes pinned packages, loopback http, https and disabled servers', async () => {
    const r = await run([
      { name: 'np', enabled: true, transport: { kind: 'stdio', command: 'npx', args: ['-y', '@x/server@1.2.3'] } },
      { name: 'uv', enabled: true, transport: { kind: 'stdio', command: 'uvx', args: ['mcp-x==0.4.1'] } },
      { name: 'lo', enabled: true, transport: { kind: 'streamable_http', url: 'http://127.0.0.1:3000/mcp' } },
      { name: 'tls', enabled: true, transport: { kind: 'streamable_http', url: 'https://mcp.example.test/mcp' } },
      { name: 'off', enabled: false, transport: { kind: 'stdio', command: 'bash', args: ['-c', 'x'] } },
    ]);
    expect(r.passed).toBe(true);
  });
});

describe('AT-008 webhook without secret', () => {
  it('flags webhooks lacking a secret', async () => {
    const cfg = makeJson({ webhooks: { open: { userMessageTemplate: '{{body.x}}' }, locked: { userMessageTemplate: 'x', secret: 's3cretvalue' } } });
    const r = await check('AT-008').run(makeCtx([cfg]));
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence![0].snippet).toContain('webhooks.open');
  });
});

describe('AT-009 subscription CLI safety override', () => {
  const provider = (cli: string, extraArgs: string[]) => makeJson({
    llm: { providers: [{ id: 'sub', kind: 'subscription-cli', subscriptionCli: { cli, extraArgs } }] },
  });

  it('flags claude flags that re-arm tools', async () => {
    for (const args of [['--tools', 'Bash'], ['--dangerously-skip-permissions'], ['--mcp-config=/x.json'], ['--permission-mode', 'bypassPermissions']]) {
      const r = await check('AT-009').run(makeCtx([provider('claude', args)]));
      expect(r.passed, args.join(' ')).toBe(false);
    }
  });

  it('flags codex sandbox overrides', async () => {
    for (const args of [['-s', 'danger-full-access'], ['--sandbox=workspace-write'], ['--full-auto'], ['--dangerously-bypass-approvals-and-sandbox'], ['-c', 'sandbox_mode="danger-full-access"']]) {
      const r = await check('AT-009').run(makeCtx([provider('codex', args)]));
      expect(r.passed, args.join(' ')).toBe(false);
    }
  });

  it('passes inference-only flags', async () => {
    expect((await check('AT-009').run(makeCtx([provider('claude', ['--effort', 'high'])]))).passed).toBe(true);
    expect((await check('AT-009').run(makeCtx([provider('codex', ['--oss'])]))).passed).toBe(true);
  });
});

describe('AT-010 plaintext inference endpoint', () => {
  it('flags remote http:// external llama-server and provider URLs', async () => {
    const cfg = makeJson({
      localModels: { mode: 'external', url: 'http://10.20.30.40:8080' },
      llm: { providers: [{ id: 'lan', kind: 'openai-compatible', baseUrl: 'http://gpu-box:11434/v1' }] },
    });
    expect((await check('AT-010').run(makeCtx([cfg]))).evidence).toHaveLength(2);
  });

  it('passes loopback, https, and managed mode', async () => {
    const cfg = makeJson({
      localModels: { mode: 'managed', url: 'http://10.20.30.40:8080' },
      llm: { providers: [
        { id: 'a', kind: 'openai-compatible', url: 'http://localhost:1234' },
        { id: 'b', kind: 'openai-compatible', baseUrl: 'https://api.example.test/v1' },
      ] },
    });
    expect((await check('AT-010').run(makeCtx([cfg]))).passed).toBe(true);
  });
});

describe('AT-011 private state permissions', () => {
  it('flags readable sqlite stores and traces', async () => {
    const fs = makeFs({
      modes: {
        '/home/test': 0o040755,
        [STATE]: 0o040775,
        [`${STATE}/traces`]: 0o040775,
        [`${STATE}/memory.sqlite`]: 0o100644,
        [`${STATE}/sessions.sqlite`]: 0o100600,
        [`${STATE}/traces/s-1.ndjson`]: 0o100664,
      },
      dirEntries: {
        [`${STATE}/traces`]: [{ name: 's-1.ndjson', isDirectory: false, isFile: true } as DirentInfo],
      },
    });
    const r = await check('AT-011').run(makeCtx([], fs));
    expect(r.evidence!.map(e => e.file)).toEqual([`${STATE}/memory.sqlite`, `${STATE}/traces/s-1.ndjson`]);
    expect(r.severity).toBe('warning');
  });

  it('passes when everything is owner-only', async () => {
    const fs = makeFs({ modes: { [`${STATE}/memory.sqlite`]: 0o100600 } });
    expect((await check('AT-011').run(makeCtx([], fs))).passed).toBe(true);
  });
});
