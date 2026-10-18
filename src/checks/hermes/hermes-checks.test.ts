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
  it('exports 11 checks', () => {
    expect(hermesChecks).toHaveLength(11);
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
  it('does not treat long prose (personality prompts with emoji) as a credential', async () => {
    const cfg = makeYaml('/h/.hermes/config.yaml', {
      agent: { personalities: {
        kawaii: 'You are a kawaii assistant! ✨ Use cute expressions like (◕‿◕), ★ and ♡ — end with ~nya (｡♥‿♥｡)',
        hype: 'YOU ARE THE HYPE BOT 🔥🚀💯 — every answer is LEGENDARY, use ALL CAPS and emoji 🎉⚡️🙌',
      } },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
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
  const at = (configs: ParsedConfig[], version?: string): ScanContext => {
    const ctx = makeCtx(configs);
    ctx.installation.version = version;
    return ctx;
  };
  it('fails critical when host=0.0.0.0 and key empty before the start-up guard (< 0.9.0)', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0' });
    const result = await check.run(at([cfg], '0.8.0'));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });
  it('downgrades to info when the Hermes version is unknown', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });
  it('passes when the release refuses to start the server without a usable key', async () => {
    const env = makeEnv('/h/.hermes/.env', { API_SERVER_ENABLED: 'true', API_SERVER_HOST: '0.0.0.0' });
    for (const v of ['0.9.0', '0.15.0', '0.21.6']) {
      const r = await check.run(at([env], v));
      expect(r.passed, v).toBe(true);
    }
    // 0.18.0+: a placeholder / short key is refused too
    const weak = makeYaml('/h/.hermes/config.yaml', { gateway: { api_server: { host: '0.0.0.0', key: 'changeme' } } });
    expect((await check.run(at([weak], '0.21.6'))).message).toContain('refuses to start');
  });
  it('honours config.yaml over API_SERVER_HOST when the env block carries no usable key', async () => {
    const yaml = makeYaml('/h/.hermes/config.yaml', { gateway: { api_server: { host: '127.0.0.1' } } });
    // Before 0.19.1 the env block applies alongside API_SERVER_ENABLED (or any key)…
    const env = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0' });
    expect((await check.run(at([yaml, env], '0.8.0'))).passed).toBe(true);
    const enabled = makeEnv('/h/.hermes/.env', { API_SERVER_ENABLED: 'true', API_SERVER_HOST: '0.0.0.0' });
    expect((await check.run(at([yaml, enabled], '0.8.0'))).passed).toBe(false);
    // …and with no version known, only alongside a usable env key (current releases)
    expect((await check.run(at([yaml, enabled]))).passed).toBe(true);
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
  it('reads host and key from config.yaml gateway.api_server', async () => {
    const open = makeYaml('/h/.hermes/config.yaml', { gateway: { api_server: { host: '0.0.0.0' } } });
    expect((await check.run(makeCtx([open]))).passed).toBe(false);
    expect((await check.run(at([open], '0.8.0'))).severity).toBe('critical');
    const keyed = makeYaml('/h/.hermes/config.yaml', { gateway: { api_server: { host: '0.0.0.0', key: 'secret-token' } } });
    expect((await check.run(makeCtx([keyed]))).passed).toBe(true);
    const extra = makeYaml('/h/.hermes/config.yaml', { platforms: { api_server: { extra: { host: '0.0.0.0', key: 'k' } } } });
    expect((await check.run(makeCtx([extra]))).passed).toBe(true);
  });
});

describe('HM-005 permissive CORS', () => {
  const check = hermesChecks.find(c => c.id === 'HM-005')!;
  it('passes a non-loopback bind with no CORS origins (Hermes sends no CORS headers)', async () => {
    const cfg = makeEnv('/h/.hermes/.env', { API_SERVER_HOST: '0.0.0.0' });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
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
  it('flags an uppercase HTTP:// scheme', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      mcp_servers: { remote: { url: 'HTTP://mcp.example.org/sse' } },
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
  it('judges only inference base_urls, not remote MCP server URLs', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      mcp_servers: { linear: { url: 'https://mcp.linear.app/sse' } },
      model: { base_url: 'https://api.z.ai/api/paas/v4' },
      auxiliary: { vision: { base_url: 'https://api.moonshot.ai/v1' } },
      delegation: { base_url: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1' },
      fallback: { base_url: 'https://api.minimax.io/v1' },
    });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(true);
  });
  it('does not accept a lookalike of a known provider', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', { model: { base_url: 'https://evil-openrouter.ai/v1' } });
    expect((await check.run(makeCtx([cfg]))).passed).toBe(false);
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
  it('flags YAML booleans that PyYAML loads as False (mode: false / no)', async () => {
    for (const mode of [false, 'no', 'Off']) {
      const cfg = makeYaml('/h/.hermes/config.yaml', { approvals: { mode } });
      expect((await check.run(makeCtx([cfg]))).passed, String(mode)).toBe(false);
    }
  });
  it('flags cron_mode / unattended_mode: approve', async () => {
    const cfg = makeYaml('/h/.hermes/config.yaml', { approvals: { mode: 'smart', cron_mode: 'approve', unattended_mode: 'approve' } });
    const result = await check.run(makeCtx([cfg]));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(2);
    const deny = makeYaml('/h/.hermes/config.yaml', { approvals: { mode: 'smart', cron_mode: 'deny' } });
    expect((await check.run(makeCtx([deny]))).passed).toBe(true);
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
  it('no finding for a config at v50+, where Hermes removed tirith (911da42); v49 still flagged', async () => {
    const v51 = makeYaml('/h/.hermes/config.yaml', { _config_version: 51, security: { tirith_enabled: true, tirith_fail_open: true } });
    expect((await check.run(makeCtx([v51], { fs: makeFs({}) }))).passed).toBe(true);
    const v49 = makeYaml('/h/.hermes/config.yaml', { _config_version: 49, security: { tirith_enabled: false } });
    expect((await check.run(makeCtx([v49]))).passed).toBe(false);
  });
  it('flags fail-open without binary', async () => {
    const cfg = makeYaml('/h/.hermes/cli-config.yaml', {
      security: { tirith_enabled: true, tirith_fail_open: true },
    });
    const result = await check.run(makeCtx([cfg], { fs: makeFs({}) }));
    expect(result.passed).toBe(false);
  });
  it('finds the auto-installed binary at $HERMES_HOME/bin/tirith (not on PATH)', async () => {
    const cfg = makeYaml('/home/test/.hermes/config.yaml', { security: { tirith_enabled: true } });
    const fs = makeFs({ modes: { '/home/test/.hermes/bin/tirith': 0o100755 } });
    expect((await check.run(makeCtx([cfg], { fs }))).passed).toBe(true);
  });
  it('honours TIRITH_ENABLED=false in .env over config.yaml', async () => {
    const cfg = makeYaml('/home/test/.hermes/config.yaml', { security: { tirith_enabled: true, tirith_fail_open: false } });
    const env = makeEnv('/home/test/.hermes/.env', { TIRITH_ENABLED: 'false' });
    const result = await check.run(makeCtx([cfg, env]));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].snippet).toBe('TIRITH_ENABLED=false');
    // Blank falls back to config.yaml
    const blank = makeEnv('/home/test/.hermes/.env', { TIRITH_ENABLED: '' });
    expect((await check.run(makeCtx([cfg, blank]))).passed).toBe(true);
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
