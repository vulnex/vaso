import { describe, it, expect } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { cfg001 } from './cfg-001-gateway-binding.js';
import { cfg002 } from './cfg-002-api-key-exposure.js';
import { cfg004 } from './cfg-004-tls-config.js';
import { cfg005 } from './cfg-005-shell-allowlist.js';
import { cfg006 } from './cfg-006-workspace-restriction.js';
import { cfg007 } from './cfg-007-webhook-auth.js';
import { cfg008 } from './cfg-008-sandbox-disabled.js';
import { cfg009 } from './cfg-009-default-credentials.js';
import { cfg010 } from './cfg-010-rate-limiting.js';
import { cfg012 } from './cfg-012-auth-bypass.js';
import { cfg013 } from './cfg-013-dm-policy.js';
import { cfg014 } from './cfg-014-tool-policy.js';
import { cfg015 } from './cfg-015-mdns-broadcast.js';

function makeConfig(data: Record<string, unknown>, raw?: string): ParsedConfig {
  return {
    raw: raw ?? JSON.stringify(data, null, 2),
    format: 'json',
    filePath: '/tmp/test-config.json',
    data,
  };
}

function makeContext(configs: ParsedConfig[]): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: configs,
    gateway: configs.length > 0
      ? {
          host: (configs[0].data.gateway as Record<string, unknown>)?.host as string,
          port: (configs[0].data.gateway as Record<string, unknown>)?.port as number,
          tls: (configs[0].data.gateway as Record<string, unknown>)?.tls as boolean,
        }
      : undefined,
  };
  return { installation, configs, platform: 'darwin' };
}

describe('CFG-001: Gateway Binding', () => {
  it('fails when gateway bound to 0.0.0.0', async () => {
    const config = makeConfig({ gateway: { host: '0.0.0.0', port: 18789 } });
    const result = await cfg001.run(makeContext([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when gateway bound to 127.0.0.1', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1', port: 18789 } });
    const result = await cfg001.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });

  it('passes with no gateway config', async () => {
    const config = makeConfig({});
    const result = await cfg001.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-002: API Key Exposure', () => {
  it('fails when API key found in config', async () => {
    const raw = '{\n  "apiKey": "sk-abc123456789012345678901234567890123"\n}';
    const config = makeConfig({ apiKey: 'sk-abc123456789012345678901234567890123' }, raw);
    const result = await cfg002.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when AWS key found', async () => {
    const raw = '{\n  "aws": "AKIAIOSFODNN7EXAMPLE"\n}';
    const config = makeConfig({ aws: 'AKIAIOSFODNN7EXAMPLE' }, raw);
    const result = await cfg002.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes with clean config', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1' } });
    const result = await cfg002.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });

  it('skips .env files', async () => {
    const envConfig: ParsedConfig = {
      raw: 'API_KEY=sk-abc123456789012345678901234567890123',
      format: 'env',
      filePath: '/tmp/.env',
      data: { API_KEY: 'sk-abc123456789012345678901234567890123' },
    };
    const result = await cfg002.run(makeContext([envConfig]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-004: TLS Not Configured', () => {
  it('fails when TLS is not configured', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1', tls: false } });
    const ctx = makeContext([config]);
    ctx.installation.gateway = { host: '127.0.0.1', tls: false };
    const result = await cfg004.run(ctx);
    expect(result.passed).toBe(false);
  });

  it('passes when TLS is enabled', async () => {
    const raw = '{"gateway": {"tls": true}}';
    const config = makeConfig({ gateway: { tls: true } }, raw);
    const ctx = makeContext([config]);
    ctx.installation.gateway = { tls: true };
    const result = await cfg004.run(ctx);
    expect(result.passed).toBe(true);
  });
});

describe('CFG-005: Missing Shell Allowlist', () => {
  it('fails when no safeBins configured', async () => {
    const config = makeConfig({});
    const result = await cfg005.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when safeBins configured', async () => {
    const config = makeConfig({ security: { safeBins: ['ls', 'cat', 'grep'] } });
    const result = await cfg005.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-006: Workspace Restriction', () => {
  it('fails when no workspace configured', async () => {
    const config = makeConfig({});
    const result = await cfg006.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when workspace configured', async () => {
    const config = makeConfig({ workspace: '/home/user/projects' });
    const result = await cfg006.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-007: Webhook Missing Auth', () => {
  it('fails when webhook has no auth', async () => {
    const config = makeConfig({ webhooks: [{ url: 'https://example.com/hook' }] });
    const result = await cfg007.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when webhook has secret', async () => {
    const config = makeConfig({ webhooks: [{ url: 'https://example.com/hook', secret: 'abc123' }] });
    const result = await cfg007.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when no webhooks configured', async () => {
    const config = makeConfig({});
    const result = await cfg007.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-008: Sandbox Disabled', () => {
  it('fails when sandbox is false', async () => {
    const config = makeConfig({ sandbox: false });
    const result = await cfg008.run(makeContext([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when sandbox is "disabled"', async () => {
    const config = makeConfig({ sandbox: 'disabled' });
    const result = await cfg008.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when sandbox is true', async () => {
    const config = makeConfig({ sandbox: true });
    const result = await cfg008.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-009: Default Credentials', () => {
  it('fails with weak password', async () => {
    const config = makeConfig({ auth: { password: 'admin' } });
    const result = await cfg009.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('fails with "changeme"', async () => {
    const config = makeConfig({ auth: { password: 'changeme' } });
    const result = await cfg009.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes with strong credentials', async () => {
    const config = makeConfig({ auth: { password: 'xK9#mP2$vL5nQ8wR' } });
    const result = await cfg009.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-010: Rate Limiting', () => {
  it('fails when no rate limiting', async () => {
    const config = makeConfig({});
    const result = await cfg010.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when rate limiting configured', async () => {
    const config = makeConfig({ rateLimit: { max: 100, window: '1m' } });
    const result = await cfg010.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-012: Auth Bypass', () => {
  it('fails when auth bypass is true', async () => {
    const config = makeConfig({ auth: { bypass: true } });
    const result = await cfg012.run(makeContext([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when auth mode is none', async () => {
    const config = makeConfig({ gateway: { auth: { mode: 'none' } } });
    const result = await cfg012.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes with proper auth', async () => {
    const config = makeConfig({ gateway: { auth: { mode: 'bearer' } } });
    const result = await cfg012.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-013: DM Policy', () => {
  it('fails when DM policy is open', async () => {
    const config = makeConfig({ dm: { policy: 'open' } });
    const result = await cfg013.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes with restricted policy', async () => {
    const config = makeConfig({ dm: { policy: 'restricted' } });
    const result = await cfg013.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-014: Tool Policy', () => {
  it('fails when tool policy is permissive', async () => {
    const config = makeConfig({ tools: { policy: 'allow_all' } });
    const result = await cfg014.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes with allowlist policy', async () => {
    const config = makeConfig({ tools: { policy: 'allowlist' } });
    const result = await cfg014.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CFG-015: mDNS Broadcast', () => {
  it('fails when mDNS is enabled', async () => {
    const config = makeConfig({ mdns: true });
    const result = await cfg015.run(makeContext([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });

  it('passes when mDNS is not configured', async () => {
    const config = makeConfig({});
    const result = await cfg015.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});
