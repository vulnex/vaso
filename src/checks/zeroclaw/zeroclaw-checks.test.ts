import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { zeroclawChecks } from './index.js';

const FIXTURE_DIR = join(process.cwd(), 'testing', 'fixtures', 'zeroclaw');

function makeConfig(filePath: string, data: Record<string, unknown>, raw?: string): ParsedConfig {
  return {
    raw: raw ?? JSON.stringify(data, null, 2),
    format: filePath.endsWith('.toml') ? 'toml' : 'json',
    filePath,
    data,
  };
}

function makeCtx(configs: ParsedConfig[], installDir?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'zeroclaw',
    installDir: installDir ?? FIXTURE_DIR,
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux' };
}

describe('ZeroClaw checks', () => {
  it('exports 14 checks', () => {
    expect(zeroclawChecks).toHaveLength(14);
  });

  it('all checks have zeroclaw category and supportedAgents', () => {
    for (const check of zeroclawChecks) {
      expect(check.category).toBe('zeroclaw');
      expect(check.supportedAgents).toContain('zeroclaw');
    }
  });

  it('all check IDs start with ZC-', () => {
    for (const check of zeroclawChecks) {
      expect(check.id).toMatch(/^ZC-0\d{2}$/);
    }
  });
});

describe('ZC-001: Plaintext API Keys', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-001')!;

  it('fails when encrypt=false with API keys', async () => {
    const raw = 'secrets.encrypt = false\nopenai = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"';
    const config = makeConfig('config.toml', {
      secrets: { encrypt: false },
      openai: 'sk-abc123def456ghi789jkl012mno345pqr678stu901vwx',
    }, raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when encrypt=true', async () => {
    const config = makeConfig('config.toml', {
      secrets: { encrypt: true },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-002: Legacy XOR Encryption', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-002')!;

  it('fails when enc: prefix found', async () => {
    const raw = 'api_key = "enc:SGVsbG8gV29ybGQ="';
    const config = makeConfig('config.toml', { api_key: 'enc:SGVsbG8gV29ybGQ=' }, raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when no enc: prefix found', async () => {
    const raw = 'api_key = "enc2:properly-encrypted"';
    const config = makeConfig('config.toml', { api_key: 'enc2:properly-encrypted' }, raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-003: Public Bind No Tunnel', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-003')!;

  it('fails when public bind + no tunnel', async () => {
    const config = makeConfig('config.toml', {
      security: { allow_public_bind: true },
      tunnel: { provider: 'none' },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when tunnel configured', async () => {
    const config = makeConfig('config.toml', {
      security: { allow_public_bind: true },
      tunnel: { provider: 'cloudflare' },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-005: Full Autonomy', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-005')!;

  it('fails when autonomy level is full', async () => {
    const config = makeConfig('config.toml', { autonomy: { level: 'full' } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when autonomy level is supervised', async () => {
    const config = makeConfig('config.toml', { autonomy: { level: 'supervised' } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-007: Wildcard Channel Users', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-007')!;

  it('fails when * in allowed_users', async () => {
    const config = makeConfig('config.toml', {
      channels: {
        telegram: { enabled: true, allowed_users: ['*'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when specific users listed', async () => {
    const config = makeConfig('config.toml', {
      channels: {
        telegram: { enabled: true, allowed_users: ['123456789'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-010: Composio Enabled', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-010')!;

  it('fails (info) when composio enabled', async () => {
    const config = makeConfig('config.toml', {
      integrations: { composio: { enabled: true } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });

  it('passes when composio not enabled', async () => {
    const config = makeConfig('config.toml', {
      integrations: { composio: { enabled: false } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-011: Browser No Domain Allowlist', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-011')!;

  it('fails when browser enabled without allowlist', async () => {
    const config = makeConfig('config.toml', {
      tools: { browser: { enabled: true } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when browser has allowed_domains', async () => {
    const config = makeConfig('config.toml', {
      tools: { browser: { enabled: true, allowed_domains: ['example.com'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('ZC-014: No OS Sandbox', () => {
  const check = zeroclawChecks.find(c => c.id === 'ZC-014')!;

  it('fails when runtime is native without sandbox', async () => {
    const config = makeConfig('config.toml', {
      runtime: { kind: 'native' },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when using firejail', async () => {
    const config = makeConfig('config.toml', {
      runtime: { kind: 'firejail', sandbox: 'firejail' },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});
