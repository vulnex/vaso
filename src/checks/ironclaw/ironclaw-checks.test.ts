import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { ironclawChecks } from './index.js';

const FIXTURE_DIR = join(process.cwd(), 'testing', 'fixtures', 'ironclaw');

function makeConfig(filePath: string, data: Record<string, unknown>, raw?: string): ParsedConfig {
  return {
    raw: raw ?? JSON.stringify(data, null, 2),
    format: filePath.endsWith('.toml') ? 'toml' : filePath.endsWith('.env') ? 'env' : 'json',
    filePath,
    data,
  };
}

function makeCtx(configs: ParsedConfig[], installDir?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'ironclaw',
    installDir: installDir ?? FIXTURE_DIR,
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux' };
}

describe('IronClaw checks', () => {
  it('exports 12 checks', () => {
    expect(ironclawChecks).toHaveLength(12);
  });

  it('all checks have ironclaw category and supportedAgents', () => {
    for (const check of ironclawChecks) {
      expect(check.category).toBe('ironclaw');
      expect(check.supportedAgents).toContain('ironclaw');
    }
  });

  it('all check IDs start with IC-', () => {
    for (const check of ironclawChecks) {
      expect(check.id).toMatch(/^IC-0\d{2}$/);
    }
  });
});

describe('IC-001: HTTP Webhook Public Bind', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-001')!;

  it('fails when HTTP_HOST=0.0.0.0', async () => {
    const config = makeConfig('.env', { HTTP_HOST: '0.0.0.0', HTTP_PORT: '8080' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when HTTP_HOST=127.0.0.1', async () => {
    const config = makeConfig('.env', { HTTP_HOST: '127.0.0.1', HTTP_PORT: '8080' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('IC-005: Sandbox Disabled', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-005')!;

  it('fails when SANDBOX_ENABLED=false', async () => {
    const config = makeConfig('.env', { SANDBOX_ENABLED: 'false' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when SANDBOX_ENABLED=true', async () => {
    const config = makeConfig('.env', { SANDBOX_ENABLED: 'true' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('IC-006: Sandbox Full Access', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-006')!;

  it('fails when SANDBOX_POLICY=full_access', async () => {
    const config = makeConfig('.env', { SANDBOX_POLICY: 'full_access' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when SANDBOX_POLICY=restricted', async () => {
    const config = makeConfig('.env', { SANDBOX_POLICY: 'restricted' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('IC-007: Auto-Approve Tools', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-007')!;

  it('fails when AGENT_AUTO_APPROVE_TOOLS=true', async () => {
    const config = makeConfig('.env', { AGENT_AUTO_APPROVE_TOOLS: 'true' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when AGENT_AUTO_APPROVE_TOOLS=false', async () => {
    const config = makeConfig('.env', { AGENT_AUTO_APPROVE_TOOLS: 'false' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('IC-009: Secrets Key in .env', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-009')!;

  it('fails when SECRETS_MASTER_KEY is present', async () => {
    const config = makeConfig('.env', { SECRETS_MASTER_KEY: 'my-secret-key' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when SECRETS_MASTER_KEY is absent', async () => {
    const config = makeConfig('.env', { OTHER_KEY: 'value' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('IC-010: Telegram Without Owner ID', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-010')!;

  it('fails when token set but no owner', async () => {
    const config = makeConfig('.env', {
      TELEGRAM_TOKEN: '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi',
      TELEGRAM_OWNER_ID: '',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when both token and owner set', async () => {
    const config = makeConfig('.env', {
      TELEGRAM_TOKEN: '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi',
      TELEGRAM_OWNER_ID: '123456789',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('IC-012: Docker Auto-Pull No Digest', () => {
  const check = ironclawChecks.find(c => c.id === 'IC-012')!;

  it('fails when auto-pull without digest', async () => {
    const config = makeConfig('.env', {
      SANDBOX_AUTO_PULL: 'true',
      SANDBOX_DOCKER_IMAGE: 'ironclaw/sandbox:latest',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when using digest-pinned image', async () => {
    const config = makeConfig('.env', {
      SANDBOX_AUTO_PULL: 'true',
      SANDBOX_DOCKER_IMAGE: 'ironclaw/sandbox@sha256:abcdef1234567890',
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});
