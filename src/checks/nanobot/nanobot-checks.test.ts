import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { nanobotChecks } from './index.js';

const FIXTURE_DIR = join(process.cwd(), 'testing', 'fixtures', 'nanobot');

function makeConfig(filePath: string, data: Record<string, unknown>, raw?: string): ParsedConfig {
  return {
    raw: raw ?? JSON.stringify(data, null, 2),
    format: 'json',
    filePath,
    data,
  };
}

function makeCtx(configs: ParsedConfig[], installDir?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'nanobot',
    installDir: installDir ?? FIXTURE_DIR,
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux' };
}

describe('Nanobot checks', () => {
  it('exports 12 checks', () => {
    expect(nanobotChecks).toHaveLength(12);
  });

  it('all checks have nanobot category and supportedAgents', () => {
    for (const check of nanobotChecks) {
      expect(check.category).toBe('nanobot');
      expect(check.supportedAgents).toContain('nanobot');
    }
  });

  it('all check IDs start with NB-', () => {
    for (const check of nanobotChecks) {
      expect(check.id).toMatch(/^NB-0\d{2}$/);
    }
  });
});

describe('NB-001: Empty Channel allowFrom', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-001')!;

  it('fails when channels have empty allowFrom', async () => {
    const config = makeConfig('config.json', {
      channels: {
        telegram: { enabled: true, allowFrom: [] },
        discord: { enabled: true, allowFrom: [] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence).toHaveLength(2);
  });

  it('passes when channels have allowFrom entries', async () => {
    const config = makeConfig('config.json', {
      channels: {
        telegram: { enabled: true, allowFrom: ['123456789'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-002: Plaintext Secrets', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-002')!;

  it('fails when API keys are in plaintext', async () => {
    const raw = JSON.stringify({
      openaiApiKey: 'sk-abc123def456ghi789jkl012mno345pqr678stu901vwx',
    });
    const config = makeConfig('config.json', JSON.parse(raw), raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when no API keys found', async () => {
    const raw = JSON.stringify({ host: '127.0.0.1', port: 18790 });
    const config = makeConfig('config.json', JSON.parse(raw), raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-003: Workspace Restriction', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-003')!;

  it('fails when restrictToWorkspace is false', async () => {
    const config = makeConfig('config.json', { restrictToWorkspace: false });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when restrictToWorkspace is true', async () => {
    const config = makeConfig('config.json', { restrictToWorkspace: true });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-004: Exec Tool Filter', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-004')!;

  it('fails when denyList is too short', async () => {
    const config = makeConfig('config.json', {
      tools: { exec: { enabled: true, denyList: ['rm', 'shutdown'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when denyList is comprehensive', async () => {
    const config = makeConfig('config.json', {
      tools: { exec: { enabled: true, denyList: ['rm', 'shutdown', 'reboot', 'mkfs', 'dd', 'kill'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-005: SSRF WebFetch', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-005')!;

  it('fails when no host restrictions configured', async () => {
    const config = makeConfig('config.json', {
      tools: { webFetch: { enabled: true } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when blockedHosts configured', async () => {
    const config = makeConfig('config.json', {
      tools: { webFetch: { enabled: true, blockedHosts: ['localhost', '127.0.0.1'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-011: No Rate Limit', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-011')!;

  it('fails when no rate limiting on channels', async () => {
    const config = makeConfig('config.json', {
      channels: { telegram: { enabled: true } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when rate limiting configured', async () => {
    const config = makeConfig('config.json', {
      channels: { telegram: { enabled: true, rateLimit: { maxRequests: 10 } } },
      rateLimit: { maxRequests: 100 },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-012: ClawHub via npx', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-012')!;

  it('fails when skillSource is npx', async () => {
    const raw = JSON.stringify({ skillSource: 'npx' });
    const config = makeConfig('config.json', JSON.parse(raw), raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when no npx references', async () => {
    const raw = JSON.stringify({ skillSource: 'local' });
    const config = makeConfig('config.json', JSON.parse(raw), raw);
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});
