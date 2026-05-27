import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
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

// ---- Filesystem-backed Nanobot checks ----

function makeFsCtx(configs: ParsedConfig[], installDir: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'nanobot',
    installDir,
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: new LocalFSProvider() };
}

describe('NB-006: HEARTBEAT.md Injection Risk', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-006')!;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-nb006-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no HEARTBEAT.md is present', async () => {
    const result = await check.run(makeFsCtx([], tempDir));
    expect(result.passed).toBe(true);
  });

  it('flags HEARTBEAT.md when world-writable', async () => {
    const workspace = join(tempDir, 'workspace');
    await mkdir(workspace, { recursive: true });
    const heartbeat = join(workspace, 'HEARTBEAT.md');
    await writeFile(heartbeat, '# pulse\n');
    await chmod(heartbeat, 0o666);
    const result = await check.run(makeFsCtx([], tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence![0].detail).toContain('world-writable');
  });
});

describe('NB-007: MEMORY.md Prompt Injection', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-007')!;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-nb007-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when MEMORY.md is absent', async () => {
    const result = await check.run(makeFsCtx([], tempDir));
    expect(result.passed).toBe(true);
  });

  it('flags MEMORY.md when memory is enabled in config and file exists', async () => {
    const memoryDir = join(tempDir, 'workspace', 'memory');
    await mkdir(memoryDir, { recursive: true });
    const memory = join(memoryDir, 'MEMORY.md');
    await writeFile(memory, '# remembered context\n');
    const raw = JSON.stringify({ memory: true });
    const config = makeConfig('config.json', { memory: true }, raw);
    const result = await check.run(makeFsCtx([config], tempDir));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });
});

describe('NB-008: Empty Bridge Token', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-008')!;

  it('fails when a WhatsApp bridge channel has empty bridge_token', async () => {
    const config = makeConfig('config.json', {
      channels: {
        wa: { type: 'whatsapp', bridge_token: '' },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when bridge_token is configured', async () => {
    const config = makeConfig('config.json', {
      channels: {
        wa: { type: 'whatsapp', bridge_token: 'persistent-secret' },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('NB-009: Unencrypted Session Files', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-009')!;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-nb009-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when no session files exist', async () => {
    const config = makeConfig('config.json', {});
    const result = await check.run(makeFsCtx([config], tempDir));
    expect(result.passed).toBe(true);
  });

  it('flags session files when encryption is not configured', async () => {
    const sessions = join(tempDir, 'sessions');
    await mkdir(sessions, { recursive: true });
    await writeFile(join(sessions, 'a.jsonl'), '{"role":"user"}\n');
    const config = makeConfig('config.json', {});
    const result = await check.run(makeFsCtx([config], tempDir));
    expect(result.passed).toBe(false);
  });

  it('passes when session encryption is enabled', async () => {
    const sessions = join(tempDir, 'sessions');
    await mkdir(sessions, { recursive: true });
    await writeFile(join(sessions, 'a.jsonl'), '{"role":"user"}\n');
    const config = makeConfig('config.json', { sessions: { encryption: true } });
    const result = await check.run(makeFsCtx([config], tempDir));
    expect(result.passed).toBe(true);
  });
});

describe('NB-010: Unrestricted Cron Channels', () => {
  const check = nanobotChecks.find(c => c.id === 'NB-010')!;

  it('fails when a cron job has no channel or recipient restriction', async () => {
    const config = makeConfig('config.json', {
      cron: { daily: { schedule: '0 9 * * *', message: 'morning ping' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when a cron job targets channel "*"', async () => {
    const config = makeConfig('config.json', {
      cron: { broadcast: { schedule: '* * * * *', channel: '*' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when each cron job restricts its channel', async () => {
    const config = makeConfig('config.json', {
      cron: { daily: { schedule: '0 9 * * *', channel: 'team-alerts', allowedRecipients: ['ops@example.com'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});
