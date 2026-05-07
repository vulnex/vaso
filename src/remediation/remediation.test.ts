import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFile, readFile, mkdir, rm, copyFile, stat, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { homedir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';

// IronClaw checks
import { ic001 } from '../checks/ironclaw/ic-001-webhook-binding.js';
import { ic005 } from '../checks/ironclaw/ic-005-sandbox-disabled.js';
import { ic007 } from '../checks/ironclaw/ic-007-auto-approve-tools.js';
import { ic002 } from '../checks/ironclaw/ic-002-no-tls.js';

// Config checks
import { cfg001 } from '../checks/config/cfg-001-gateway-binding.js';
import { cfg003 } from '../checks/config/cfg-003-file-permissions.js';
import { cfg008 } from '../checks/config/cfg-008-sandbox-disabled.js';

// Nanobot checks
import { nb003 } from '../checks/nanobot/nb-003-restrict-workspace.js';
import { nb004 } from '../checks/nanobot/nb-004-exec-tool-filter.js';
import { nb001 } from '../checks/nanobot/nb-001-channel-allow-from.js';

// ZeroClaw checks
import { zc001 } from '../checks/zeroclaw/zc-001-plaintext-api-keys.js';
import { zc005 } from '../checks/zeroclaw/zc-005-full-autonomy.js';
import { zc013 } from '../checks/zeroclaw/zc-013-secret-key-perms.js';
import { zc002 } from '../checks/zeroclaw/zc-002-xor-encryption.js';

// Rollback
import { rollback } from './rollback.js';

const TEST_DIR = join(tmpdir(), 'vaso-remediation-test');

beforeEach(async () => {
  await mkdir(TEST_DIR, { recursive: true });
});

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

function makeEnvConfig(filePath: string, data: Record<string, string>): ParsedConfig {
  const raw = Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  return { raw, format: 'env', filePath, data };
}

function makeJsonConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  const raw = JSON.stringify(data, null, 2);
  return { raw, format: 'json', filePath, data };
}

function makeTomlConfig(filePath: string, data: Record<string, unknown>, raw: string): ParsedConfig {
  return { raw, format: 'toml', filePath, data };
}

function makeCtx(
  agent: 'ironclaw' | 'nanobot' | 'zeroclaw' | 'openclaw',
  configs: ParsedConfig[],
  installDir?: string,
  credentialPaths?: string[],
): ScanContext {
  const installation: AgentInstallation = {
    agent,
    installDir: installDir ?? TEST_DIR,
    configFiles: configs,
  };
  return { installation, configs, platform: 'darwin', fs: new LocalFSProvider(), credentialPaths };
}

// ── IronClaw fix() tests ──────────────────────────────────────────────

describe('IronClaw fix() methods', () => {
  it('IC-001: fixes HTTP_HOST from 0.0.0.0 to 127.0.0.1 in .env', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'HTTP_HOST=0.0.0.0\nHTTP_PORT=8080\n');

    const config = makeEnvConfig(filePath, { HTTP_HOST: '0.0.0.0', HTTP_PORT: '8080' });
    const ctx = makeCtx('ironclaw', [config]);

    // Verify check fails
    const before = await ic001.run(ctx);
    expect(before.passed).toBe(false);

    // Apply fix
    const result = await ic001.fix!(ctx);
    expect(result.applied).toBe(true);
    expect(result.checkId).toBe('IC-001');

    // Re-read and re-check
    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('HTTP_HOST=127.0.0.1');
  });

  it('IC-005: fixes SANDBOX_ENABLED from false to true', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'SANDBOX_ENABLED=false\n');

    const config = makeEnvConfig(filePath, { SANDBOX_ENABLED: 'false' });
    const ctx = makeCtx('ironclaw', [config]);

    const before = await ic005.run(ctx);
    expect(before.passed).toBe(false);

    const result = await ic005.fix!(ctx);
    expect(result.applied).toBe(true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('SANDBOX_ENABLED=true');
  });

  it('IC-007: fixes AGENT_AUTO_APPROVE_TOOLS from true to false', async () => {
    const filePath = join(TEST_DIR, '.env');
    await writeFile(filePath, 'AGENT_AUTO_APPROVE_TOOLS=true\n');

    const config = makeEnvConfig(filePath, { AGENT_AUTO_APPROVE_TOOLS: 'true' });
    const ctx = makeCtx('ironclaw', [config]);

    const before = await ic007.run(ctx);
    expect(before.passed).toBe(false);

    const result = await ic007.fix!(ctx);
    expect(result.applied).toBe(true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('AGENT_AUTO_APPROVE_TOOLS=false');
  });

  it('IC-002: returns guidance-only (applied: false)', async () => {
    const config = makeEnvConfig(join(TEST_DIR, '.env'), {});
    const ctx = makeCtx('ironclaw', [config]);

    const result = await ic002.fix!(ctx);
    expect(result.applied).toBe(false);
    expect(result.message).toContain('Manual action required');
  });
});

// ── Config fix() tests ────────────────────────────────────────────────

describe('Config fix() methods', () => {
  it('CFG-001: fixes gateway.host in JSON config', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ gateway: { host: '0.0.0.0', port: 18789 } }, null, 2) + '\n');

    const config = makeJsonConfig(filePath, { gateway: { host: '0.0.0.0', port: 18789 } });
    const ctx = makeCtx('openclaw', [config]);

    const before = await cfg001.run(ctx);
    expect(before.passed).toBe(false);

    const result = await cfg001.fix!(ctx);
    expect(result.applied).toBe(true);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.gateway.host).toBe('127.0.0.1');
    // Preserve existing keys
    expect(data.gateway.port).toBe(18789);
  });

  it('CFG-003: fixes credential file permissions to 600', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, '{}');
    await chmod(filePath, 0o644);

    const config = makeJsonConfig(filePath, {});
    const ctx = makeCtx('openclaw', [config], undefined, [filePath]);

    const before = await cfg003.run(ctx);
    expect(before.passed).toBe(false);

    const result = await cfg003.fix!(ctx);
    expect(result.applied).toBe(true);

    const stats = await stat(filePath);
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it('CFG-008: fixes sandbox=false to sandbox=true', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ sandbox: false }, null, 2) + '\n');

    const config = makeJsonConfig(filePath, { sandbox: false });
    const ctx = makeCtx('openclaw', [config]);

    const before = await cfg008.run(ctx);
    expect(before.passed).toBe(false);

    const result = await cfg008.fix!(ctx);
    expect(result.applied).toBe(true);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.sandbox).toBe(true);
  });
});

// ── Nanobot fix() tests ───────────────────────────────────────────────

describe('Nanobot fix() methods', () => {
  it('NB-003: fixes restrictToWorkspace in JSON', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ restrictToWorkspace: false }, null, 2) + '\n');

    const config = makeJsonConfig(filePath, { restrictToWorkspace: false });
    const ctx = makeCtx('nanobot', [config]);

    const before = await nb003.run(ctx);
    expect(before.passed).toBe(false);

    const result = await nb003.fix!(ctx);
    expect(result.applied).toBe(true);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.restrictToWorkspace).toBe(true);
  });

  it('NB-004: adds comprehensive denyList to exec tool', async () => {
    const filePath = join(TEST_DIR, 'config.json');
    await writeFile(filePath, JSON.stringify({ tools: { exec: {} } }, null, 2) + '\n');

    const config = makeJsonConfig(filePath, { tools: { exec: {} } });
    const ctx = makeCtx('nanobot', [config]);

    const before = await nb004.run(ctx);
    expect(before.passed).toBe(false);

    const result = await nb004.fix!(ctx);
    expect(result.applied).toBe(true);

    const data = JSON.parse(await readFile(filePath, 'utf-8'));
    expect(data.tools.exec.denyList).toBeInstanceOf(Array);
    expect(data.tools.exec.denyList.length).toBeGreaterThanOrEqual(5);
    expect(data.tools.exec.denyList).toContain('rm');
    expect(data.tools.exec.denyList).toContain('curl');
  });

  it('NB-001: returns guidance-only (applied: false)', async () => {
    const config = makeJsonConfig(join(TEST_DIR, 'config.json'), {});
    const ctx = makeCtx('nanobot', [config]);

    const result = await nb001.fix!(ctx);
    expect(result.applied).toBe(false);
    expect(result.message).toContain('Manual action required');
  });
});

// ── ZeroClaw fix() tests ──────────────────────────────────────────────

describe('ZeroClaw fix() methods', () => {
  it('ZC-001: fixes secrets.encrypt in TOML', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[secrets]\nencrypt = false\n');

    const config = makeTomlConfig(filePath, { secrets: { encrypt: false } }, '[secrets]\nencrypt = false\n');
    const ctx = makeCtx('zeroclaw', [config]);

    const result = await zc001.fix!(ctx);
    expect(result.applied).toBe(true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('encrypt = true');
  });

  it('ZC-005: fixes autonomy.level from full to supervised', async () => {
    const filePath = join(TEST_DIR, 'config.toml');
    await writeFile(filePath, '[autonomy]\nlevel = "full"\n');

    const config = makeTomlConfig(filePath, { autonomy: { level: 'full' } }, '[autonomy]\nlevel = "full"\n');
    const ctx = makeCtx('zeroclaw', [config]);

    const before = await zc005.run(ctx);
    expect(before.passed).toBe(false);

    const result = await zc005.fix!(ctx);
    expect(result.applied).toBe(true);

    const content = await readFile(filePath, 'utf-8');
    expect(content).toContain('supervised');
  });

  it('ZC-013: fixes .secret_key permissions', async () => {
    const keyPath = join(TEST_DIR, '.secret_key');
    await writeFile(keyPath, 'secret-key-data');
    await chmod(keyPath, 0o644);

    const config = makeTomlConfig(join(TEST_DIR, 'config.toml'), {}, '');
    const ctx = makeCtx('zeroclaw', [config], TEST_DIR);

    const result = await zc013.fix!(ctx);
    expect(result.applied).toBe(true);

    const stats = await stat(keyPath);
    expect(stats.mode & 0o777).toBe(0o600);
  });

  it('ZC-002: returns guidance-only (applied: false)', async () => {
    const config = makeTomlConfig(join(TEST_DIR, 'config.toml'), {}, '');
    const ctx = makeCtx('zeroclaw', [config]);

    const result = await zc002.fix!(ctx);
    expect(result.applied).toBe(false);
    expect(result.message).toContain('Manual action required');
  });
});

// ── Rollback tests ────────────────────────────────────────────────────

describe('rollback', () => {
  it('restores files from a backup directory', async () => {
    // Create a "backup" directory structure simulating what RemediationEngine creates
    const backupBase = join(homedir(), '.vaso', 'backups');
    const backupTimestamp = `test-rollback-${Date.now()}`;
    const backupDir = join(backupBase, backupTimestamp);

    // The original file
    const originalFile = join(TEST_DIR, 'original.env');
    await writeFile(originalFile, 'KEY=modified\n');

    // Create backup with original content
    const backupFilePath = join(backupDir, originalFile);
    await mkdir(join(backupDir, TEST_DIR), { recursive: true });
    await writeFile(backupFilePath, 'KEY=original\n');

    // Rollback should restore
    await rollback(backupTimestamp);

    const content = await readFile(originalFile, 'utf-8');
    expect(content).toBe('KEY=original\n');

    // Cleanup backup
    await rm(backupDir, { recursive: true, force: true });
  });
});
