import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { pol001 } from './pol-001-exec-approval.js';
import { pol002 } from './pol-002-log-redaction.js';
import { pol003 } from './pol-003-session-credentials.js';
import { pol004 } from './pol-004-sandbox-enforcement.js';
import { pol005 } from './pol-005-plaintext-credentials.js';

function makeConfig(data: Record<string, unknown>): ParsedConfig {
  return {
    raw: JSON.stringify(data, null, 2),
    format: 'json',
    filePath: '/tmp/test-config.json',
    data,
  };
}

function makeContext(configs: ParsedConfig[], installDir = '/tmp/test-install'): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir,
    configFiles: configs,
  };
  return { installation, configs, platform: 'darwin', fs: new LocalFSProvider() };
}

// POL-001
describe('POL-001: Exec Approval Required', () => {
  const origEnv = process.env['AGENT_AUTO_APPROVE_TOOLS'];

  afterEach(() => {
    if (origEnv !== undefined) {
      process.env['AGENT_AUTO_APPROVE_TOOLS'] = origEnv;
    } else {
      delete process.env['AGENT_AUTO_APPROVE_TOOLS'];
    }
  });

  it('fails when auto_approve is true', async () => {
    const config = makeConfig({ auto_approve: true });
    const result = await pol001.run(makeContext([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
  });

  it('passes when no auto-approve config', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1' } });
    const result = await pol001.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });

  it('passes with no configs', async () => {
    const result = await pol001.run(makeContext([]));
    expect(result.passed).toBe(true);
  });

  it('fails when AGENT_AUTO_APPROVE_TOOLS env var is set', async () => {
    process.env['AGENT_AUTO_APPROVE_TOOLS'] = 'true';
    const result = await pol001.run(makeContext([]));
    expect(result.passed).toBe(false);
    expect(result.evidence!.some(e => e.detail?.includes('AGENT_AUTO_APPROVE_TOOLS'))).toBe(true);
  });
});

// POL-002
describe('POL-002: Log Redaction', () => {
  it('fails when logging enabled without redaction', async () => {
    const config = makeConfig({ logging: { enabled: true } });
    const result = await pol002.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when logging enabled with redaction', async () => {
    const config = makeConfig({ logging: { enabled: true, redact: true } });
    const result = await pol002.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when no logging configured', async () => {
    const config = makeConfig({ gateway: { host: '127.0.0.1' } });
    const result = await pol002.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

// POL-003
describe('POL-003: Session Credential Permissions', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-pol003-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('fails with permissive session file', async () => {
    await writeFile(join(tempDir, 'session.json'), '{"token": "abc"}');
    await chmod(join(tempDir, 'session.json'), 0o644);

    const result = await pol003.run(makeContext([], tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
  });

  it('passes with restrictive session file', async () => {
    await writeFile(join(tempDir, 'session.json'), '{"token": "abc"}');
    await chmod(join(tempDir, 'session.json'), 0o600);

    const result = await pol003.run(makeContext([], tempDir));
    expect(result.passed).toBe(true);
  });
});

// POL-004
describe('POL-004: Sandbox Policy Enforcement', () => {
  it('fails when sandbox enabled with 0 constraints', async () => {
    const config = makeConfig({ sandbox: true });
    const result = await pol004.run(makeContext([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when sandbox has 2+ constraints', async () => {
    const config = makeConfig({
      sandbox: {
        allowedExec: ['/usr/bin/node'],
        allowedPaths: ['/workspace'],
        allowedHosts: ['localhost'],
      },
    });
    const result = await pol004.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when sandbox is disabled', async () => {
    const config = makeConfig({ sandbox: false });
    const result = await pol004.run(makeContext([config]));
    expect(result.passed).toBe(true);
  });
});

// POL-005
describe('POL-005: Plaintext Credential Files', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-pol005-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('fails when credential file contains API key', async () => {
    await writeFile(join(tempDir, '.npmrc'), '//registry.npmjs.org/:_authToken=ghp_abcdefghijklmnopqrstuvwxyz1234567890');

    const result = await pol005.run(makeContext([], tempDir));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
  });

  it('passes with clean credential file', async () => {
    await writeFile(join(tempDir, '.npmrc'), 'registry=https://registry.npmjs.org/');

    const result = await pol005.run(makeContext([], tempDir));
    expect(result.passed).toBe(true);
  });

  it('passes when no credential files exist', async () => {
    await writeFile(join(tempDir, 'readme.txt'), 'nothing here');

    const result = await pol005.run(makeContext([], tempDir));
    expect(result.passed).toBe(true);
  });
});
