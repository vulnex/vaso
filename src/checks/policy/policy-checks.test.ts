import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm, chmod, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
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

function makeContext(
  configs: ParsedConfig[],
  installDir = '/tmp/test-install',
  credentialPaths?: string[],
): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir,
    configFiles: configs,
  };
  return { installation, configs, platform: 'darwin', fs: new LocalFSProvider(), credentialPaths };
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

  it('ignores AGENT_AUTO_APPROVE_TOOLS (IronClaw 0.x\'s own variable, judged by IC-007 from its .env)', async () => {
    process.env['AGENT_AUTO_APPROVE_TOOLS'] = 'true';
    const result = await pol001.run({ ...makeContext([]), installation: { agent: 'nanobot', installDir: '/x', configFiles: [] } });
    expect(result.passed).toBe(true);
  });

  it('does not run on OpenClaw (its exec policy is CFG-005\'s; these keys are not in its schema)', () => {
    expect(pol001.excludedAgents).toContain('openclaw');
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

  it('fails when an adapter-declared credential file is world/group readable', async () => {
    const credPath = join(tempDir, 'session.json');
    await writeFile(credPath, '{"token": "abc"}');
    await chmod(credPath, 0o644);

    const result = await pol003.run(makeContext([], tempDir, [credPath]));
    expect(result.passed).toBe(false);
    expect(result.evidence).toBeDefined();
  });

  it('fixes only the files it reports, not a declared directory (dt15)', async () => {
    const credPath = join(tempDir, 'session.json');
    const sessionDir = join(tempDir, 'session-state');
    await writeFile(credPath, '{"token": "abc"}');
    await chmod(credPath, 0o644);
    await mkdir(sessionDir);
    await chmod(sessionDir, 0o755);

    const ctx = makeContext([], tempDir, [credPath, sessionDir]);
    expect((await pol003.run(ctx)).evidence?.map(e => e.file)).toEqual([credPath]);
    const fixed = await pol003.fix!(ctx);
    expect(fixed.message).toBe('Removed group/other access from 1 file(s)');
    expect((await stat(credPath)).mode & 0o777).toBe(0o600);
    expect((await stat(sessionDir)).mode & 0o777).toBe(0o755);
  });

  it('passes when adapter-declared credential file has 0600', async () => {
    const credPath = join(tempDir, 'session.json');
    await writeFile(credPath, '{"token": "abc"}');
    await chmod(credPath, 0o600);

    const result = await pol003.run(makeContext([], tempDir, [credPath]));
    expect(result.passed).toBe(true);
  });

  it('skips when adapter declares no credential paths (no false positives on benign names)', async () => {
    // Filenames that previously fired the recursive heuristic — a sample doc, a
    // node_modules artefact, a fixture — must not produce findings now that the
    // check only looks at adapter-declared credential paths.
    await writeFile(join(tempDir, 'docs-auth.md'), '# Auth notes\n');
    await writeFile(join(tempDir, 'session-helpers.js'), 'export const x = 1;');
    await chmod(join(tempDir, 'docs-auth.md'), 0o644);
    await chmod(join(tempDir, 'session-helpers.js'), 0o644);

    const result = await pol003.run(makeContext([], tempDir));
    expect(result.passed).toBe(true);
    expect(result.message).toMatch(/does not declare credential paths/i);
  });

  it('does not flag benign files that share a credential-like name when not declared', async () => {
    // docs-auth.md is world-readable but not on the adapter's credential list,
    // so it must be ignored.
    const benign = join(tempDir, 'docs-auth.md');
    const real = join(tempDir, 'auth.json');
    await writeFile(benign, '# Auth notes\n');
    await chmod(benign, 0o644);
    await writeFile(real, '{"token":"abc"}');
    await chmod(real, 0o600);

    const result = await pol003.run(makeContext([], tempDir, [real]));
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

  it('ignores an empty or disabled sandbox section', async () => {
    for (const data of [{ isolation: {} }, { isolation: { enabled: false, expose_paths: [] } }]) {
      expect((await pol004.run(makeContext([makeConfig(data)]))).passed).toBe(true);
    }
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

  it('looks two directory levels deep, not further (the remote probe collects the same depths)', async () => {
    const key = '//registry.npmjs.org/:_authToken=ghp_abcdefghijklmnopqrstuvwxyz1234567890';
    await mkdir(join(tempDir, 'a', 'b', 'c'), { recursive: true });
    await writeFile(join(tempDir, 'a', 'b', '.npmrc'), key);
    await writeFile(join(tempDir, 'a', 'b', 'c', '.netrc'), 'machine x password ghp_abcdefghijklmnopqrstuvwxyz1234567890');
    const result = await pol005.run(makeContext([], tempDir));
    expect(result.evidence?.map(e => e.file)).toEqual([join(tempDir, 'a', 'b', '.npmrc')]);
  });

  it('passes, saying it could not check, for a credential file a remote snapshot holds without content', async () => {
    const { SnapshotFSProvider } = await import('../../core/snapshot-fs-provider.js');
    const fs = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/h', timestamp: 't',
      privilege: { uid: 1, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { '/h/.agent/.npmrc': { content: '', mode: 0o600, exists: true, contentOmitted: true, omitted: 'metadata' } },
      directories: {}, commandOutputs: {}, env: {}, directoryModes: { '/h/.agent': 0o700 },
    });
    const ctx = { ...makeContext([], '/h/.agent'), fs };
    const result = await pol005.run(ctx);
    // Nothing was read, so nothing was found — a pass that says why, not "found 1 plaintext credential"
    expect(result.passed).toBe(true);
    expect(result.message).toMatch(/1 credential file\(s\) present; their content is not collected by remote scans/);
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
