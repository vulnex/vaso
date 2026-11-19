import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CheckModule, ParsedConfig, ScanContext } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { worldWritableCommandPath } from './writable-command.js';
import { hm010 } from '../checks/hermes/hm-010-mcp-server-hardening.js';
import { at007 } from '../checks/atomic-agent/at-007-mcp-server-hardening.js';
import { cd009 } from '../checks/claude-desktop/cd-009-world-writable-command.js';

const posix = process.platform !== 'win32';

/**
 * A command the owner keeps 0755 inside a directory anyone can write: any
 * local user can swap it. Judged alike locally and from a probe snapshot,
 * which carries the command's mode and its directories' modes.
 */
describe.runIf(posix)('MCP command in a world-writable directory', () => {
  let root: string;
  let cmd: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'vaso-wwdir-'));
    await mkdir(join(root, 'open'));
    await chmod(join(root, 'open'), 0o777);
    cmd = join(root, 'open', 'mcp-server');
    await writeFile(cmd, '#!/bin/sh\n');
    await chmod(cmd, 0o755);
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  /** The same host as the remote probe would ship it. */
  function snapshotOf(): SnapshotFSProvider {
    return new SnapshotFSProvider({
      version: 1, hostname: 'box', platform: process.platform === 'darwin' ? 'darwin' : 'linux', homedir: root, timestamp: 't',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { [cmd]: { content: '', mode: 0o755, exists: true, contentOmitted: true, omitted: 'metadata' } },
      directoryModes: { [join(root, 'open')]: 0o777, [root]: 0o700 },
      directories: {}, commandOutputs: {}, env: {},
    } as never);
  }

  const cases: Array<[CheckModule, ParsedConfig['format'], string, (c: string) => Record<string, unknown>]> = [
    [hm010, 'yaml', 'config.yaml', c => ({ mcp_servers: { s: { command: c } } })],
    [at007, 'json', 'config.json', c => ({ mcp: { servers: [{ name: 's', enabled: true, transport: { kind: 'stdio', command: c } }] } })],
    [cd009, 'json', 'claude_desktop_config.json', c => ({ mcpServers: { s: { command: c } } })],
  ];

  for (const [check, format, name, data] of cases) {
    it(`${check.id} flags it, locally and from a snapshot`, async () => {
      const config: ParsedConfig = { raw: '', format, filePath: join(root, name), data: data(cmd) };
      const ctx = (fs: FSProvider): ScanContext => ({
        installation: { agent: check.supportedAgents![0], installDir: root, configFiles: [config] },
        configs: [config], platform: fs.platform, fs,
      });
      const local = await check.run(ctx(new LocalFSProvider()));
      const remote = await check.run(ctx(snapshotOf()));
      for (const r of [local, remote]) {
        expect(r.passed, check.id).toBe(false);
        expect(r.evidence![0].snippet).toContain(`${join(root, 'open')} (mode `);
      }
      expect(remote.evidence).toEqual(local.evidence);
    });
  }

  it('reports the binary first, then its directory', async () => {
    expect(await worldWritableCommandPath(new LocalFSProvider(), cmd)).toEqual({ kind: 'directory', path: join(root, 'open'), octal: '777' });
    await chmod(cmd, 0o777);
    expect(await worldWritableCommandPath(new LocalFSProvider(), cmd)).toMatchObject({ kind: 'binary', path: cmd });
  });
});
