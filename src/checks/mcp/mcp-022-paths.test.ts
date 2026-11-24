import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { AgentInstallation, ScanContext } from '../../core/types.js';
import type { MCPConfig, MCPServer } from '../../mcp/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { mcp022 } from './mcp-022-world-writable-command.js';

const installation: AgentInstallation = {
  type: 'mcp', name: 'MCP', version: 'n/a', installDir: '/', configDir: '/', confidence: 1,
} as AgentInstallation;

function ctx(servers: Array<Partial<MCPServer> & { name: string }>): ScanContext {
  const config: MCPConfig = {
    source: 'project',
    filePath: '/nonexistent/mcp.json',
    servers: servers.map(s => ({ args: [], transport: 'stdio', ...s }) as MCPServer),
  };
  return { installation, configs: [], platform: process.platform as ScanContext['platform'], fs: new LocalFSProvider(), mcpConfigs: [config] };
}

/**
 * g7-F1 (dt25): MCP-022 judges launch paths through the shared
 * writable-command module (as CD-009/HM-010/AT-007), not a /tmp prefix list.
 */
describe.runIf(process.platform !== 'win32')('MCP-022 judges every spelling and wrapper of a writable launch path', () => {
  const missing = `vaso-mcp022-${process.pid}-${Date.now()}`;
  let root: string;
  beforeEach(async () => {
    root = await realpath(await mkdtemp(join('/tmp', 'vaso-mcp022-')));
    await chmod(root, 0o755);
  });
  afterEach(async () => { await rm(root, { recursive: true, force: true }); });

  it.each([
    ['//tmp', { command: `//tmp/${missing}` }],
    ['/./tmp', { command: `/./tmp/${missing}` }],
    ['python3.12 script', { command: 'python3.12', args: [`/tmp/${missing}.py`] }],
    ['uv run script', { command: 'uv', args: ['run', `/tmp/${missing}.py`] }],
    ['env wrapper', { command: 'env', args: [`/tmp/${missing}`] }],
  ])('flags %s (critical: anyone can plant it)', async (_label, srv) => {
    const r = await mcp022.run(ctx([{ name: 's', ...srv }]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].snippet).toContain(`/tmp/${missing}`);
  });

  it.runIf(process.platform === 'darwin')('flags /private/var/tmp', async () => {
    const r = await mcp022.run(ctx([{ name: 's', command: `/private/var/tmp/${missing}` }]));
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].snippet).toContain('/private/var/tmp (mode 1777)');
  });

  it('flags a command in any world-writable directory, not only /tmp', async () => {
    const dir = join(root, 'ww');
    await mkdir(dir);
    await writeFile(join(dir, 'srv.sh'), '#!/bin/sh\n');
    await chmod(join(dir, 'srv.sh'), 0o755);
    await chmod(dir, 0o777);
    const r = await mcp022.run(ctx([{ name: 's', command: join(dir, 'srv.sh') }, { name: 'n', command: 'node', args: [join(dir, 'srv.sh')] }]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence).toHaveLength(2);
    expect(r.evidence?.[0].snippet).toContain(`${dir} (mode 777)`);
  });

  it('passes a command the user owns in a safe directory, and a group-writable one', async () => {
    const safe = join(root, 'safe', 'srv.sh');
    await mkdir(join(root, 'safe'));
    await writeFile(safe, '#!/bin/sh\n');
    await chmod(safe, 0o755);
    const gw = join(root, 'gw');
    await mkdir(gw);
    await writeFile(join(gw, 'srv.sh'), '#!/bin/sh\n');
    await chmod(gw, 0o775);
    const r = await mcp022.run(ctx([{ name: 'a', command: safe }, { name: 'b', command: join(gw, 'srv.sh') }]));
    expect(r.passed).toBe(true);
  });

  it('a command the user owns in a sticky world-writable directory is protected', async () => {
    const sticky = join(root, 'sticky');
    await mkdir(sticky);
    await writeFile(join(sticky, 'srv.sh'), '#!/bin/sh\n');
    await chmod(join(sticky, 'srv.sh'), 0o755);
    await chmod(sticky, 0o1777);
    const r = await mcp022.run(ctx([{ name: 's', command: join(sticky, 'srv.sh') }]));
    expect(r.passed).toBe(true);
  });
});
