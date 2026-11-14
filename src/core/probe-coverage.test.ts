import { beforeAll, describe, expect, it } from 'vitest';
import { registerAllAdapters } from '../adapters/index.js';
import { adapterRegistry } from '../adapters/registry.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { FileEntry, ProbeSnapshot } from './snapshot-types.js';
import type { AgentInstallation, ParsedConfig, ScanContext } from './types.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { globToRegexSource, probeCoversFile, probeCoversTree, uncollectedPath } from './probe-coverage.js';
import { collectSkillInventory } from '../inventory/skills.js';
import { linkInventoryFindings } from '../inventory/findings.js';
import { skl002 } from '../checks/skills/skl-002-obfuscated-code.js';
import { hm009 } from '../checks/hermes/hm-009-tirith-disabled.js';
import { hm010 } from '../checks/hermes/hm-010-mcp-server-hardening.js';
import { at007 } from '../checks/atomic-agent/at-007-mcp-server-hardening.js';
import { cd009 } from '../checks/claude-desktop/cd-009-world-writable-command.js';

const HOME = '/home/u';

function file(content = '', mode = 0o100644): FileEntry {
  return { content, mode, exists: true };
}

function snapshot(files: Record<string, FileEntry> = {}, extra: Partial<ProbeSnapshot> = {}): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1,
    hostname: 'box',
    platform: 'linux',
    homedir: HOME,
    timestamp: '2026-11-14T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files,
    directories: {},
    commandOutputs: {},
    env: {},
    ...extra,
  });
}

beforeAll(() => {
  if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
});

describe('globToRegexSource', () => {
  const m = (glob: string, path: string) => new RegExp(`^${globToRegexSource(glob)}$`).test(path);
  it('reads the probe glob syntax', () => {
    expect(m('/a/*/b', '/a/x/b')).toBe(true);
    expect(m('/a/*/b', '/a/x/y/b')).toBe(false);
    expect(m('/a/**', '/a/x/y/b')).toBe(true);
    expect(m('/a/**/c.json', '/a/c.json')).toBe(true);
    expect(m('/a/{x,y}.md', '/a/y.md')).toBe(true);
    expect(m('/a/[nN]ano', '/a/Nano')).toBe(true);
    expect(m('/a/b.c', '/a/bxc')).toBe(false);
  });
});

describe('probe coverage', () => {
  it('always covers paths on a local scan', () => {
    const fs = new LocalFSProvider();
    expect(probeCoversTree(fs, '/nowhere/skills')).toBe(true);
    expect(probeCoversFile(fs, '/nowhere/bin/tool')).toBe(true);
  });

  it('knows the default skill trees and config files of the manifest', () => {
    const fs = snapshot();
    expect(probeCoversTree(fs, `${HOME}/.nanobot/workspace/skills`)).toBe(true);
    expect(probeCoversTree(fs, `${HOME}/.claude/skills`)).toBe(true);
    expect(probeCoversTree(fs, `${HOME}/.zeroclaw/agents/main/workspace/skills`)).toBe(true);
    // OpenClaw profiles and legacy dirs have a default workspace too
    expect(probeCoversTree(fs, `${HOME}/.openclaw-ops/workspace/skills`)).toBe(true);
    expect(probeCoversTree(fs, `${HOME}/.clawdbot/workspace/skills`)).toBe(true);
    expect(probeCoversFile(fs, `${HOME}/.hermes/config.yaml`)).toBe(true);
    expect(probeCoversFile(fs, `${HOME}/.claude/skills/x/run.sh`)).toBe(true);
  });

  it('does not cover what a config points elsewhere', () => {
    const fs = snapshot();
    expect(probeCoversTree(fs, `${HOME}/work/nbws/skills`)).toBe(false);
    expect(probeCoversFile(fs, '/opt/tools/tirith')).toBe(false);
    expect(probeCoversFile(fs, `${HOME}/opt/bin/mcp-server`)).toBe(false);
  });

  it('follows ${VAR} trees through the collected environment', () => {
    expect(probeCoversTree(snapshot(), '/srv/pico/workspace/skills')).toBe(false);
    expect(probeCoversTree(snapshot({}, { env: { PICOCLAW_HOME: '/srv/pico' } }), '/srv/pico/workspace/skills')).toBe(true);
  });

  it('a snapshot path is uncollected only when outside the manifest and absent', async () => {
    const fs = snapshot({ '/opt/bin/present': file('', 0o100755) });
    expect(await uncollectedPath(fs, '/opt/bin/absent')).toBe(true);
    expect(await uncollectedPath(fs, '/opt/bin/present')).toBe(false);
    expect(await uncollectedPath(fs, `${HOME}/.hermes/bin/tirith`)).toBe(false);
    expect(await uncollectedPath(new LocalFSProvider(), '/opt/bin/absent')).toBe(false);
  });
});

function inst(agent: AgentInstallation['agent'], installDir: string, configs: ParsedConfig[], extra: Partial<AgentInstallation> = {}): AgentInstallation {
  return { agent, installDir, configFiles: configs, ...extra };
}

function ctx(installation: AgentInstallation, fs: SnapshotFSProvider): ScanContext {
  return { installation, configs: installation.configFiles as ParsedConfig[], platform: 'linux', fs };
}

describe('skills directories outside the probe manifest', () => {
  const ws = `${HOME}/work/nbws/skills`;
  const nb = inst('nanobot', `${HOME}/.nanobot`, [], { skillsDir: ws, skillsDirs: [ws] });

  it('inventory marks the directory not verified instead of absent', async () => {
    const { inventory } = await collectSkillInventory(nb, snapshot());
    expect(inventory.skillsDirs).toEqual([{ path: ws, exists: false, unverified: true }]);
    expect(inventory.incomplete?.[0]).toMatch(/not collected by the remote probe/);
  });

  it('a default directory the probe looked at stays absent', async () => {
    const def = `${HOME}/.nanobot/workspace/skills`;
    const { inventory } = await collectSkillInventory(inst('nanobot', `${HOME}/.nanobot`, [], { skillsDirs: [def] }), snapshot());
    expect(inventory.skillsDirs).toEqual([{ path: def, exists: false }]);
    expect(inventory.incomplete).toBeUndefined();
  });

  it('SKL-002 reports it as not scanned (info)', async () => {
    const r = await skl002.run(ctx(nb, snapshot()));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence?.[0]).toMatchObject({ file: ws, mitigated: true });
    expect(r.message).toBe('Found 1 skill location(s) not scanned');
  });

  it('SKL-002 says nothing about a default directory that is absent', async () => {
    const def = `${HOME}/.nanobot/workspace/skills`;
    const r = await skl002.run(ctx(inst('nanobot', `${HOME}/.nanobot`, [], { skillsDirs: [def] }), snapshot()));
    expect(r.passed).toBe(true);
  });
});

describe('HM-009 tirith_path outside the probe manifest', () => {
  const yaml = (path: string): ParsedConfig => ({
    raw: '', format: 'yaml', filePath: `${HOME}/.hermes/config.yaml`,
    data: { security: { tirith_enabled: true, tirith_path: path } },
  });

  it('is not verified on a snapshot, not missing', async () => {
    const r = await hm009.run(ctx(inst('hermes', `${HOME}/.hermes`, [yaml('/opt/tools/tirith')]), snapshot()));
    expect(r.passed).toBe(true);
    expect(r.message).toMatch(/\/opt\/tools\/tirith not verified/);
  });

  it('a tirith_path the probe collects and finds absent is still missing', async () => {
    const r = await hm009.run(ctx(inst('hermes', `${HOME}/.hermes`, [yaml(`${HOME}/.hermes/skills/tirith`)]), snapshot()));
    expect(r.passed).toBe(false);
  });
});

describe('world-writable MCP command paths on snapshots', () => {
  const cmd = '/opt/bin/mcp-srv';

  it('HM-010 says an uncollected command path is not verified', async () => {
    const c: ParsedConfig = { raw: '', format: 'yaml', filePath: `${HOME}/.hermes/config.yaml`, data: { mcp_servers: { s: { command: cmd } } } };
    const r = await hm010.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), snapshot()));
    expect(r.passed).toBe(true);
    expect(r.message).toMatch(/command path\(s\) \/opt\/bin\/mcp-srv not verified/);
  });

  it('AT-007 says an uncollected command path is not verified', async () => {
    const c: ParsedConfig = {
      raw: '', format: 'json', filePath: `${HOME}/.atomic-agent/config.json`,
      data: { mcp: { servers: [{ name: 's', transport: { kind: 'stdio', command: cmd } }] } },
    };
    const r = await at007.run(ctx(inst('atomic-agent', `${HOME}/.atomic-agent`, [c]), snapshot()));
    expect(r.passed).toBe(true);
    expect(r.message).toMatch(/not verified/);
  });

  it('CD-009 says an uncollected command path is not verified', async () => {
    const c: ParsedConfig = {
      raw: '', format: 'json', filePath: `${HOME}/.config/Claude/claude_desktop_config.json`,
      data: { mcpServers: { s: { command: cmd } } },
    };
    const r = await cd009.run(ctx(inst('claude-desktop', `${HOME}/.config/Claude`, [c]), snapshot()));
    expect(r.passed).toBe(true);
    expect(r.message).toMatch(/\/opt\/bin\/mcp-srv not verified/);
  });

  it('a collected world-writable command is still judged, and its finding links to the server', async () => {
    const c: ParsedConfig = { raw: '', format: 'yaml', filePath: `${HOME}/.hermes/config.yaml`, data: { mcp_servers: { s: { command: cmd } } } };
    const r = await hm010.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), snapshot({ [cmd]: file('', 0o100777) })));
    expect(r.passed).toBe(false);
    const inventory = {
      skillsDirs: [], skills: [], otherEntries: [],
      mcpServers: [{ name: 's', configFile: c.filePath, scope: 'user' as const, transport: 'stdio' as const, command: cmd }],
    };
    linkInventoryFindings(inventory, [r]);
    expect(inventory.mcpServers[0]).toMatchObject({ findings: ['HM-010'] });
  });

  it('CD-009 findings on the binary or its directory link to the server', () => {
    const inventory = {
      skillsDirs: [], skills: [], otherEntries: [],
      mcpServers: [
        { name: 'a', configFile: '/c.json', scope: 'user' as const, transport: 'stdio' as const, command: '/opt/bin/a' },
        { name: 'b', configFile: '/c.json', scope: 'user' as const, transport: 'stdio' as const, command: '/opt/ww/b' },
      ],
    };
    linkInventoryFindings(inventory, [{
      id: 'CD-009', name: '', category: 'coding-agent', severity: 'warning', passed: false, message: '',
      evidence: [
        { file: '/opt/bin/a', snippet: 'mcpServers.a.command = /opt/bin/a (mode 777)' },
        { file: '/opt/ww', snippet: 'mcpServers.b.command = /opt/ww/b: /opt/ww (mode 777)' },
      ],
    }]);
    expect(inventory.mcpServers.map(s => (s as { findings?: string[] }).findings)).toEqual([['CD-009'], ['CD-009']]);
  });
});

describe('config-set skill roots on snapshots', () => {
  it('OpenClaw keeps an extra skills dir the probe never collected', async () => {
    const { openclawAdapter } = await import('../adapters/openclaw.js');
    const fs = snapshot({
      [`${HOME}/.openclaw/openclaw.json`]: file(JSON.stringify({ skills: { load: { extraDirs: ['/srv/packs'] } } })),
    });
    const [install] = (await openclawAdapter.detect({ fs })).filter(i => !i.agentName);
    expect(install.skillsDirs).toEqual([`${HOME}/.openclaw/skills`, '/srv/packs']);
  });

  it('ZeroClaw keeps a workspace path set in config.toml', async () => {
    const { zeroclawAdapter } = await import('../adapters/zeroclaw.js');
    const fs = snapshot({
      [`${HOME}/.zeroclaw/config.toml`]: file('schema_version = 3\n[agents.main.workspace]\npath = "/srv/zcws"\n'),
    });
    const [install] = await zeroclawAdapter.detect({ fs });
    expect(install.skillsDirs).toEqual(['/srv/zcws/skills']);
  });
});
