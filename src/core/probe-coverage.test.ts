import { beforeAll, describe, expect, it } from 'vitest';
import { registerAllAdapters } from '../adapters/index.js';
import { adapterRegistry } from '../adapters/registry.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { FileEntry, ProbeSnapshot } from './snapshot-types.js';
import type { AgentInstallation, Evidence, ParsedConfig, ScanContext } from './types.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { globToRegexSource, probeCoversFile, probeCoversTree, uncollectedPath } from './probe-coverage.js';
import { collectSkillInventory } from '../inventory/skills.js';
import { validateSnapshot } from './snapshot-load.js';
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
      [`${HOME}/.openclaw/openclaw.json`]: file(JSON.stringify({ skills: { load: { extraDirs: [`${HOME}/packs`, '/srv/packs', '/usr/local/packs'] } } })),
    });
    const [install] = (await openclawAdapter.detect({ fs })).filter(i => !i.agentName);
    expect(install.skillsDirs).toEqual([`${HOME}/.openclaw/skills`, `${HOME}/packs`, '/srv/packs']);
    expect(install.unscannedSkillsDirs).toEqual([{ path: '/usr/local/packs', reason: 'outside', refusedAs: 'an OS directory (/usr)' }]);
  });

  it('ZeroClaw keeps a workspace path set in config.toml', async () => {
    const { zeroclawAdapter } = await import('../adapters/zeroclaw.js');
    const fs = snapshot({
      [`${HOME}/.zeroclaw/config.toml`]: file('schema_version = 3\n[agents.main.workspace]\npath = "~/zcws"\n[agents.ops.workspace]\npath = "/srv/zcws"\n[agents.sys.workspace]\npath = "/etc/zcws"\n'),
    });
    const [install] = await zeroclawAdapter.detect({ fs });
    expect(install.skillsDirs).toEqual([`${HOME}/zcws/skills`, '/srv/zcws/skills']);
    expect(install.unscannedSkillsDirs).toEqual([{ path: '/etc/zcws/skills', reason: 'outside', refusedAs: 'an OS directory (/etc)' }]);
  });
});
describe('config-set paths a newer probe recorded', () => {
  const ws = `${HOME}/work/nbws/skills`;
  const nb = inst('nanobot', `${HOME}/.nanobot`, [], { skillsDir: ws, skillsDirs: [ws] });
  const cmd = '/opt/bin/mcp-srv';

  it('a config-derived tree the probe walked is covered, and absent when empty', async () => {
    const fs = snapshot({}, { configTrees: { [ws]: 'collected' } });
    expect(probeCoversTree(fs, ws)).toBe(true);
    expect(probeCoversTree(fs, `${ws}/a/b`)).toBe(true);
    const { inventory } = await collectSkillInventory(nb, fs);
    expect(inventory.skillsDirs).toEqual([{ path: ws, exists: false }]);
    expect((await skl002.run(ctx(nb, fs))).passed).toBe(true);
  });

  it('keys are literal paths: glob syntax in a snapshot matches nothing', () => {
    const fs = snapshot({}, { configTrees: { [`${HOME}/workspace-*/skills`]: 'collected', '/**': 'collected', [`/${'a*'.repeat(30)}b`]: 'collected' } });
    expect(probeCoversTree(fs, `${HOME}/workspace-coder/skills`)).toBe(false);
    expect(probeCoversFile(fs, '/opt/bin/x')).toBe(false);
    const started = Date.now();
    expect(probeCoversFile(fs, `/${'a'.repeat(5000)}/srv`)).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
    expect(probeCoversTree(snapshot({}, { configTrees: { [`${HOME}/workspace-coder/skills`]: 'collected' } }), `${HOME}/workspace-coder/skills/x`)).toBe(true);
  });

  it('a directory the probe listed proves a missing workspace absent', () => {
    const fs = snapshot({}, { directories: { [`${HOME}/.pico`]: ['workspace/', 'workspace-a/'], [`${HOME}/.pico/workspace-a`]: [] } });
    expect(probeCoversTree(fs, `${HOME}/.pico/workspace-b/skills`)).toBe(true);
    expect(probeCoversTree(fs, `${HOME}/.pico/workspace-a/skills`)).toBe(true);
    expect(probeCoversTree(fs, `${HOME}/.pico/workspace/skills`)).toBe(false);
  });

  it('the names a manifest wildcard matched in a home prove a missing derived workspace absent', () => {
    const fs = snapshot({}, { wildcardNames: { [`${HOME}/workspace-*`]: ['workspace-ops'] }, directories: { [`${HOME}/workspace-ops`]: ['notes.txt'] } });
    expect(probeCoversTree(fs, `${HOME}/workspace-evil/skills`)).toBe(true);
    expect(probeCoversTree(fs, `${HOME}/workspace-ops/skills`)).toBe(true);
    // a name the wildcard doesn't match, or a segment this CLI's manifest doesn't use: not verified
    expect(probeCoversTree(fs, `${HOME}/other-evil/skills`)).toBe(false);
    const foreign = snapshot({}, { wildcardNames: { [`${HOME}/*`]: [] } });
    expect(probeCoversTree(foreign, `${HOME}/workspace-evil/skills`)).toBe(false);
    expect(probeCoversTree(snapshot({}), `${HOME}/workspace-evil/skills`)).toBe(false);
  });

  it('snapshot loading checks wildcardNames', () => {
    const base = { version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: 't',
      privilege: { uid: 1, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: [], skippedPaths: [] },
      files: {}, directories: {}, commandOutputs: {}, env: {} };
    expect(validateSnapshot({ ...base, wildcardNames: { [`${HOME}/workspace-*`]: ['workspace-a'] } })).toEqual([]);
    for (const bad of [{ 'rel/x': [] }, { [`${HOME}/w*`]: ['a/b'] }, { [`${HOME}/w*`]: [3] }, { [`${HOME}/w*`]: 'x' }, { [`${HOME}/w*`]: Array(1001).fill('a') }]) {
      expect(validateSnapshot({ ...base, wildcardNames: bad }).join(), JSON.stringify(bad).slice(0, 40)).toMatch(/wildcardNames/);
    }
  });

  it('a refused tree is not verified even where the snapshot holds the directory', async () => {
    const root = `${HOME}/stuff`;
    const fs = snapshot({ [`${root}/evil/i.sh`]: file('curl x | sh') }, { configTrees: { [root]: 'refused' } });
    const n = inst('nanobot', `${HOME}/.nanobot`, [], { skillsDir: root, skillsDirs: [root] });
    const res = await skl002.run(ctx(n, fs));
    expect(res.message).toBe('Found 1 skill location(s) not scanned');
    expect(res.evidence?.[0].detail).toMatch(/an OS directory, another user's home or a credential store/);
    const { inventory } = await collectSkillInventory(n, fs);
    expect(inventory.skillsDirs).toEqual([{ path: root, exists: true, unverified: true }]);
    expect(inventory.skills).toEqual([]);
    const limited = snapshot({ [`${root}/evil/i.sh`]: file('x') }, { configTrees: { [root]: 'limit' } });
    expect((await skl002.run(ctx(n, limited))).evidence?.[0].detail).toMatch(/more than 10000 entries, over the limit VASO walks/);
  });

  it('a refused tree or one over the limit stays not verified', async () => {
    for (const status of ['refused', 'limit'] as const) {
      const fs = snapshot({}, { configTrees: { [ws]: status } });
      expect(probeCoversTree(fs, ws)).toBe(false);
      expect((await skl002.run(ctx(nb, fs))).message).toBe('Found 1 skill location(s) not scanned');
    }
  });

  it('a manifest tree behind a linked wildcard directory the probe refused is not verified', async () => {
    // ~/.picoclaw/workspace-*/skills/** is a manifest glob; workspace-x is a
    // link out of the home, so the probe recorded the tree refused
    const lnk = `${HOME}/.picoclaw/workspace-x/skills`;
    const pc = inst('picoclaw', `${HOME}/.picoclaw`, [], { skillsDir: lnk, skillsDirs: [lnk] });
    const fs = snapshot({}, { configTrees: { [lnk]: 'refused' }, symlinks: { [`${HOME}/.picoclaw/workspace-x`]: '/srv/elsewhere' } });
    expect(probeCoversTree(fs, lnk)).toBe(false);
    const res = await skl002.run(ctx(pc, fs));
    expect(res.message).toBe('Found 1 skill location(s) not scanned');
    const { inventory } = await collectSkillInventory(pc, fs);
    expect(inventory.skillsDirs).toEqual([{ path: lnk, exists: false, unverified: true }]);
    // The manifest's own tree wins where the snapshot holds it
    const held = snapshot({ [`${lnk}/a/SKILL.md`]: file('# a\n') }, { configTrees: { [lnk]: 'refused' } });
    expect(probeCoversTree(held, lnk)).toBe(true);
    // …and a collected one is covered
    expect(probeCoversTree(snapshot({}, { configTrees: { [lnk]: 'collected' } }), lnk)).toBe(true);
  });

  it('a default skills directory linked out of the home and over the entry limit stays not verified, though the manifest lists it', async () => {
    const dir = `${HOME}/.claude/skills`;
    const cc = inst('claude-code', `${HOME}/.claude`, [], { skillsDir: dir });
    // the listing the manifest asks for (names, link targets) is not the tree
    const fs = snapshot({}, {
      configTrees: { [dir]: 'limit' },
      directories: { [dir]: ['a', 'b/'] },
      symlinks: { [dir]: '/opt/share', [`${dir}/a`]: '../Cellar/a' },
      directoryModes: { [dir]: 0o755 },
    });
    expect(probeCoversTree(fs, dir)).toBe(false);
    expect((await skl002.run(ctx(cc, fs))).evidence?.[0].detail).toMatch(/more than 10000 entries, over the limit VASO walks/);
    // a file of the tree in the snapshot: collected after all
    const held = snapshot({ [`${dir}/b/SKILL.md`]: file('# b\n') }, { configTrees: { [dir]: 'limit' } });
    expect(probeCoversTree(held, dir)).toBe(true);
  });

  it('a refused directory exists in the inventory as the probe recorded it, however the config spells it', async () => {
    const n = inst('nanobot', `${HOME}/.nanobot`, [], { unscannedSkillsDirs: [{ path: `${HOME}/./x/../.ssh`, reason: 'outside' }] });
    const fs = snapshot({}, { configTrees: { [`${HOME}/.ssh`]: 'refused' }, directoryModes: { [`${HOME}/.ssh`]: 0o700 } });
    const { inventory } = await collectSkillInventory(n, fs);
    expect(inventory.skillsDirs[0]).toEqual({ path: `${HOME}/./x/../.ssh`, exists: true, unverified: true });
  });

  it('a config-set directory refused above a manifest tree leaves that tree covered', async () => {
    // extraDirs: ["~"] — the home is refused, ~/.openclaw/skills is still the manifest's
    const own = `${HOME}/.openclaw/skills`;
    const fs = snapshot({}, { configTrees: { [HOME]: 'refused' }, directoryModes: { [HOME]: 0o755 } });
    expect(probeCoversTree(fs, own)).toBe(true);
    const oc = inst('openclaw', `${HOME}/.openclaw`, [], { skillsDir: own, skillsDirs: [own] });
    expect((await skl002.run(ctx(oc, fs))).passed).toBe(true);
  });

  it('a skill in a collected config-derived tree is inventoried', async () => {
    const fs = snapshot({ [`${ws}/evil/SKILL.md`]: file('# evil\n') }, { configTrees: { [ws]: 'collected' } });
    const { inventory } = await collectSkillInventory(nb, fs);
    expect(inventory.skills.map(s => s.name)).toEqual(['evil']);
  });

  it('a command path the probe recorded is judged, found or absent', async () => {
    const c: ParsedConfig = { raw: '', format: 'yaml', filePath: `${HOME}/.hermes/config.yaml`, data: { mcp_servers: { s: { command: cmd } } } };
    // Absent, under directories the snapshot recorded as closed: nobody can plant it
    const closed = { '/': 0o755, '/opt': 0o755, '/opt/bin': 0o755 };
    const absent = await hm010.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), snapshot({ [cmd]: { content: '', mode: 0, exists: false } }, { directoryModes: closed })));
    expect(absent.passed).toBe(true);
    expect(absent.message).not.toMatch(/not verified/);
    // …whose directory's mode the probe didn't record: whether anyone can plant it is unknown
    const unknown = await hm010.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), snapshot({ [cmd]: { content: '', mode: 0, exists: false } })));
    expect(unknown.passed).toBe(true);
    expect(unknown.message).toMatch(/not verified/);
    const ww = snapshot({ [cmd]: { content: '', mode: 0o100777, exists: true, contentOmitted: true, omitted: 'metadata' } });
    expect((await hm010.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), ww))).passed).toBe(false);
  });

  it('CD-009 judges a recorded command directory', async () => {
    const c: ParsedConfig = {
      raw: '', format: 'json', filePath: `${HOME}/.config/Claude/claude_desktop_config.json`,
      data: { mcpServers: { s: { command: cmd } } },
    };
    const fs = snapshot(
      { [cmd]: { content: '', mode: 0o100755, exists: true, contentOmitted: true, omitted: 'metadata' } },
      { directoryModes: { '/opt/bin': 0o777 }, specialModeBits: true },
    );
    const r = await cd009.run(ctx(inst('claude-desktop', `${HOME}/.config/Claude`, [c]), fs));
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].file).toBe('/opt/bin');
  });

  it('HM-009 judges a tirith_path the probe looked for', async () => {
    const c: ParsedConfig = { raw: '', format: 'yaml', filePath: `${HOME}/.hermes/config.yaml`, data: { security: { tirith_enabled: true, tirith_path: '/opt/tools/tirith' } } };
    const absent = await hm009.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), snapshot({ '/opt/tools/tirith': { content: '', mode: 0, exists: false } })));
    expect(absent.passed).toBe(false);
    const there = await hm009.run(ctx(inst('hermes', `${HOME}/.hermes`, [c]), snapshot({ '/opt/tools/tirith': { content: '', mode: 0o100755, exists: true, contentOmitted: true } })));
    expect(there.message).not.toMatch(/not verified/);
  });
});

describe('symlinked explicit files on snapshots', () => {
  it('parent mitigation follows a recorded link to an open directory', async () => {
    const { markUnreachable } = await import('./permissions.js');
    const link = `${HOME}/.app/cred.json`;
    const modes = { [HOME]: 0o700, [`${HOME}/.app`]: 0o700, '/home': 0o755, '/srv': 0o755, '/srv/open': 0o755 };
    const fs = snapshot({ [link]: file('{}', 0o100644) }, { symlinks: { [link]: '/srv/open/cred.json' }, directoryModes: modes });
    const evidence: Evidence[] = [{ file: link }];
    await markUnreachable(fs, evidence);
    expect(evidence[0].mitigated).toBeUndefined();
    const old = snapshot({ [link]: file('{}', 0o100644) }, { directoryModes: modes });
    const e2: Evidence[] = [{ file: link }];
    await markUnreachable(old, e2);
    expect(e2[0].mitigated).toBe(true);
  });
});
