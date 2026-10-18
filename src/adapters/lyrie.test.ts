import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ProbeSnapshot } from '../core/snapshot-types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { lyrieAdapter, findLyrieCheckouts, isLyrieCheckout, lyrieShieldBinaryPaths } from './lyrie.js';

const HOME = '/home/test';
const STATE = `${HOME}/.lyrie`;
const PKG = (version: string, name = 'lyrie-agent') => JSON.stringify({ name, version, workspaces: ['packages/core'] });

/** In-memory FSProvider: `files` have content, `dirs` exist, `env` is the host env. */
function memFs(files: Record<string, string>, dirs: string[] = [], env: Record<string, string> = {}): FSProvider {
  const has = (p: string) => p in files || dirs.includes(p)
    || Object.keys(files).some(f => f.startsWith(`${p}/`));
  return {
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error(`ENOENT: ${p}`);
      return files[p];
    },
    readBytes: async () => new Uint8Array(),
    readdir: async () => [],
    readdirEntries: async () => [],
    access: async (p: string) => has(p),
    stat: async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false }),
    realpath: async (p: string) => p,
    readlink: async () => { throw new Error('not a link'); },
    exec: async () => ({ stdout: '', stderr: '', exitCode: 1 }),
    execSync: () => { throw new Error('exec not expected'); },
    getEnv: (k: string) => env[k],
    platform: 'linux',
    homedir: () => HOME,
    hostname: () => 'test-host',
  } as FSProvider;
}

/** Live-like layout: checkout at ~/lyrie-ai (.env from .env.example + real
 *  keys), ~/.lyrie state from the Python CLI and a nanobot migration. */
function liveLayout(extra: Record<string, string> = {}): Record<string, string> {
  return {
    [`${HOME}/lyrie-ai/package.json`]: PKG('3.4.0'),
    [`${HOME}/lyrie-ai/.env`]: [
      'ANTHROPIC_API_KEY=sk-ant-...',
      'LYRIE_MODE=hybrid',
      'LYRIE_SHIELD_MODE=active',
      'NODE_ENV=development',
      'ANTHROPIC_API_KEY=sk-ant-api03-TESTTESTTEST',
      'LYRIE_TELEGRAM_TOKEN=7000000001:AAtest',
      'LYRIE_WEBCHAT_ENABLED=true',
      'LYRIE_WEBCHAT_HOST=0.0.0.0',
    ].join('\n'),
    [`${STATE}/config.json`]: JSON.stringify({ ANTHROPIC_API_KEY: 'sk-ant-api03-TEST' }),
    [`${STATE}/migrations/nanobot-1.json`]: JSON.stringify({ platform: 'nanobot', success: true, errors: [] }),
    ...extra,
  };
}

describe('Lyrie adapter', () => {
  it('returns [] when neither a checkout nor ~/.lyrie state exists', async () => {
    expect(await lyrieAdapter.detect({ fs: memFs({}) })).toEqual([]);
  });

  it('detects the checkout, loads its .env and the Python CLI key store, version from package.json', async () => {
    const [inst] = await lyrieAdapter.detect({ fs: memFs(liveLayout(), [`${STATE}/skills`]) });
    expect(inst.agent).toBe('lyrie');
    expect(inst.installDir).toBe(`${HOME}/lyrie-ai`);
    expect(inst.version).toBe('3.4.0');
    expect(inst.cliBinary).toBeUndefined();
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/lyrie-ai/.env`, `${STATE}/config.json`]);
    const env = inst.configFiles[0];
    expect(env.format).toBe('env');
    expect(env.data.LYRIE_TELEGRAM_TOKEN).toBe('7000000001:AAtest');
    expect(env.data.ANTHROPIC_API_KEY).toBe('sk-ant-api03-TESTTESTTEST'); // last duplicate wins
    expect(inst.skillsDir).toBe(`${STATE}/skills`);
    // WebChat is enabled on 0.0.0.0 but 3.4.0 binds nothing — no gateway reported
    expect(inst.gateway).toBeUndefined();
  });

  it('never reports the Python lyrie CLI (lyrie-omega) version as the agent version', async () => {
    const fs = memFs({ [`${STATE}/config.json`]: '{}', [`${HOME}/.local/bin/lyrie`]: '#!/usr/bin/env python3' });
    const [inst] = await lyrieAdapter.detect({ fs });
    expect(inst.installDir).toBe(STATE);
    expect(inst.version).toBeUndefined();
    expect(inst.otherInstalls).toBeUndefined();
  });

  it('ignores directories whose package.json is not lyrie-agent', async () => {
    const fs = memFs({ [`${HOME}/lyrie/package.json`]: PKG('1.0.0', 'lyrie-website') });
    expect(await lyrieAdapter.detect({ fs })).toEqual([]);
    expect(await isLyrieCheckout(`${HOME}/lyrie`, fs)).toBe(false);
  });

  it('finds a checkout cloned into ~/.lyrie by the upstream installer', async () => {
    const fs = memFs({ [`${STATE}/package.json`]: PKG('3.4.0'), [`${STATE}/.env`]: 'NODE_ENV=production' });
    const [inst] = await lyrieAdapter.detect({ fs });
    expect(inst.installDir).toBe(STATE);
    expect(inst.version).toBe('3.4.0');
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${STATE}/.env`]);
  });

  it('prefers the checkout referenced by the installed service unit and lists other checkouts', async () => {
    const files = {
      [`${HOME}/lyrie-ai/package.json`]: PKG('3.3.0'),
      [`${HOME}/lyrie-ai/.env`]: 'NODE_ENV=production',
      [`${HOME}/work/lyrie-prod/package.json`]: PKG('3.4.0'),
      [`${HOME}/work/lyrie-prod/.env`]: 'LYRIE_TELEGRAM_TOKEN=1:x',
      [`${HOME}/.config/systemd/user/ai-lyrie-daemon.service`]: [
        '[Service]',
        'Type=simple',
        `ExecStart=${HOME}/.bun/bin/bun run ${HOME}/work/lyrie-prod/scripts/daemon.ts --channel telegram --interval 5m`,
      ].join('\n'),
    };
    const fs = memFs(files);
    const checkouts = await findLyrieCheckouts(fs);
    expect(checkouts.map(c => c.dir)).toEqual([`${HOME}/work/lyrie-prod`, `${HOME}/lyrie-ai`]);

    const [inst] = await lyrieAdapter.detect({ fs });
    expect(inst.installDir).toBe(`${HOME}/work/lyrie-prod`);
    expect(inst.version).toBe('3.4.0');
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/work/lyrie-prod/.env`, `${HOME}/lyrie-ai/.env`]);
    expect(inst.otherInstalls).toEqual([{ path: `${HOME}/lyrie-ai`, version: '3.3.0' }]);
  });

  it('reads the checkout from a launchd plist ProgramArguments', async () => {
    const files = {
      [`${HOME}/code/agents/lyrie/package.json`]: PKG('3.4.0'),
      [`${HOME}/Library/LaunchAgents/ai.lyrie.daemon.plist`]:
        `<plist><dict><key>ProgramArguments</key><array><string>/opt/homebrew/bin/bun</string><string>run</string><string>${HOME}/code/agents/lyrie/scripts/daemon.ts</string></array></dict></plist>`,
    };
    const [inst] = await lyrieAdapter.detect({ fs: memFs(files) });
    expect(inst.installDir).toBe(`${HOME}/code/agents/lyrie`);
  });

  it('detects the same install over a remote snapshot (probe-collected files only)', async () => {
    const files: ProbeSnapshot['files'] = {};
    for (const [path, content] of Object.entries(liveLayout())) {
      files[path] = { content, mode: path.endsWith('/.env') ? 0o664 : 0o600, exists: true };
    }
    // Candidates the probe looked for but did not find
    files[`${HOME}/lyrie/package.json`] = { content: '', mode: 0, exists: false };
    files[`${STATE}/package.json`] = { content: '', mode: 0, exists: false };
    const fs = new SnapshotFSProvider({
      version: 1, hostname: 'remote', platform: 'linux', homedir: HOME, timestamp: '2026-01-01T00:00:00Z',
      privilege: { uid: 1000, username: 'test', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['test'], skippedPaths: [] },
      files, directories: {}, commandOutputs: {}, env: {},
    });
    const [inst] = await lyrieAdapter.detect({ fs });
    expect(inst.installDir).toBe(`${HOME}/lyrie-ai`);
    expect(inst.version).toBe('3.4.0');
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/lyrie-ai/.env`, `${STATE}/config.json`]);
  });

  it('detects state-only installs (pairing.json / migrations)', async () => {
    const [inst] = await lyrieAdapter.detect({ fs: memFs({ [`${STATE}/pairing.json`]: '{"pending":[],"approved":[]}' }) });
    expect(inst.installDir).toBe(STATE);
    expect(inst.configFiles).toEqual([]);
  });

  it('credential paths are the checkout .env and ~/.lyrie/config.json on the scanned host', () => {
    const fs = memFs({});
    expect(lyrieAdapter.getCredentialPaths!(`${HOME}/lyrie-ai`, fs)).toEqual([
      `${HOME}/lyrie-ai/.env`,
      `${HOME}/lyrie-ai/.env.development`,
      `${HOME}/lyrie-ai/.env.production`,
      `${HOME}/lyrie-ai/.env.local`,
      `${HOME}/lyrie-ai/.env.development.local`,
      `${HOME}/lyrie-ai/.env.production.local`,
      `${STATE}/config.json`,
    ]);
  });

  it('loads the env layers Bun auto-loads over .env (.env.<NODE_ENV>, .env.local, .env.<NODE_ENV>.local)', async () => {
    const files = liveLayout({
      [`${HOME}/lyrie-ai/.env.local`]: 'LYRIE_DISCORD_DM_POLICY=open\n',
      [`${HOME}/lyrie-ai/.env.development`]: 'LYRIE_LOCAL_DRY_RUN=true\n',
      [`${HOME}/lyrie-ai/.env.production`]: 'NODE_ENV=production\n',
    });
    const [inst] = await lyrieAdapter.detect({ fs: memFs(files) });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([
      `${HOME}/lyrie-ai/.env`,
      `${HOME}/lyrie-ai/.env.development`,
      `${HOME}/lyrie-ai/.env.local`,
      `${STATE}/config.json`,
    ]);
    expect(lyrieAdapter.getProbeManifest!().filePaths).toContain('~/lyrie-ai/.env.local');
  });

  it('picks the layers from the launch mode, not a NODE_ENV inside .env (Bun 1.3.11)', async () => {
    const files = liveLayout({
      [`${HOME}/lyrie-ai/.env.development`]: 'LYRIE_LOCAL_DRY_RUN=true\n',
      [`${HOME}/lyrie-ai/.env.production`]: 'LYRIE_SHIELD_MODE=passive\n',
    });
    files[`${HOME}/lyrie-ai/.env`] = files[`${HOME}/lyrie-ai/.env`].replace('NODE_ENV=development', 'NODE_ENV=production');
    const [inst] = await lyrieAdapter.detect({ fs: memFs(files) });
    const paths = inst.configFiles.map(c => c.filePath);
    expect(paths).toContain(`${HOME}/lyrie-ai/.env.development`);
    expect(paths).not.toContain(`${HOME}/lyrie-ai/.env.production`);
  });

  it('reads env values the way Bun 1.3.11 does: `#` starts a comment, $VAR expands across layers', async () => {
    const files = liveLayout({
      [`${HOME}/lyrie-ai/.env.local`]: 'SHIELD=passive\n',
    });
    files[`${HOME}/lyrie-ai/.env`] += '\nLYRIE_DISCORD_DM_POLICY=open#was pairing\nLYRIE_SHIELD_MODE=${SHIELD}\nSHIELD=active';
    const [inst] = await lyrieAdapter.detect({ fs: memFs(files) });
    const env = inst.configFiles.find(c => c.filePath === `${HOME}/lyrie-ai/.env`)!;
    expect(env.data.LYRIE_DISCORD_DM_POLICY).toBe('open');
    // .env.local's SHIELD wins, and Bun expands against the final value
    expect(env.data.LYRIE_SHIELD_MODE).toBe('passive');
  });

  it('Shield binary paths match AgenticThreatBridge.findDefaultBinary', () => {
    expect(lyrieShieldBinaryPaths('/srv/lyrie')).toEqual([
      '/srv/lyrie/packages/shield/target/release/lyrie-shield',
      '/srv/lyrie/packages/shield/target/debug/lyrie-shield',
    ]);
  });

  it('has no CLI command (the `lyrie` binary is the separate lyrie-omega product)', () => {
    expect(lyrieAdapter.getCLICommand).toBeUndefined();
  });

  it('zone graph has 5 zones with shield-bypass and pairing-bypass inversions', () => {
    const graph = lyrieAdapter.getZoneGraph!();
    expect(graph.zones).toHaveLength(5);
    const inversions = graph.edges.filter(e => e.triggerCheckIds && e.triggerCheckIds.length > 0);
    expect(inversions.map(e => e.label)).toEqual(
      expect.arrayContaining(['shield bypass', 'DM pairing bypass']),
    );
  });

  it('probe manifest ships checkout configs and keeps memory/binaries metadata-only', () => {
    const m = lyrieAdapter.getProbeManifest!();
    expect(m.filePaths).toEqual(expect.arrayContaining([
      '~/lyrie-ai/.env', '~/lyrie-ai/package.json', '~/.lyrie/.env', '~/.lyrie/package.json',
      '~/.lyrie/config.json', '~/.lyrie/pairing.json', '~/.lyrie/edits.json', '~/.lyrie/mcp.json',
      '~/.config/systemd/user/ai-lyrie-daemon.service', '~/Library/LaunchAgents/ai.lyrie.daemon.plist',
    ]));
    expect(m.globPatterns).toContain('~/.lyrie/migrations/*.json');
    expect(m.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.lyrie/memory/lyrie-memory.db',
      '~/.lyrie/memory/archive/*',
      '~/lyrie-ai/packages/shield/target/release/lyrie-shield',
    ]));
    const content = [...m.filePaths, ...m.globPatterns];
    expect(content.some(p => p.includes('/memory/'))).toBe(false);
    expect(m.envPrefixes).toContain('LYRIE_');
    expect(m.commands).toEqual([]);
  });
});
