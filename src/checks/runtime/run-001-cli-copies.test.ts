import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../../core/fs-provider.js';
import type { ScanContext } from '../../core/types.js';
import { run001, systemdLoads } from './run-001-launch-agents.js';
import { run002 } from './run-002-suspicious-cron.js';
import { cliCopyPaths } from '../../adapters/cli-installs.js';

// dt25 g1-F1: the real box. OpenClaw 2026.11.2's installer writes an sh
// wrapper at ~/.local/bin/openclaw (the primary) that runs the package of the
// v24.16.0 nvm copy — the same version, so that copy is not in otherInstalls.
// Its gateway unit runs that package and must be the agent's own (info).
const HOME = '/home/test';
const UNIT_DIR = `${HOME}/.config/systemd/user`;
const NVM = `${HOME}/.nvm/versions/node`;
const PKG = `${NVM}/v24.16.0/lib/node_modules/openclaw`;
const WRAPPER = `${HOME}/.local/bin/openclaw`;
const GATEWAY = `[Service]\nExecStart=${NVM}/v24.22.1/bin/node ${PKG}/openclaw.mjs gateway --port 18789\n`;

function boxFs(units: Record<string, string>, crontab = ''): FSProvider {
  const files = new Set([WRAPPER, `${NVM}/v24.16.0/bin/openclaw`]);
  const links: Record<string, string> = { [`${NVM}/v24.16.0/bin/openclaw`]: '../lib/node_modules/openclaw/openclaw.mjs' };
  const dirs: Record<string, string[]> = { [NVM]: ['v24.16.0', 'v24.22.1'], [UNIT_DIR]: Object.keys(units) };
  return {
    platform: 'linux',
    homedir: () => HOME,
    readdir: async (d: string) => dirs[d] ?? [],
    readdirEntries: async (d: string) => {
      if (!dirs[d]) throw new Error('ENOENT');
      return dirs[d].map(name => ({ name, isDirectory: true, isFile: false }));
    },
    readFile: async (p: string) => {
      const u = units[p.slice(UNIT_DIR.length + 1)];
      if (u === undefined) throw new Error('ENOENT');
      return u;
    },
    access: async (p: string) => files.has(p),
    readlink: async (p: string) => { if (links[p]) return links[p]; throw new Error('EINVAL'); },
    realpath: async (p: string) => {
      if (links[p]) return `${PKG}/openclaw.mjs`;
      if (files.has(p)) return p;
      throw new Error('ENOENT');
    },
    execSync: () => crontab,
    getEnv: () => undefined,
  } as unknown as FSProvider;
}

function ctx(fs: FSProvider): ScanContext {
  return {
    installation: {
      agent: 'openclaw', installDir: `${HOME}/.openclaw`, configFiles: [], version: '2026.11.2',
      cliBinary: WRAPPER,
      // only the copy at another version
      otherInstalls: [{ path: `${NVM}/v22.22.1/bin/openclaw`, version: '2026.3.13' }],
    },
    configs: [],
    platform: 'linux',
    fs,
  };
}

describe('RUN-001/002: every copy of the agent CLI counts as its own', () => {
  it('finds the same-version nvm copy behind a wrapper', async () => {
    expect(await cliCopyPaths(HOME, boxFs({}), ['openclaw'])).toEqual([WRAPPER, `${NVM}/v24.16.0/bin/openclaw`]);
  });

  it('reports the installer-written gateway unit as the agent\'s own, once', async () => {
    const result = await run001.run(ctx(boxFs({ 'openclaw-gateway.service': GATEWAY })));
    expect(result.severity).toBe('info');
    expect(result.evidence).toHaveLength(1);
    expect(result.evidence![0]).toMatchObject({ mitigated: true });
    expect(result.evidence![0].detail).toContain(`${PKG}/openclaw.mjs`);
  });

  it('judges a cron job running the same package as the agent\'s own', async () => {
    const result = await run002.run(ctx(boxFs({}, `0 * * * * ${NVM}/v24.22.1/bin/node ${PKG}/openclaw.mjs doctor\n`)));
    expect(result.evidence?.[0]).toMatchObject({ mitigated: true });
  });

  it('skips files systemd never loads (installer backups and receipts)', async () => {
    const result = await run001.run(ctx(boxFs({
      'openclaw-gateway.service': GATEWAY,
      'openclaw-gateway.service.bak': '[Service]\nExecStart=/tmp/x/openclaw gateway\n',
      'openclaw-gateway.service.reconcile-3e6e.bak': GATEWAY,
      'openclaw-gateway.service.reconcile-3e6e.receipt.bak': '{"unit":"openclaw-gateway.service"}',
    })));
    expect(result.evidence?.map(e => e.file)).toEqual([`${UNIT_DIR}/openclaw-gateway.service`]);
  });

  it('still flags a keyword unit running something else', async () => {
    const result = await run001.run(ctx(boxFs({
      'openclaw-gateway.service': GATEWAY,
      'clawbot.service': '[Service]\nExecStart=/tmp/.x/clawbot\n',
    })));
    expect(result.severity).toBe('warning');
    expect(result.evidence?.filter(e => !e.mitigated).map(e => e.file)).toEqual([`${UNIT_DIR}/clawbot.service`]);
  });

  it('systemdLoads: unit suffixes and drop-in dirs, not backups', () => {
    for (const n of ['a.service', 'a.timer', 'a.socket', 'a.path', 'a.service.d', 'default.target.wants', 'A.SERVICE']) expect(systemdLoads(n), n).toBe(true);
    for (const n of ['a.service.bak', 'a.service~', 'a.service.orig', 'a.receipt.bak', 'openclaw', 'a.service.dpkg-old']) expect(systemdLoads(n), n).toBe(false);
  });
});
