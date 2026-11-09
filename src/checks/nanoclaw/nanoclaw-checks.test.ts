import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, statSync, realpathSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import type { ProbeSnapshot } from '../../core/snapshot-types.js';
import { SnapshotFSProvider } from '../../core/snapshot-fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { nanoclawChecks } from './index.js';
import { installedChannels } from './nc-004-webhook-listener-public-bind.js';

const HOME = '/home/test';
const CHECKOUT = `${HOME}/nanoclaw`;
const CONFIG_DIR = `${HOME}/.config/nanoclaw`;
const ALLOWLIST_PATH = `${CONFIG_DIR}/mount-allowlist.json`;

const byId = (id: string) => nanoclawChecks.find(c => c.id === id)!;

function allowlist(data: Record<string, unknown>, filePath = ALLOWLIST_PATH): ParsedConfig {
  return { raw: JSON.stringify(data), format: 'json', filePath, data };
}

function env(data: Record<string, string>, filePath = `${CHECKOUT}/.env`): ParsedConfig {
  return { raw: Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n'), format: 'env', filePath, data };
}

type Entry = string | { content?: string; mode?: number };

/** Snapshot FS: files with modes, plus recorded directory modes (tri-state permissions). */
function snapFs(files: Record<string, Entry>, dirModes: Record<string, number> = {}, envVars: Record<string, string> = {}): FSProvider {
  const snap: ProbeSnapshot = {
    version: 1,
    hostname: 'test-host',
    platform: 'linux',
    homedir: HOME,
    timestamp: '2026-09-29T00:00:00Z',
    privilege: { uid: 1000, username: 'test', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['test'], skippedPaths: [] },
    files: Object.fromEntries(Object.entries(files).map(([p, e]) => {
      const entry = typeof e === 'string' ? { content: e } : e;
      return [p, { content: entry.content ?? '', mode: entry.mode ?? 0o100600, exists: true }];
    })),
    directories: {},
    directoryModes: { '/': 0o755, '/home': 0o755, [HOME]: 0o755, ...dirModes },
    commandOutputs: {},
    env: envVars,
  };
  return new SnapshotFSProvider(snap);
}

function ctx(opts: { configs?: ParsedConfig[]; installDir?: string; skillsDir?: string; fs?: FSProvider } = {}): ScanContext {
  const installDir = opts.installDir ?? CHECKOUT;
  const installation: AgentInstallation = {
    agent: 'nanoclaw',
    installDir,
    configFiles: opts.configs ?? [],
    skillsDir: opts.skillsDir,
  };
  return { installation, configs: opts.configs ?? [], platform: 'linux', fs: opts.fs ?? snapFs({}) };
}

describe('NanoClaw checks', () => {
  it('exports 5 checks with the nanoclaw category and NC-0NN ids', () => {
    expect(nanoclawChecks.map(c => c.id)).toEqual(['NC-001', 'NC-002', 'NC-003', 'NC-004', 'NC-005']);
    for (const check of nanoclawChecks) {
      expect(check.category).toBe('nanoclaw');
      expect(check.supportedAgents).toEqual(['nanoclaw']);
    }
  });

  it('only NC-002 is fixable (chmod) — no check writes config keys', () => {
    expect(nanoclawChecks.filter(c => c.fix).map(c => c.id)).toEqual(['NC-002']);
  });

  it('never throws on odd allowlist / env shapes', async () => {
    const odd: ParsedConfig[] = [
      allowlist({ allowedRoots: null, blockedPatterns: 'x' }),
      allowlist({ allowedRoots: [null, 7, 'relative', { path: 42 }, { path: '' }, {}] }),
      allowlist({}),
      env({}),
    ];
    for (const config of odd) {
      for (const check of nanoclawChecks) {
        await expect(check.run(ctx({ configs: [config] }))).resolves.toBeDefined();
        await expect(check.run(ctx({ configs: [config], installDir: CONFIG_DIR }))).resolves.toBeDefined();
      }
    }
  });
});

describe('NC-001: Overbroad Mount Allowlist (allowedRoots)', () => {
  const check = byId('NC-001');
  const run = (roots: unknown[], installDir = CHECKOUT) =>
    check.run(ctx({ configs: [allowlist({ allowedRoots: roots, blockedPatterns: [] })], installDir }));

  it('flags the setup default "~" read-write as critical (live-install shape)', async () => {
    const r = await check.run(ctx({
      configs: [allowlist({ allowedRoots: [{ path: '~', allowReadWrite: true }], blockedPatterns: [], nonMainReadOnly: false })],
      installDir: CONFIG_DIR,
    }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toMatch(/whole home directory.*writable/);
  });

  it('flags "~" read-only too — blocked patterns only guard the mount root', async () => {
    const r = await run([{ path: '~', allowReadWrite: false }]);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toMatch(/read-only/);
  });

  it('flags "/", ancestors of home and the Docker socket tree', async () => {
    for (const p of ['/', '/home', '/var', '/run', '/proc']) {
      const r = await run([{ path: p, allowReadWrite: false }]);
      expect(r.passed, p).toBe(false);
      expect(r.severity, p).toBe('critical');
    }
  });

  it('judges roots inside a home that lives under a system dir (root: /root) as home paths', async () => {
    const rootHome = new SnapshotFSProvider({
      version: 1, hostname: 'test-host', platform: 'linux', homedir: '/root', timestamp: '2026-09-29T00:00:00Z',
      privilege: { uid: 0, username: 'root', isRoot: true, sudoAvailable: false, escalated: false, scannedUsers: ['root'], skippedPaths: [] },
      files: {}, directories: {}, directoryModes: { '/': 0o755, '/root': 0o700 }, commandOutputs: {}, env: {},
    });
    const config = allowlist({ allowedRoots: [{ path: '~/projects', allowReadWrite: true }, { path: '~/Documents/work', allowReadWrite: false }], blockedPatterns: [] },
      '/root/.config/nanoclaw/mount-allowlist.json');
    const r = await check.run({
      installation: { agent: 'nanoclaw', installDir: '/root/nanoclaw', configFiles: [config] },
      configs: [config], platform: 'linux', fs: rootHome,
    });
    expect(r.passed).toBe(true);
  });

  it('system directories: critical when writable, warning when read-only', async () => {
    expect((await run([{ path: '/etc', allowReadWrite: true }])).severity).toBe('critical');
    expect((await run([{ path: '/etc', allowReadWrite: false }])).severity).toBe('warning');
  });

  it('flags a root containing the NanoClaw checkout (.env secrets, host code)', async () => {
    const r = await run([{ path: '~/nanoclaw', allowReadWrite: true }]);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toMatch(/NanoClaw checkout/);
    // relative roots resolve against the checkout (the service cwd)
    expect((await run([{ path: '.', allowReadWrite: false }])).passed).toBe(false);
  });

  it('~/.config: critical when writable, warning read-only', async () => {
    expect((await run([{ path: '~/.config', allowReadWrite: true }])).severity).toBe('critical');
    expect((await run([{ path: '~/.config', allowReadWrite: false }])).severity).toBe('warning');
  });

  it('honors the legacy readOnly key and defaults to read-only', async () => {
    expect((await run([{ path: '/etc', readOnly: false }])).severity).toBe('critical');
    expect((await run([{ path: '/etc' }])).severity).toBe('warning');
  });

  it('passes for project roots and built-in-blocked credential stores', async () => {
    const r = await run([
      { path: '~/projects', allowReadWrite: true, description: 'Development projects' },
      { path: '~/repos', allowReadWrite: true },
      { path: '~/Documents/work', allowReadWrite: false },
      { path: '~/.ssh', allowReadWrite: false },
      { path: '/var/lib/data-share', allowReadWrite: false },
    ]);
    expect(r.passed).toBe(true);
  });

  it('passes an allowlist NanoClaw refuses (it then blocks every additional mount)', async () => {
    const home = [{ path: '~', allowReadWrite: true }];
    // no blockedPatterns array (upstream: "blockedPatterns must be an array")
    const noPatterns = await check.run(ctx({ configs: [allowlist({ allowedRoots: home })] }));
    expect(noPatterns.passed).toBe(true);
    expect(noPatterns.message).toMatch(/no blockedPatterns array.*blocks additional mounts/);
    // JSON.parse, not JSONC
    const jsonc = { ...allowlist({ allowedRoots: home, blockedPatterns: [] }), raw: '// mounts\n{"allowedRoots":[{"path":"~","allowReadWrite":true}],"blockedPatterns":[]}' };
    expect((await check.run(ctx({ configs: [jsonc] }))).message).toMatch(/not strict JSON/);
    // a null entry makes normalizeRoot throw
    expect((await check.run(ctx({ configs: [allowlist({ allowedRoots: [...home, null], blockedPatterns: [] })] }))).passed).toBe(true);
    // the same roots in an accepted file are the critical finding
    expect((await check.run(ctx({ configs: [allowlist({ allowedRoots: home, blockedPatterns: [] })] }))).severity).toBe('critical');
  });

  it('an entry without a string path is the host cwd (the checkout)', async () => {
    const r = await run(['~']);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toMatch(/NanoClaw checkout/);
  });

  describe('roots compared after realpath', () => {
    let home: string;
    beforeEach(() => { home = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-nc001-'))); });
    afterEach(() => rmSync(home, { recursive: true, force: true }));

    const scan = (roots: unknown[]) => {
      const local = new LocalFSProvider();
      const fs = Object.assign(Object.create(local) as FSProvider, { homedir: () => home });
      const config = allowlist({ allowedRoots: roots, blockedPatterns: [] }, join(home, '.config/nanoclaw/mount-allowlist.json'));
      return check.run({ installation: { agent: 'nanoclaw', installDir: join(home, '.config/nanoclaw'), configFiles: [config] }, configs: [config], platform: 'linux', fs });
    };

    it('flags a project root that is a symlink to the home directory', async () => {
      symlinkSync('.', join(home, 'projects'));
      const r = await scan([{ path: '~/projects', allowReadWrite: true }]);
      expect(r.severity).toBe('critical');
      expect(r.evidence?.[0].detail).toMatch(/→ .*whole home directory/);
    });

    it('passes a real project directory', async () => {
      mkdirSync(join(home, 'projects'));
      expect((await scan([{ path: '~/projects', allowReadWrite: true }])).passed).toBe(true);
    });
  });

  it('passes without an allowlist or with the --empty template', async () => {
    expect((await check.run(ctx())).passed).toBe(true);
    const empty = allowlist({ allowedRoots: [], blockedPatterns: [], nonMainReadOnly: true });
    expect((await check.run(ctx({ configs: [empty] }))).passed).toBe(true);
  });

  it('ignores the v1 allowedPaths/mounts keys (not read by NanoClaw v2)', async () => {
    const v1 = allowlist({ allowedPaths: ['/'], mounts: ['/etc'] });
    const r = await check.run(ctx({ configs: [v1] }));
    expect(r.passed).toBe(true);
  });
});

describe('NC-002: Mount Allowlist / Host Config Exposed', () => {
  const check = byId('NC-002');
  const cfg = [allowlist({ allowedRoots: [], blockedPatterns: [] })];

  it('umask-002 layout (dir 775, allowlist 664) is info-only, not "writable by other users"', async () => {
    const fs = snapFs({ [ALLOWLIST_PATH]: { content: '{}', mode: 0o100664 } }, { [`${HOME}/.config`]: 0o755, [CONFIG_DIR]: 0o775 });
    const r = await check.run(ctx({ configs: cfg, installDir: CONFIG_DIR, fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence).toHaveLength(2);
    expect(r.evidence?.[0].detail).toMatch(/group only/);
  });

  it('world-writable allowlist is critical', async () => {
    const fs = snapFs({ [ALLOWLIST_PATH]: { content: '{}', mode: 0o100666 } }, { [`${HOME}/.config`]: 0o755, [CONFIG_DIR]: 0o755 });
    const r = await check.run(ctx({ configs: cfg, fs }));
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toMatch(/any local user/);
  });

  it('world-readable identity files are critical; 0600 passes', async () => {
    const bad = snapFs({
      [ALLOWLIST_PATH]: { content: '{}', mode: 0o100600 },
      [`${CONFIG_DIR}/device-key.json`]: { mode: 0o100644 },
      [`${CONFIG_DIR}/account.json`]: { mode: 0o100600 },
    }, { [`${HOME}/.config`]: 0o755, [CONFIG_DIR]: 0o755 });
    const r = await check.run(ctx({ configs: cfg, fs: bad }));
    expect(r.severity).toBe('critical');
    expect(r.evidence?.map(e => e.file)).toEqual([`${CONFIG_DIR}/device-key.json`]);

    const good = snapFs({
      [ALLOWLIST_PATH]: { content: '{}', mode: 0o100600 },
      [`${CONFIG_DIR}/device-key.json`]: { mode: 0o100600 },
    }, { [`${HOME}/.config`]: 0o755, [CONFIG_DIR]: 0o700 });
    expect((await check.run(ctx({ configs: cfg, fs: good }))).passed).toBe(true);
  });

  it('world findings behind a 0750 home are mitigated to info', async () => {
    const fs = snapFs({ [ALLOWLIST_PATH]: { content: '{}', mode: 0o100666 } }, { [HOME]: 0o750, [`${HOME}/.config`]: 0o755, [CONFIG_DIR]: 0o700 });
    const r = await check.run(ctx({ configs: cfg, fs }));
    expect(r.severity).toBe('info');
    expect(r.evidence?.[0].mitigated).toBe(true);
  });

  describe('fix', () => {
    let root: string;
    beforeEach(() => { root = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-nc002-'))); });
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it('chmods the dir 700 and existing files 600', async () => {
      const dir = join(root, '.config', 'nanoclaw');
      mkdirSync(dir, { recursive: true });
      chmodSync(dir, 0o775);
      const allow = join(dir, 'mount-allowlist.json');
      writeFileSync(allow, '{"allowedRoots":[],"blockedPatterns":[]}');
      chmodSync(allow, 0o664);
      const res = await check.fix!(ctx({ configs: [allowlist({}, allow)], fs: new LocalFSProvider() }));
      expect(res.applied).toBe(true);
      expect(statSync(dir).mode & 0o777).toBe(0o700);
      expect(statSync(allow).mode & 0o777).toBe(0o600);
    });
  });
});

describe('NC-003: Checkout or State Directory Exposed', () => {
  const check = byId('NC-003');

  it('passes when no checkout was located', async () => {
    expect((await check.run(ctx({ installDir: CONFIG_DIR }))).passed).toBe(true);
  });

  it('group-writable checkout (775) with a 700 data dir is info-only', async () => {
    const fs = snapFs({ [`${CHECKOUT}/data/install-id`]: { mode: 0o100664 } }, { [CHECKOUT]: 0o775, [`${CHECKOUT}/data`]: 0o700 });
    const r = await check.run(ctx({ fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence?.map(e => e.file)).toEqual([CHECKOUT]);
  });

  it('world-writable data dir / socket is critical', async () => {
    const fs = snapFs({
      [`${CHECKOUT}/data/ncl.sock`]: { mode: 0o140666 },
      [`${CHECKOUT}/data/v2.db`]: { mode: 0o100644 },
    }, { [CHECKOUT]: 0o755, [`${CHECKOUT}/data`]: 0o777 });
    const r = await check.run(ctx({ fs }));
    expect(r.severity).toBe('critical');
    expect(r.evidence?.map(e => e.file)).toEqual([`${CHECKOUT}/data`, `${CHECKOUT}/data/ncl.sock`, `${CHECKOUT}/data/v2.db`]);
  });

  it('flags a checkout inside /tmp and NANOCLAW_TEMPLATES_DIR in a temp dir', async () => {
    const r = await check.run(ctx({ installDir: '/tmp/nanoclaw', fs: snapFs({}, {}, { NANOCLAW_TEMPLATES_DIR: '/dev/shm/tpl' }) }));
    expect(r.severity).toBe('critical');
    expect(r.evidence?.map(e => e.detail).join('\n')).toMatch(/temp location[\s\S]*NANOCLAW_TEMPLATES_DIR/);
  });

  it('owner-only checkout passes; unknown directory modes are skipped', async () => {
    const fs = snapFs({ [`${CHECKOUT}/data/v2.db`]: { mode: 0o100600 } }, { [CHECKOUT]: 0o755, [`${CHECKOUT}/data`]: 0o700 });
    expect((await check.run(ctx({ fs }))).passed).toBe(true);
    const unknown = snapFs({ [`${CHECKOUT}/package.json`]: '{}' });
    expect((await check.run(ctx({ fs: unknown }))).passed).toBe(true);
  });
});

describe('NC-004: Webhook Listener Bound to All Interfaces', () => {
  const check = byId('NC-004');
  const barrel = `${CHECKOUT}/src/channels/index.ts`;
  const BARREL_HEAD = [
    '// Channel self-registration barrel.',
    '// Each import triggers the channel module\'s registerChannelAdapter() call.',
    "import './cli.js';",
  ].join('\n');

  it('parses channel imports and ignores comments', () => {
    expect(installedChannels(`${BARREL_HEAD}\n// import './slack.js';\nimport './telegram.js';\nimport "./whatsapp-cloud.js"`))
      .toEqual(['cli', 'telegram', 'whatsapp-cloud']);
  });

  it('default checkout (cli only) opens no listener', async () => {
    const fs = snapFs({ [barrel]: BARREL_HEAD });
    const r = await check.run(ctx({ configs: [env({ WEBHOOK_PORT: '3000' })], fs }));
    expect(r.passed).toBe(true);
  });

  it('polling/gateway channels (telegram, discord) open no listener', async () => {
    const fs = snapFs({ [barrel]: `${BARREL_HEAD}\nimport './telegram.js';\nimport './discord.js';` });
    expect((await check.run(ctx({ fs }))).passed).toBe(true);
  });

  it('flags webhook channels with the configured port', async () => {
    const fs = snapFs({ [barrel]: `${BARREL_HEAD}\nimport './slack.js';\nimport './github.js';` });
    const r = await check.run(ctx({ configs: [env({ WEBHOOK_PORT: '8443' })], fs }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence?.[0].detail).toMatch(/slack, github → listener on 0\.0\.0\.0:8443/);
    expect(r.fixable).toBe(false);
  });

  it('Slack in Socket Mode (SLACK_APP_TOKEN) is not a webhook channel', async () => {
    const fs = snapFs({ [barrel]: `${BARREL_HEAD}\nimport './slack.js';` });
    const r = await check.run(ctx({ configs: [env({ SLACK_APP_TOKEN: 'xapp-fake' })], fs }));
    expect(r.passed).toBe(true);
  });

  it('defaults the port to 3000', async () => {
    const fs = snapFs({ [barrel]: `${BARREL_HEAD}\nimport './teams.js';` });
    const r = await check.run(ctx({ fs }));
    expect(r.evidence?.[0].detail).toMatch(/0\.0\.0\.0:3000/);
  });

  // g4-F36: upstream 8a91aadb (2026.10.1-rc.2) binds WEBHOOK_HOST, default 127.0.0.1
  describe('WEBHOOK_HOST (2026.10.1-rc.2+)', () => {
    const github = `${BARREL_HEAD}\nimport './github.js';`;
    const versioned = (version: string | undefined, configs: ParsedConfig[], fs: FSProvider) => {
      const c = ctx({ configs, fs });
      c.installation.version = version;
      return c;
    };

    it('passes on a loopback WEBHOOK_HOST', async () => {
      const r = await check.run(ctx({ configs: [env({ WEBHOOK_HOST: '127.0.0.1' })], fs: snapFs({ [barrel]: github }) }));
      expect(r.passed).toBe(true);
    });

    it('passes when the source reads WEBHOOK_HOST (loopback default)', async () => {
      const fs = snapFs({ [barrel]: github, [`${CHECKOUT}/src/config.ts`]: "const host = process.env.WEBHOOK_HOST || envConfig.WEBHOOK_HOST || '127.0.0.1';" });
      expect((await check.run(ctx({ fs }))).passed).toBe(true);
    });

    it('decides by version when the source is not collected', async () => {
      const fs = snapFs({ [barrel]: github });
      expect((await check.run(versioned('2026.10.1-rc.2', [], fs))).passed).toBe(true);
      expect((await check.run(versioned('2026.10.2', [], fs))).passed).toBe(true);
      const old = await check.run(versioned('2026.10.0', [], fs));
      expect(old.passed).toBe(false);
      expect(old.evidence?.[0].detail).toContain('hardcoded');
    });

    it('flags a non-loopback WEBHOOK_HOST on a new release', async () => {
      const fs = snapFs({ [barrel]: github });
      const lan = await check.run(versioned('2026.10.2', [env({ WEBHOOK_HOST: '192.168.1.5' })], fs));
      expect(lan.passed).toBe(false);
      expect(lan.message).toContain('192.168.1.5');
      expect(lan.evidence?.[0].file).toBe(`${CHECKOUT}/.env`);
      const all = await check.run(versioned('2026.10.2', [env({ WEBHOOK_HOST: '0.0.0.0' })], fs));
      expect(all.message).toContain('all interfaces');
    });
  });
});

describe('NC-005: Skills Directory Writable by Others', () => {
  const check = byId('NC-005');
  const skills = `${CHECKOUT}/container/skills`;

  it('passes without a checkout', async () => {
    expect((await check.run(ctx({ installDir: CONFIG_DIR }))).passed).toBe(true);
  });

  it('world-writable container/skills is a warning; group-only operator skills are info', async () => {
    const fs = snapFs({
      [`${skills}/welcome/SKILL.md`]: '# welcome',
      [`${CHECKOUT}/.claude/skills/setup/SKILL.md`]: { mode: 0o100664 },
    }, { [CHECKOUT]: 0o755, [`${CHECKOUT}/container`]: 0o755, [skills]: 0o777, [`${CHECKOUT}/.claude`]: 0o755, [`${CHECKOUT}/.claude/skills`]: 0o775 });
    const r = await check.run(ctx({ skillsDir: skills, fs }));
    expect(r.severity).toBe('warning');
    expect(r.evidence?.map(e => e.file)).toEqual([skills, `${CHECKOUT}/.claude/skills`]);
  });

  describe('local', () => {
    let root: string;
    beforeEach(() => { root = realpathSync(mkdtempSync(join(tmpdir(), 'vaso-nc005-'))); });
    afterEach(() => rmSync(root, { recursive: true, force: true }));

    it('0755 skills dirs pass', async () => {
      const dir = join(root, 'container', 'skills');
      mkdirSync(dir, { recursive: true });
      chmodSync(dir, 0o755);
      const r = await check.run(ctx({ installDir: root, skillsDir: dir, fs: new LocalFSProvider() }));
      expect(r.passed).toBe(true);
    });
  });
});
