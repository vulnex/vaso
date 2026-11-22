import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig, ScanContext } from '../core/types.js';
import { picoclawAdapter, picoclawPaths, picoclawWorkspaces } from './picoclaw.js';
import { cfg001 } from '../checks/config/cfg-001-gateway-binding.js';
import { cfg002 } from '../checks/config/cfg-002-api-key-exposure.js';
import { cfg003 } from '../checks/config/cfg-003-file-permissions.js';
import { net001 } from '../checks/network/net-001-gateway-exposure.js';

interface FakeFs {
  files?: Record<string, string>;
  modes?: Record<string, number>;
  dirs?: string[];
  env?: Record<string, string>;
  which?: string;
  versionOutput?: string;
}

const HOME = '/home/test';
const PICO = `${HOME}/.picoclaw`;

function makeFs(o: FakeFs = {}): FSProvider {
  const files = o.files ?? {};
  const dirs = new Set(o.dirs ?? []);
  return {
    kind: 'local',
    homedir: () => HOME,
    platform: 'linux',
    access: vi.fn(async (p: string) => p in files || dirs.has(p)),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error(`ENOENT ${p}`);
    }),
    stat: vi.fn(async (p: string) => {
      if (!(p in files) && !dirs.has(p)) throw new Error(`ENOENT ${p}`);
      return {
        mode: dirs.has(p) ? 0o40700 : 0o100000 | (o.modes?.[p] ?? 0o600),
        isFile: () => p in files,
        isDirectory: () => dirs.has(p),
      };
    }),
    readdirEntries: vi.fn(async () => []),
    realpath: vi.fn(async (p: string) => p),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] === 'picoclaw' && o.which) return `${o.which}\n`;
      if (args.length === 1 && args[0] === 'version' && o.versionOutput) return o.versionOutput;
      // Real picoclaw: `--version` is an unknown flag (exit 1)
      throw new Error('unknown flag: --version');
    }),
    getEnv: vi.fn((k: string) => o.env?.[k]),
  } as unknown as FSProvider;
}

/** Trimmed `picoclaw onboard` output (schema v3). */
function onboardConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    session: { dimensions: ['chat'] },
    version: 3,
    isolation: {},
    agents: {
      defaults: {
        workspace: `${PICO}/workspace`,
        restrict_to_workspace: true,
        allow_read_outside_workspace: false,
        provider: '',
        model_name: 'glm-4.7',
        max_tokens: 32768,
        max_tool_iterations: 50,
      },
    },
    channel_list: {
      irc: { enabled: false, type: 'irc', settings: { channels: [], nick: 'picoclaw', server: '', tls: true } },
      line: {
        enabled: false,
        type: 'line',
        group_trigger: { mention_only: true },
        settings: { webhook_host: '0.0.0.0', webhook_path: '/webhook/line', webhook_port: 18791 },
      },
      maixcam: { enabled: false, type: 'maixcam', settings: { host: '0.0.0.0', port: 18790 } },
      pico: { enabled: false, type: 'pico', settings: { max_connections: 100, ping_interval: 30 } },
      telegram: { enabled: false, type: 'telegram', typing: { enabled: true }, settings: { use_markdown_v2: false } },
    },
    model_list: [
      { model_name: 'glm-4.7', provider: 'zhipu', model: 'glm-4.7', api_base: 'https://open.bigmodel.cn/api/paas/v4' },
      { model_name: 'gpt-5.4', provider: 'openai', model: 'gpt-5.4', api_base: 'https://api.openai.com/v1' },
      { model_name: 'openrouter-gpt-5.4', provider: 'openrouter', model: 'openai/gpt-5.4', api_base: 'https://openrouter.ai/api/v1' },
      { model_name: 'gemini-flash', provider: 'antigravity', model: 'gemini-3-flash', auth_method: 'oauth' },
      { model_name: 'copilot-gpt-5.4', provider: 'github-copilot', model: 'gpt-5.4', api_base: 'http://localhost:4321', auth_method: 'oauth' },
    ],
    gateway: { host: 'localhost', port: 18790, hot_reload: false, log_level: 'warn' },
    hooks: { enabled: true, defaults: { observer_timeout_ms: 500 } },
    tools: {
      allow_read_paths: null,
      allow_write_paths: null,
      exec: { enabled: true, enable_deny_patterns: true, allow_remote: true, custom_deny_patterns: null, custom_allow_patterns: null },
      cron: { enabled: true, allow_command: true },
      mcp: { enabled: false, discovery: { enabled: false } },
      skills: { enabled: true, registries: { clawhub: { base_url: 'https://clawhub.ai', enabled: true } } },
      install_skill: { enabled: true },
    },
    heartbeat: { enabled: true, interval: 30 },
    ...overrides,
  };
}

/** `.security.yml` as onboard writes it: every secure slot present, all empty. */
const EMPTY_SECURITY = [
  'channel_list:',
  '  telegram:',
  '    settings: {}',
  '  pico:',
  '    settings: {}',
  'model_list:',
  '  glm-4.7:0: {}',
  '  gpt-5.4:0: {}',
  'web:',
  '  brave: {}',
  'skills:',
  '  registries: {}',
  '',
].join('\n');

function onboardFiles(config = onboardConfig(), security = EMPTY_SECURITY): Record<string, string> {
  return {
    [`${PICO}/config.json`]: JSON.stringify(config, null, 2),
    [`${PICO}/.security.yml`]: security,
  };
}

function ctxFor(inst: Awaited<ReturnType<typeof picoclawAdapter.detect>>[number], fs: FSProvider): ScanContext {
  return {
    installation: inst,
    configs: inst.configFiles,
    platform: 'linux',
    fs,
    credentialPaths: picoclawAdapter.getCredentialPaths!(inst.installDir, fs),
  };
}

describe('PicoClaw adapter', () => {
  it('returns nothing when no PicoClaw files exist', async () => {
    expect(await picoclawAdapter.detect({ fs: makeFs() })).toEqual([]);
  });

  it('detects an onboarded install: config.json + .security.yml, workspace skills, default gateway', async () => {
    const fs = makeFs({ files: onboardFiles(), dirs: [PICO, `${PICO}/workspace`] });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.agent).toBe('picoclaw');
    expect(inst.installDir).toBe(PICO);
    expect(inst.configFiles.map(c => [c.filePath, c.format])).toEqual([
      [`${PICO}/config.json`, 'json'],
      [`${PICO}/.security.yml`, 'yaml'],
    ]);
    expect(inst.skillsDir).toBe(`${PICO}/workspace/skills`);
    expect(inst.skillsDirs).toEqual([`${PICO}/workspace/skills`, `${PICO}/skills`]);
    expect(inst.gateway).toEqual({ host: 'localhost', port: 18790 });
    // Only the configured default is reported — not the ~30 key-less catalogue entries
    expect(inst.models).toEqual([{ id: 'glm-4.7', provider: 'zhipu' }]);
  });

  it('overlays PicoClaw env overrides (env.Parse) onto config.json and ships their names to the probe', async () => {
    const fs = makeFs({
      files: onboardFiles(),
      env: {
        PICOCLAW_TOOLS_EXEC_ENABLE_DENY_PATTERNS: 'false',
        PICOCLAW_AGENTS_DEFAULTS_RESTRICT_TO_WORKSPACE: 'F',
        PICOCLAW_TOOLS_EXEC_ALLOW_REMOTE: 'maybe',
      },
    });
    const [inst] = await picoclawAdapter.detect({ fs });
    const data = inst.configFiles[0].data as Record<string, any>;
    expect(data.tools.exec.enable_deny_patterns).toBe(false);
    expect(data.agents.defaults.restrict_to_workspace).toBe(false);
    // Unparseable bools are ignored, like strconv.ParseBool errors
    expect(data.tools.exec.allow_remote).not.toBe('maybe');
    const prefixes = picoclawAdapter.getProbeManifest!().envPrefixes;
    expect(prefixes).toContain('PICOCLAW_TOOLS_EXEC_ENABLE_DENY_PATTERNS');
    expect(prefixes).not.toContain('PICOCLAW_');
    expect(prefixes.some(p => 'PICOCLAW_KEY_PASSPHRASE'.startsWith(p))).toBe(false);
  });

  it('overlays the comma-separated list overrides (allow paths, exec allow patterns, web host whitelist)', async () => {
    const fs = makeFs({
      files: onboardFiles(),
      env: {
        PICOCLAW_TOOLS_ALLOW_READ_PATHS: '^/etc/.*,^/home/alice/\\.ssh/.*',
        PICOCLAW_TOOLS_ALLOW_WRITE_PATHS: '.*',
        PICOCLAW_TOOLS_EXEC_CUSTOM_ALLOW_PATTERNS: '.*',
        PICOCLAW_TOOLS_WEB_PRIVATE_HOST_WHITELIST: '169.254.169.254',
      },
    });
    const [inst] = await picoclawAdapter.detect({ fs });
    const data = inst.configFiles[0].data as Record<string, any>;
    expect(data.tools.allow_read_paths).toEqual(['^/etc/.*', '^/home/alice/\\.ssh/.*']);
    expect(data.tools.allow_write_paths).toEqual(['.*']);
    expect(data.tools.exec.custom_allow_patterns).toEqual(['.*']);
    expect(data.tools.web.private_host_whitelist).toEqual(['169.254.169.254']);
    const prefixes = picoclawAdapter.getProbeManifest!().envPrefixes;
    for (const name of ['PICOCLAW_TOOLS_ALLOW_READ_PATHS', 'PICOCLAW_TOOLS_ALLOW_WRITE_PATHS', 'PICOCLAW_TOOLS_EXEC_CUSTOM_ALLOW_PATTERNS', 'PICOCLAW_TOOLS_WEB_PRIVATE_HOST_WHITELIST']) {
      expect(prefixes).toContain(name);
    }
  });

  it('never reports the config schema version ("version": 3) as the app version', async () => {
    const fs = makeFs({ files: onboardFiles() });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.version).toBeUndefined();
  });

  it('reads the version from `picoclaw version` (banner output), not `--version`', async () => {
    const fs = makeFs({
      files: { ...onboardFiles(), [`${HOME}/.local/bin/picoclaw`]: '' },
      which: `${HOME}/.local/bin/picoclaw`,
      versionOutput: '\u001b[1;38;2;62;93;185m██████╗\n \u001b[0m\n🦞 picoclaw 0.3.1 (git: 2cf030d2)\n  Build: 2026-07-03T07:10:50Z\n  Go: 1.25.11\n',
    });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.version).toBe('0.3.1');
    expect(inst.cliBinary).toBe(`${HOME}/.local/bin/picoclaw`);
    expect(vi.mocked(fs.execSync).mock.calls.some(([, args]) => args.includes('--version'))).toBe(false);
  });

  it('loads auth.json and launcher-config.json alongside config.json', async () => {
    const fs = makeFs({
      files: {
        ...onboardFiles(),
        [`${PICO}/auth.json`]: JSON.stringify({ credentials: { antigravity: { access_token: 'ya29.x', provider: 'google-antigravity', auth_method: 'oauth' } } }),
        [`${PICO}/launcher-config.json`]: JSON.stringify({ port: 18800, public: false, allow_localhost_bypass: true }),
      },
    });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([
      `${PICO}/config.json`,
      `${PICO}/.security.yml`,
      `${PICO}/auth.json`,
      `${PICO}/launcher-config.json`,
    ]);
    // OAuth-logged-in provider's catalogue entry counts as in use
    expect(inst.models).toEqual([
      { id: 'glm-4.7', provider: 'zhipu' },
      { id: 'gemini-3-flash', provider: 'antigravity', via: 'gemini-flash' },
    ]);
    expect(inst.gateway?.host).toBe('localhost');
  });

  it('a public launcher starts the gateway on all interfaces', async () => {
    const fs = makeFs({
      files: { ...onboardFiles(), [`${PICO}/launcher-config.json`]: JSON.stringify({ port: 18800, public: true }) },
    });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.gateway).toEqual({ host: '0.0.0.0', port: 18790 });
  });

  it('normalizes `*` and comma-list gateway hosts; honours PICOCLAW_GATEWAY_HOST', async () => {
    const star = onboardConfig({ gateway: { host: '*', port: 18790 } });
    const [a] = await picoclawAdapter.detect({ fs: makeFs({ files: onboardFiles(star) }) });
    expect(a.gateway?.host).toBe('0.0.0.0');

    const list = onboardConfig({ gateway: { host: 'localhost,::', port: 9000 } });
    const [b] = await picoclawAdapter.detect({ fs: makeFs({ files: onboardFiles(list) }) });
    expect(b.gateway).toEqual({ host: '::', port: 9000 });

    const [c] = await picoclawAdapter.detect({
      fs: makeFs({ files: onboardFiles(), env: { PICOCLAW_GATEWAY_HOST: '0.0.0.0' } }),
    });
    expect(c.gateway?.host).toBe('0.0.0.0');
  });

  it('takes PICOCLAW_HOME / PICOCLAW_CONFIG literally — 0.3.1 does not expand ~ (picoclaw status: "Config: ~/ph/config.json ✗")', async () => {
    const fs = makeFs({
      env: { PICOCLAW_HOME: '~/ph' },
      files: { [`${HOME}/ph/config.json`]: JSON.stringify(onboardConfig()) },
    });
    const paths = picoclawPaths(HOME, fs);
    expect(paths.home).not.toBe(`${HOME}/ph`);
    expect(paths.configPath.endsWith('/~/ph/config.json')).toBe(true);
    // …but the default workspace derived from it is ~-expanded like every workspace path
    expect(paths.workspaceRoot).toBe(`${HOME}/ph`);
    expect(await picoclawAdapter.detect({ fs })).toEqual([]);
    expect(picoclawPaths(HOME, makeFs({ env: { PICOCLAW_CONFIG: '~/ph/config.json' } })).configPath).not.toBe(`${HOME}/ph/config.json`);
  });

  it('honours PICOCLAW_HOME and PICOCLAW_CONFIG (secrets/launcher files live next to the config)', async () => {
    const fs = makeFs({
      env: { PICOCLAW_HOME: '/srv/pico', PICOCLAW_CONFIG: '/etc/pico/agent.json' },
      files: {
        '/etc/pico/agent.json': JSON.stringify(onboardConfig({ agents: { defaults: { model_name: 'glm-4.7' } } })),
        '/etc/pico/.security.yml': EMPTY_SECURITY,
        '/srv/pico/auth.json': JSON.stringify({ credentials: {} }),
      },
    });
    expect(picoclawPaths(HOME, fs)).toEqual({ home: '/srv/pico', configPath: '/etc/pico/agent.json', configDir: '/etc/pico', workspaceRoot: '/srv/pico' });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.installDir).toBe('/srv/pico');
    expect(inst.configFiles.map(c => c.filePath)).toEqual(['/etc/pico/agent.json', '/etc/pico/.security.yml', '/srv/pico/auth.json']);
    // workspace defaults to $PICOCLAW_HOME/workspace when the config doesn't set one
    expect(inst.skillsDirs).toEqual(['/srv/pico/workspace/skills', '/srv/pico/skills']);
    expect(inst.models).toEqual([{ id: 'glm-4.7', provider: 'zhipu' }]);
    expect(picoclawAdapter.getCredentialPaths!('/srv/pico', fs)).toEqual([
      '/etc/pico/.security.yml',
      '/srv/pico/auth.json',
      '/etc/pico/launcher-config.json',
      '/etc/pico/agent.json',
      `${HOME}/.ssh/picoclaw_ed25519.key`,
    ]);
  });

  it('adds named-agent workspaces and PICOCLAW_BUILTIN_SKILLS to the skills dirs', async () => {
    const config = onboardConfig({
      agents: {
        defaults: { workspace: '~/.picoclaw/workspace', model_name: 'glm-4.7' },
        list: [
          { id: 'main', default: true },
          { id: 'Research Bot' },
          { id: 'ops', workspace: '/data/ops-ws' },
          { id: 'sys', workspace: '/var/lib/sys-ws' },
          'not-an-object',
        ],
      },
    });
    const fs = makeFs({ files: onboardFiles(config), env: { PICOCLAW_BUILTIN_SKILLS: '/opt/picoclaw/skills' } });
    const [inst] = await picoclawAdapter.detect({ fs });
    // a workspace the config sets out of the home is walked where skills live (/data)…
    expect(inst.skillsDirs).toEqual([
      `${PICO}/workspace/skills`,
      `${PICO}/workspace-research-bot/skills`,
      '/data/ops-ws/skills',
      `${PICO}/skills`,
      '/opt/picoclaw/skills',
    ]);
    // …not in an OS directory
    expect(inst.unscannedSkillsDirs).toEqual([{ path: '/var/lib/sys-ws/skills', reason: 'outside', refusedAs: 'an OS directory (/var)' }]);
    expect(picoclawWorkspaces(undefined, PICO, HOME)).toEqual([`${PICO}/workspace`]);
  });

  it('screens PICOCLAW_BUILTIN_SKILLS like a config-set skills directory', async () => {
    const cases: Array<[string, string[], Array<Record<string, unknown>>]> = [
      ['/tmp/./pico-skills/', ['/tmp/pico-skills'], []],
      ['/etc/', [], [{ path: '/etc', reason: 'outside', refusedAs: 'an OS directory (/etc)' }]],
      ['~', [], [{ path: HOME, reason: 'home' }]],
      ['~/.ssh', [], [expect.objectContaining({ path: `${HOME}/.ssh`, reason: 'outside' })]],
      ['skills', [], [{ path: 'skills', reason: 'relative' }]],
    ];
    for (const [value, scan, unscanned] of cases) {
      const fs = makeFs({ files: onboardFiles(onboardConfig()), env: { PICOCLAW_BUILTIN_SKILLS: value } });
      const [inst] = await picoclawAdapter.detect({ fs });
      expect(inst.skillsDirs, value).toEqual([`${PICO}/workspace/skills`, `${PICO}/skills`, ...scan]);
      expect(inst.unscannedSkillsDirs ?? [], value).toEqual(unscanned);
    }
  });

  it('asks the probe for PICOCLAW_BUILTIN_SKILLS as an env-only tree', () => {
    const roots = picoclawAdapter.getProbeManifest!().configRoots ?? [];
    expect(roots).toContainEqual(expect.objectContaining({ configs: [], kind: 'tree', keys: [], envFallback: 'PICOCLAW_BUILTIN_SKILLS', globs: ['**'] }));
  });

  it('does not throw on null/odd sections', async () => {
    const config = { version: 3, agents: null, model_list: null, gateway: null, channel_list: { telegram: null, x: 5 } };
    const fs = makeFs({ files: { [`${PICO}/config.json`]: JSON.stringify(config), [`${PICO}/.security.yml`]: 'model_list:\n' } });
    const [inst] = await picoclawAdapter.detect({ fs });
    expect(inst.gateway).toEqual({ host: 'localhost', port: 18790 });
    expect(inst.models).toEqual([]);
    expect(inst.skillsDirs).toEqual([`${PICO}/workspace/skills`, `${PICO}/skills`]);
  });

  it('declares secret files (incl. the enc:// SSH key) as credential paths', () => {
    const fs = makeFs();
    expect(picoclawAdapter.getCredentialPaths!(PICO, fs)).toEqual([
      `${PICO}/.security.yml`,
      `${PICO}/auth.json`,
      `${PICO}/launcher-config.json`,
      `${PICO}/config.json`,
      `${HOME}/.ssh/picoclaw_ed25519.key`,
    ]);
    const withKey = makeFs({ env: { PICOCLAW_SSH_KEY_PATH: '/keys/pico' } });
    expect(picoclawAdapter.getCredentialPaths!(PICO, withKey)).toContain('/keys/pico');
    // another user's install (allUsers) — env relocations don't apply
    expect(picoclawAdapter.getCredentialPaths!('/home/other/.picoclaw', fs)).toEqual([
      '/home/other/.picoclaw/.security.yml',
      '/home/other/.picoclaw/auth.json',
      '/home/other/.picoclaw/launcher-config.json',
      '/home/other/.picoclaw/config.json',
      '/home/other/.ssh/picoclaw_ed25519.key',
    ]);
  });

  it('probe manifest: reads the real files, keeps private stores and the SSH key metadata-only, never ships PICOCLAW_KEY_PASSPHRASE', () => {
    const m = picoclawAdapter.getProbeManifest!();
    expect(m.filePaths).toEqual(expect.arrayContaining([
      '~/.picoclaw/config.json', '~/.picoclaw/.security.yml', '~/.picoclaw/auth.json', '~/.picoclaw/launcher-config.json',
    ]));
    expect(m.globPatterns).toEqual(expect.arrayContaining(['~/.picoclaw/workspace/skills/**', '~/.picoclaw/skills/**']));
    expect(m.metadataGlobPatterns).toEqual(expect.arrayContaining([
      '~/.picoclaw/workspace/sessions/**', '~/.picoclaw/workspace/memory/**', '~/.ssh/picoclaw_ed25519.key',
    ]));
    const content = [...m.filePaths, ...m.globPatterns];
    expect(content.some(p => p.includes('sessions') || p.includes('.ssh'))).toBe(false);
    expect(m.commands.find(c => c.id === 'picoclaw-version')?.args).toEqual(['version']);
    expect(m.envPrefixes).not.toContain('PICOCLAW_');
    expect(m.envPrefixes.some(p => 'PICOCLAW_KEY_PASSPHRASE'.startsWith(p))).toBe(false);
  });

  describe('generic checks on a real onboard install', () => {
    it('CFG-001 / NET-001 pass on the default loopback gateway (disabled 0.0.0.0 channel listeners ignored)', async () => {
      const fs = makeFs({ files: onboardFiles() });
      const [inst] = await picoclawAdapter.detect({ fs });
      expect((await cfg001.run(ctxFor(inst, fs))).passed).toBe(true);
      expect((await net001.run(ctxFor(inst, fs))).passed).toBe(true);
    });

    it('CFG-001 / NET-001 fire on gateway.host 0.0.0.0; CFG-001 fix targets the real gateway.host key', async () => {
      const fs = makeFs({ files: onboardFiles(onboardConfig({ gateway: { host: '0.0.0.0', port: 18790 } })) });
      const [inst] = await picoclawAdapter.detect({ fs });
      const r = await cfg001.run(ctxFor(inst, fs));
      expect(r.passed).toBe(false);
      expect(r.fixable).toBe(true);
      expect(inst.configFiles[0].filePath).toBe(`${PICO}/config.json`); // fixFirstConfig writes here
      expect((await net001.run(ctxFor(inst, fs))).passed).toBe(false);
    });

    it('CFG-002 treats .security.yml as the secret store and flags keys leaked into config.json', async () => {
      const plain = 'model_list:\n  gpt-5.4:0:\n    api_keys:\n      - "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"\n';
      const fsPlain = makeFs({ files: onboardFiles(onboardConfig(), plain) });
      const [a] = await picoclawAdapter.detect({ fs: fsPlain });
      // Keys belong in .security.yml (0600, CFG-003 checks its mode)
      expect((await cfg002.run(ctxFor(a, fsPlain))).passed).toBe(true);
      // model with a key is now reported as in use
      expect(a.models).toContainEqual({ id: 'gpt-5.4', provider: 'openai', via: 'gpt-5.4' });

      const leaked = onboardConfig();
      (leaked.model_list as Record<string, unknown>[])[0].api_key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789';
      const fsLeak = makeFs({ files: onboardFiles(leaked) });
      const [b] = await picoclawAdapter.detect({ fs: fsLeak });
      const rb = await cfg002.run(ctxFor(b, fsLeak));
      expect(rb.passed).toBe(false);
      expect(rb.evidence?.[0].file).toBe(`${PICO}/config.json`);
    });

    it('CFG-003 checks .security.yml / auth.json permissions', async () => {
      const files = { ...onboardFiles(), [`${PICO}/auth.json`]: '{"credentials":{}}' };
      const ok = makeFs({ files });
      const [a] = await picoclawAdapter.detect({ fs: ok });
      expect((await cfg003.run(ctxFor(a, ok))).passed).toBe(true);

      const loose = makeFs({ files, modes: { [`${PICO}/.security.yml`]: 0o644 } });
      const [b] = await picoclawAdapter.detect({ fs: loose });
      const r = await cfg003.run(ctxFor(b, loose));
      expect(r.passed).toBe(false);
      expect(r.evidence?.map(e => e.file)).toEqual([`${PICO}/.security.yml`]);
    });
  });

  it('getConfigPaths lists the four PicoClaw files', () => {
    const paths = picoclawAdapter.getConfigPaths();
    expect(paths.map(p => p.split('/').pop())).toEqual(['config.json', '.security.yml', 'auth.json', 'launcher-config.json']);
  });

  it('getModels: explicit provider keeps the model id verbatim; unprefixed + no provider → openai', () => {
    const cfg = (data: Record<string, unknown>): ParsedConfig => ({ filePath: '/c/config.json', format: 'json', raw: '', data });
    expect(picoclawAdapter.getModels!([cfg({
      agents: { defaults: { model_name: 'or' } },
      model_list: [{ model_name: 'or', provider: 'openrouter', model: 'openai/gpt-5.4' }],
    })])).toEqual([{ id: 'openai/gpt-5.4', provider: 'openrouter' }]);
    expect(picoclawAdapter.getModels!([cfg({
      agents: { defaults: { model_name: 'x' } },
      model_list: [{ model_name: 'x', model: 'gpt-4o' }],
    })])).toEqual([{ id: 'gpt-4o', provider: 'openai' }]);
  });
});
