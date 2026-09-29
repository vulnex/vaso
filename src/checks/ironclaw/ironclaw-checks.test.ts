import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { AgentInstallation, ParsedConfig, ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { ironclawChecks } from './index.js';

// ── fixtures ────────────────────────────────────────────────────────────

const HOME = '/home/test';
const REBORN = `${HOME}/.ironclaw/reborn`;
const LEGACY = `${HOME}/.ironclaw`;

/** `ironclaw onboard` output (1.4.0), comments trimmed. */
const ONBOARD_CONFIG = `api_version = "ironclaw.runtime/v1"

[boot]
profile = "local-dev"

[identity]
default_owner  = "reborn-cli"

[runner]
heartbeat_interval_secs = 15
poll_interval_ms        = 200

[skills]
regex_activation_enabled = true

[llm]

[llm.default]
provider_id = "ollama"
model = "llama3.2"
`;

/** `ironclaw config init` providers.json overlay example. */
const PROVIDERS_JSON = JSON.stringify([
  {
    id: 'example-openrouter',
    aliases: [],
    protocol: 'open_ai_completions',
    api_key_env: 'ACME_OPENROUTER_KEY',
    api_key_required: true,
    default_base_url: 'https://openrouter.ai/api/v1',
    default_model: 'anthropic/claude-3.5-sonnet',
    model_env: 'ACME_OPENROUTER_MODEL',
    description: 'Tenant-pinned OpenRouter route (example; rename or delete)',
  },
], null, 2);

function toml(filePath: string, raw: string): ParsedConfig {
  return { raw, format: 'toml', filePath, data: parseToml(raw) as Record<string, unknown> };
}
function json(filePath: string, raw: string): ParsedConfig {
  return { raw, format: 'json', filePath, data: JSON.parse(raw) };
}
function env(filePath: string, vars: Record<string, string>): ParsedConfig {
  const raw = Object.entries(vars).map(([k, v]) => `${k}=${v}`).join('\n');
  return { raw, format: 'env', filePath, data: { ...vars } };
}

interface FakeFsOpts {
  files?: Record<string, number>;      // path → mode
  dirs?: Record<string, number>;       // path → mode
  contents?: Record<string, string>;
  env?: Record<string, string>;
  platform?: NodeJS.Platform;
}

function makeFs(o: FakeFsOpts = {}): FSProvider {
  const files = o.files ?? {};
  const dirs = { '/': 0o755, '/home': 0o755, [HOME]: 0o755, ...(o.dirs ?? {}) };
  const contents = o.contents ?? {};
  const exists = (p: string) => p in files || p in dirs || p in contents;
  return {
    platform: o.platform ?? 'linux',
    homedir: () => HOME,
    getEnv: (k: string) => o.env?.[k],
    access: async (p: string) => exists(p),
    stat: async (p: string) => {
      if (p in dirs) return { mode: 0o040000 | dirs[p], isFile: () => false, isDirectory: () => true };
      if (p in files || p in contents) return { mode: 0o100000 | (files[p] ?? 0o600), isFile: () => true, isDirectory: () => false };
      throw new Error(`ENOENT ${p}`);
    },
    readFile: async (p: string) => {
      if (p in contents) return contents[p];
      throw new Error(`ENOENT ${p}`);
    },
    readdir: async (p: string) => {
      const prefix = p.endsWith('/') ? p : `${p}/`;
      const names = [...Object.keys(files), ...Object.keys(dirs), ...Object.keys(contents)]
        .filter(f => f.startsWith(prefix))
        .map(f => f.slice(prefix.length).split('/')[0]);
      if (names.length === 0 && !(p in dirs)) throw new Error(`ENOENT ${p}`);
      return [...new Set(names)];
    },
    readdirEntries: async () => [],
  } as unknown as FSProvider;
}

function rebornCtx(configs: ParsedConfig[], fs: FSProvider = makeFs()): ScanContext {
  const installation: AgentInstallation = { agent: 'ironclaw', installDir: REBORN, configFiles: configs };
  return { installation, configs, platform: fs.platform, fs };
}

function legacyCtx(configs: ParsedConfig[], fs: FSProvider = makeFs(), profile = 'legacy'): ScanContext {
  const installation: AgentInstallation = { agent: 'ironclaw', installDir: LEGACY, configFiles: configs, profile };
  return { installation, configs, platform: fs.platform, fs };
}

const check = (id: string) => ironclawChecks.find(c => c.id === id)!;
const onboard = () => toml(`${REBORN}/config.toml`, ONBOARD_CONFIG);
const withConfig = (extra: string) => toml(`${REBORN}/config.toml`, `${ONBOARD_CONFIG}\n${extra}\n`);

// ── registry ────────────────────────────────────────────────────────────

describe('IronClaw checks', () => {
  it('exports 14 checks with unique IC- ids', () => {
    expect(ironclawChecks).toHaveLength(14);
    expect(new Set(ironclawChecks.map(c => c.id)).size).toBe(14);
    for (const c of ironclawChecks) {
      expect(c.id).toMatch(/^IC-0\d{2}$/);
      expect(c.category).toBe('ironclaw');
      expect(c.supportedAgents).toEqual(['ironclaw']);
    }
  });

  it('a stock `ironclaw onboard` install passes every check (DB readability downgraded by a private home)', async () => {
    const fs = makeFs({
      dirs: { [HOME]: 0o750, [`${HOME}/.ironclaw`]: 0o775, [REBORN]: 0o775, [`${REBORN}/local-dev`]: 0o775 },
      files: {
        [`${REBORN}/webui-token`]: 0o600,
        [`${REBORN}/local-dev/.reborn-local-dev-secrets-master-key`]: 0o600,
        [`${REBORN}/local-dev/reborn-local-dev.db`]: 0o644,
      },
    });
    const ctx = rebornCtx([onboard(), json(`${REBORN}/providers.json`, PROVIDERS_JSON)], fs);
    for (const c of ironclawChecks) {
      const r = await c.run(ctx);
      if (c.id === 'IC-014') {
        expect(r.passed).toBe(false);
        expect(r.severity).toBe('info');
        expect(r.evidence![0].mitigated).toBe(true);
      } else {
        expect(r.passed, `${c.id}: ${r.message}`).toBe(true);
      }
    }
  });

  it('never throws on malformed shapes (scalars where tables are expected, non-array providers)', async () => {
    const junkReborn = [
      toml(`${REBORN}/config.toml`, 'llm = "x"\nwebui = 5\nboot = []\npolicy = "minimal"\n'),
      json(`${REBORN}/providers.json`, '{"id": "not-an-array"}'),
    ];
    const junkLegacy = [
      env(`${LEGACY}/.env`, { SANDBOX_EXTRA_DOMAINS: '', SANDBOX_POLICY: '' }),
      toml(`${LEGACY}/config.toml`, 'channels = 3\nsandbox = "off"\nagent = []\n'),
    ];
    for (const c of ironclawChecks) {
      await expect(c.run(rebornCtx(junkReborn))).resolves.toBeDefined();
      await expect(c.run(legacyCtx(junkLegacy))).resolves.toBeDefined();
      await expect(c.run(rebornCtx([]))).resolves.toBeDefined();
    }
  });

  it('0.x state unused by a 1.x binary: behavioural checks pass, secrets at rest still fire', async () => {
    const configs = [env(`${LEGACY}/.env`, {
      HTTP_HOST: '0.0.0.0', SANDBOX_ENABLED: 'false', AGENT_AUTO_APPROVE_TOOLS: 'true',
      ALLOW_LOCAL_TOOLS: 'true', SECRETS_MASTER_KEY: 'a1b2c3d4e5f6a7b8c9d0',
    })];
    const ctx = legacyCtx(configs, makeFs(), 'legacy-unused');
    for (const id of ['IC-001', 'IC-003', 'IC-005', 'IC-006', 'IC-007', 'IC-008']) {
      expect((await check(id).run(ctx)).passed, id).toBe(true);
    }
    expect((await check('IC-009').run(ctx)).passed).toBe(false);
  });
});

// ── IC-001 ──────────────────────────────────────────────────────────────

describe('IC-001: Listener Bound Beyond Loopback', () => {
  it('flags [webui].listen_host = "0.0.0.0" and notes the missing canonical_host', async () => {
    const r = await check('IC-001').run(rebornCtx([withConfig('[webui]\nlisten_host = "0.0.0.0"\nlisten_port = 3000')]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.fixable).toBe(true);
    expect(r.evidence![0].detail).toContain('canonical_host');
  });

  it('passes on loopback binds (127.0.0.1, ::1) and the default', async () => {
    for (const host of ['127.0.0.1', '::1']) {
      const r = await check('IC-001').run(rebornCtx([withConfig(`[webui]\nlisten_host = "${host}"`)]));
      expect(r.passed, host).toBe(true);
    }
    expect((await check('IC-001').run(rebornCtx([onboard()]))).passed).toBe(true);
  });

  it('flags `serve --host 0.0.0.0` in the systemd user unit', async () => {
    const unit = `${HOME}/.config/systemd/user/ironclaw-reborn.service`;
    for (const exec of [
      'ExecStart=/home/test/.cargo/bin/ironclaw serve --host 0.0.0.0',
      // `ironclaw service install` quotes every argument
      'ExecStart="/home/test/.cargo/bin/ironclaw" "serve" "--host" "0.0.0.0"',
    ]) {
      const fs = makeFs({ contents: { [unit]: `[Service]\n${exec}\n` } });
      const r = await check('IC-001').run(rebornCtx([onboard()], fs));
      expect(r.passed, exec).toBe(false);
      expect(r.evidence![0].file).toBe(unit);
      expect(r.fixable).toBe(false);
    }
    const loop = makeFs({ contents: { [unit]: '[Service]\nExecStart="/x/ironclaw" "serve" "--host" "127.0.0.1"\n' } });
    expect((await check('IC-001').run(rebornCtx([onboard()], loop))).passed).toBe(true);
  });

  it('0.x: flags HTTP_HOST / GATEWAY_HOST wildcards; the 127.0.0.1 default passes', async () => {
    const bad = await check('IC-001').run(legacyCtx([env(`${LEGACY}/.env`, { HTTP_HOST: '0.0.0.0', GATEWAY_HOST: '0.0.0.0' })]));
    expect(bad.passed).toBe(false);
    expect(bad.evidence).toHaveLength(2);
    const ok = await check('IC-001').run(legacyCtx([env(`${LEGACY}/.env`, { HTTP_PORT: '8080' })]));
    expect(ok.passed).toBe(true);
  });
});

// ── fixes write only schema keys ────────────────────────────────────────

const REBORN_TOP_LEVEL = new Set([
  'api_version', 'boot', 'identity', 'policy', 'drivers', 'harness', 'runner', 'skills',
  'storage', 'llm', 'webui', 'google', 'budget', 'trigger_poller', 'memory', 'slack', 'telegram',
]);
const WEBUI_KEYS = new Set([
  'listen_host', 'listen_port', 'env_token_var', 'env_user_id_var', 'allowed_origins',
  'csp_header_override', 'max_body_bytes_fallback', 'canonical_host',
]);

describe('IronClaw fixes (deny_unknown_fields config.toml)', () => {
  let dir: string | undefined;
  afterEach(async () => { if (dir) await rm(dir, { recursive: true, force: true }); dir = undefined; });

  async function tmpConfig(raw: string): Promise<ParsedConfig> {
    dir = await mkdtemp(join(tmpdir(), 'vaso-ic-'));
    const p = join(dir, 'config.toml');
    await writeFile(p, raw);
    return toml(p, raw);
  }

  it('IC-001 rewrites only [webui].listen_host', async () => {
    const cfg = await tmpConfig(`${ONBOARD_CONFIG}\n[webui]\nlisten_host = "0.0.0.0"\nallowed_origins = ["https://app.example.com"]\n`);
    const ctx = rebornCtx([cfg]);
    ctx.installation.installDir = dir!;
    const res = await check('IC-001').fix!(ctx);
    expect(res.applied).toBe(true);
    const after = parseToml(await readFile(cfg.filePath, 'utf8')) as Record<string, any>;
    expect(after.webui.listen_host).toBe('127.0.0.1');
    for (const k of Object.keys(after)) expect(REBORN_TOP_LEVEL.has(k), k).toBe(true);
    for (const k of Object.keys(after.webui)) expect(WEBUI_KEYS.has(k), k).toBe(true);
    expect(after.llm.default.provider_id).toBe('ollama');
  });

  it('IC-006 switches [boot].profile from local-dev-yolo to local-dev', async () => {
    const cfg = await tmpConfig(ONBOARD_CONFIG.replace('profile = "local-dev"', 'profile = "local-dev-yolo"'));
    const ctx = rebornCtx([cfg]);
    expect((await check('IC-006').run(ctx)).fixable).toBe(true);
    await check('IC-006').fix!(ctx);
    const after = parseToml(await readFile(cfg.filePath, 'utf8')) as Record<string, any>;
    expect(after.boot).toEqual({ profile: 'local-dev' });
    for (const k of Object.keys(after)) expect(REBORN_TOP_LEVEL.has(k), k).toBe(true);
  });

  it('IC-007 sets an existing [policy].default_approval_policy to ask_destructive', async () => {
    const cfg = await tmpConfig(`${ONBOARD_CONFIG}\n[policy]\ndeployment_mode = "local_single_user"\ndefault_approval_policy = "minimal"\n`);
    await check('IC-007').fix!(rebornCtx([cfg]));
    const after = parseToml(await readFile(cfg.filePath, 'utf8')) as Record<string, any>;
    expect(after.policy).toEqual({ deployment_mode: 'local_single_user', default_approval_policy: 'ask_destructive' });
  });

  it('0.x fixes write valid .env keys (SANDBOX_POLICY=readonly, not the invalid "restricted")', async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-ic-'));
    const p = join(dir, '.env');
    await writeFile(p, 'SANDBOX_POLICY=full_access\nSANDBOX_ALLOW_FULL_ACCESS=true\nSANDBOX_ENABLED=false\n');
    const cfg = env(p, { SANDBOX_POLICY: 'full_access', SANDBOX_ALLOW_FULL_ACCESS: 'true', SANDBOX_ENABLED: 'false' });
    const ctx = legacyCtx([cfg]);
    await check('IC-006').fix!(ctx);
    await check('IC-005').fix!(ctx);
    const out = await readFile(p, 'utf8');
    expect(out).toContain('SANDBOX_POLICY=readonly');
    expect(out).toContain('SANDBOX_ENABLED=true');
  });
});

// ── IC-002 ──────────────────────────────────────────────────────────────

describe('IC-002: Cleartext LLM Endpoint', () => {
  it('flags http:// LAN base_url in [llm.default] and providers.json; loopback/https pass', async () => {
    const cfg = withConfig('').raw.replace('model = "llama3.2"', 'model = "llama3.2"\nbase_url = "http://10.20.30.41:11434"');
    const providers = JSON.stringify([{ id: 'lan', protocol: 'open_ai_completions', default_base_url: 'http://10.0.0.5/v1', model_env: 'X', default_model: 'm', description: 'd' }]);
    const r = await check('IC-002').run(rebornCtx([toml(`${REBORN}/config.toml`, cfg), json(`${REBORN}/providers.json`, providers)]));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(2);

    const local = ONBOARD_CONFIG.replace('model = "llama3.2"', 'model = "llama3.2"\nbase_url = "http://localhost:11434"');
    expect((await check('IC-002').run(rebornCtx([toml(`${REBORN}/config.toml`, local), json(`${REBORN}/providers.json`, PROVIDERS_JSON)]))).passed).toBe(true);
  });

  it('0.x: flags http:// *_BASE_URL in .env', async () => {
    const r = await check('IC-002').run(legacyCtx([env(`${LEGACY}/.env`, { LLM_BACKEND: 'ollama', OLLAMA_BASE_URL: 'http://10.1.1.1:11434' })]));
    expect(r.passed).toBe(false);
    const ok = await check('IC-002').run(legacyCtx([env(`${LEGACY}/.env`, { OLLAMA_BASE_URL: 'http://127.0.0.1:11434' })]));
    expect(ok.passed).toBe(true);
  });
});

// ── IC-003 ──────────────────────────────────────────────────────────────

describe('IC-003: Orchestrator Worker API (0.x)', () => {
  it('reports the Linux 0.0.0.0 bind as info when the sandbox is enabled', async () => {
    const r = await check('IC-003').run(legacyCtx([env(`${LEGACY}/.env`, { ORCHESTRATOR_PORT: '50052' })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.message).toContain('50052');
  });

  it('passes with the sandbox disabled, on macOS, and for 1.x', async () => {
    expect((await check('IC-003').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_ENABLED: 'false' })]))).passed).toBe(true);
    expect((await check('IC-003').run(legacyCtx([], makeFs({ platform: 'darwin' })))).passed).toBe(true);
    expect((await check('IC-003').run(rebornCtx([onboard()]))).passed).toBe(true);
  });
});

// ── IC-004 ──────────────────────────────────────────────────────────────

describe('IC-004: WebUI Bearer Token Exposure', () => {
  it('flags a world-readable webui-token as critical', async () => {
    const fs = makeFs({ dirs: { [`${HOME}/.ironclaw`]: 0o755, [REBORN]: 0o755 }, files: { [`${REBORN}/webui-token`]: 0o644 } });
    const r = await check('IC-004').run(rebornCtx([onboard()], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it('downgrades to info when the home dir blocks traversal; 0600 passes', async () => {
    const blocked = makeFs({ dirs: { [HOME]: 0o700, [REBORN]: 0o755 }, files: { [`${REBORN}/webui-token`]: 0o644 } });
    expect((await check('IC-004').run(rebornCtx([onboard()], blocked))).severity).toBe('info');
    const ok = makeFs({ files: { [`${REBORN}/webui-token`]: 0o600 } });
    expect((await check('IC-004').run(rebornCtx([onboard()], ok))).passed).toBe(true);
  });

  it('0.x: flags a gateway token left in the config.toml overlay', async () => {
    const r = await check('IC-004').run(legacyCtx([toml(`${LEGACY}/config.toml`, '[channels]\ngateway_enabled = true\ngateway_auth_token = "abc123"\n')]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
  });
});

// ── IC-005 ──────────────────────────────────────────────────────────────

describe('IC-005: Docker Sandbox Disabled (0.x)', () => {
  it('flags SANDBOX_ENABLED=false and [sandbox].enabled = false', async () => {
    expect((await check('IC-005').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_ENABLED: 'false' })]))).passed).toBe(false);
    expect((await check('IC-005').run(legacyCtx([toml(`${LEGACY}/config.toml`, '[sandbox]\nenabled = false\npolicy = "readonly"\n')]))).passed).toBe(false);
  });

  it('passes when enabled, unset, or on 1.x', async () => {
    expect((await check('IC-005').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_ENABLED: 'true' })]))).passed).toBe(true);
    expect((await check('IC-005').run(rebornCtx([onboard()]))).passed).toBe(true);
  });
});

// ── IC-006 ──────────────────────────────────────────────────────────────

describe('IC-006: Unrestricted Host Access Profile', () => {
  it('flags [boot].profile = "local-dev-yolo"', async () => {
    const cfg = toml(`${REBORN}/config.toml`, ONBOARD_CONFIG.replace('"local-dev"', '"local-dev-yolo"'));
    const r = await check('IC-006').run(rebornCtx([cfg]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
  });

  it('flags IRONCLAW_REBORN_PROFILE=local-dev-yolo from the environment and a service unit (not fixable in config)', async () => {
    const unit = `${HOME}/.config/systemd/user/ironclaw-reborn.service`;
    const fs = makeFs({
      env: { IRONCLAW_REBORN_PROFILE: 'local-dev-yolo' },
      contents: { [unit]: '[Service]\nEnvironment="IRONCLAW_REBORN_PROFILE=local-dev-yolo"\nExecStart=/usr/local/bin/ironclaw serve --confirm-host-access\n' },
    });
    const r = await check('IC-006').run(rebornCtx([onboard()], fs));
    expect(r.passed).toBe(false);
    expect(r.evidence!.map(e => e.file)).toEqual(['environment', unit, unit]);
    expect(r.fixable).toBe(false);
  });

  it('flags a launchd agent that pins the yolo profile', async () => {
    const plist = `${HOME}/Library/LaunchAgents/com.ironclaw.reborn.plist`;
    const fs = makeFs({ contents: { [plist]: '<dict>\n<key>IRONCLAW_REBORN_PROFILE</key>\n<string>local-dev-yolo</string>\n</dict>\n' } });
    expect((await check('IC-006').run(rebornCtx([onboard()], fs))).passed).toBe(false);
  });

  it('0.x: full_access needs the SANDBOX_ALLOW_FULL_ACCESS double opt-in to be live', async () => {
    const without = await check('IC-006').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_POLICY: 'full_access' })]));
    expect(without.passed).toBe(true);
    const withAllow = await check('IC-006').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_POLICY: 'full_access', SANDBOX_ALLOW_FULL_ACCESS: 'true' })]));
    expect(withAllow.passed).toBe(false);
  });
});

// ── IC-007 ──────────────────────────────────────────────────────────────

describe('IC-007: Tool Approval Bypass', () => {
  it('0.x: AGENT_AUTO_APPROVE_TOOLS=true is critical; [agent].auto_approve_tools too', async () => {
    const r = await check('IC-007').run(legacyCtx([env(`${LEGACY}/.env`, { AGENT_AUTO_APPROVE_TOOLS: 'true' })]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect((await check('IC-007').run(legacyCtx([toml(`${LEGACY}/config.toml`, '[agent]\nauto_approve_tools = true\n')]))).passed).toBe(false);
    expect((await check('IC-007').run(legacyCtx([env(`${LEGACY}/.env`, { AGENT_AUTO_APPROVE_TOOLS: 'false' })]))).passed).toBe(true);
  });

  it('1.x: default_approval_policy = "minimal" is a warning; ask_destructive passes', async () => {
    const r = await check('IC-007').run(rebornCtx([withConfig('[policy]\ndefault_approval_policy = "minimal"')]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect((await check('IC-007').run(rebornCtx([withConfig('[policy]\ndefault_approval_policy = "ask_destructive"')]))).passed).toBe(true);
  });
});

// ── IC-008 ──────────────────────────────────────────────────────────────

describe('IC-008: Local Tools Outside Sandbox (0.x)', () => {
  it('flags ALLOW_LOCAL_TOOLS=true only', async () => {
    expect((await check('IC-008').run(legacyCtx([env(`${LEGACY}/.env`, { ALLOW_LOCAL_TOOLS: 'true' })]))).passed).toBe(false);
    expect((await check('IC-008').run(legacyCtx([env(`${LEGACY}/.env`, {})]))).passed).toBe(true);
    expect((await check('IC-008').run(rebornCtx([onboard()]))).passed).toBe(true);
  });
});

// ── IC-009 ──────────────────────────────────────────────────────────────

describe('IC-009: Secrets Master Key Exposure', () => {
  const keyPath = `${REBORN}/local-dev/.reborn-local-dev-secrets-master-key`;

  it('1.x: flags a group/world-readable fallback key file; 0600 passes', async () => {
    const bad = makeFs({ dirs: { [REBORN]: 0o755, [`${REBORN}/local-dev`]: 0o755 }, files: { [keyPath]: 0o640 } });
    const r = await check('IC-009').run(rebornCtx([onboard()], bad));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    const ok = makeFs({ files: { [keyPath]: 0o600 } });
    expect((await check('IC-009').run(rebornCtx([onboard()], ok))).passed).toBe(true);
  });

  it('0.x: flags a plaintext SECRETS_MASTER_KEY, ignores ${VAR} placeholders', async () => {
    const r = await check('IC-009').run(legacyCtx([env(`${LEGACY}/.env`, { SECRETS_MASTER_KEY: '0f1e2d3c4b5a69788796a5b4c3d2e1f0' })]));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].snippet).not.toContain('0f1e2d3c4b5a6978');
    expect((await check('IC-009').run(legacyCtx([env(`${LEGACY}/.env`, { SECRETS_MASTER_KEY: '${VAULT_KEY}' })]))).passed).toBe(true);
  });
});

// ── IC-010 ──────────────────────────────────────────────────────────────

describe('IC-010: Telegram Channel Without Owner ID (0.x)', () => {
  const fs = makeFs({ dirs: { [`${LEGACY}/channels`]: 0o755 }, files: { [`${LEGACY}/channels/telegram.wasm`]: 0o644 } });

  it('flags an installed Telegram channel with no TELEGRAM_OWNER_ID', async () => {
    const r = await check('IC-010').run(legacyCtx([env(`${LEGACY}/.env`, { LLM_BACKEND: 'nearai' })], fs));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].file).toBe(`${LEGACY}/channels/telegram.wasm`);
  });

  it('passes with an owner id or no channel installed', async () => {
    expect((await check('IC-010').run(legacyCtx([env(`${LEGACY}/.env`, { TELEGRAM_OWNER_ID: '123456789' })], fs))).passed).toBe(true);
    expect((await check('IC-010').run(legacyCtx([env(`${LEGACY}/.env`, {})]))).passed).toBe(true);
  });
});

// ── IC-011 ──────────────────────────────────────────────────────────────

describe('IC-011: Broad Sandbox Domain Allowlist (0.x)', () => {
  it('flags wildcards in SANDBOX_EXTRA_DOMAINS and [sandbox].extra_allowed_domains', async () => {
    expect((await check('IC-011').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_EXTRA_DOMAINS: '*.evil.com, api.example.com' })]))).passed).toBe(false);
    expect((await check('IC-011').run(legacyCtx([toml(`${LEGACY}/config.toml`, '[sandbox]\nextra_allowed_domains = ["*"]\n')]))).passed).toBe(false);
    expect((await check('IC-011').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_EXTRA_DOMAINS: 'api.example.com,docs.example.com' })]))).passed).toBe(true);
  });
});

// ── IC-012 ──────────────────────────────────────────────────────────────

describe('IC-012: Sandbox Image Pulled Without Digest Pin (0.x)', () => {
  it('flags an explicitly auto-pulled registry tag', async () => {
    const r = await check('IC-012').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_AUTO_PULL: 'true', SANDBOX_IMAGE: 'ghcr.io/example/worker:latest' })]));
    expect(r.passed).toBe(false);
  });

  it('passes for digest pins, disabled auto-pull, and the untouched default', async () => {
    expect((await check('IC-012').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_IMAGE: 'ghcr.io/example/worker@sha256:abcdef0123456789' })]))).passed).toBe(true);
    expect((await check('IC-012').run(legacyCtx([env(`${LEGACY}/.env`, { SANDBOX_AUTO_PULL: 'false', SANDBOX_IMAGE: 'x:latest' })]))).passed).toBe(true);
    expect((await check('IC-012').run(legacyCtx([env(`${LEGACY}/.env`, { LLM_BACKEND: 'nearai' })]))).passed).toBe(true);
  });
});

// ── IC-013 ──────────────────────────────────────────────────────────────

describe('IC-013: Permissive WebUI CORS Origins', () => {
  it('flags "null", "*" and cleartext remote origins', async () => {
    const r = await check('IC-013').run(rebornCtx([withConfig('[webui]\nallowed_origins = ["null", "*", "http://chat.example.com", "https://ok.example.com", "http://localhost:3000"]')]));
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(3);
  });

  it('passes for https / loopback origins and the empty default', async () => {
    expect((await check('IC-013').run(rebornCtx([withConfig('[webui]\nallowed_origins = ["https://app.example.com", "http://127.0.0.1:3000"]')]))).passed).toBe(true);
    expect((await check('IC-013').run(rebornCtx([onboard()]))).passed).toBe(true);
  });
});

// ── IC-014 ──────────────────────────────────────────────────────────────

describe('IC-014: State Database World-Readable', () => {
  it('flags a readable libSQL database when parents are traversable', async () => {
    const db = `${REBORN}/local-dev/reborn-local-dev.db`;
    const fs = makeFs({ dirs: { [`${HOME}/.ironclaw`]: 0o755, [REBORN]: 0o755, [`${REBORN}/local-dev`]: 0o755 }, files: { [db]: 0o644, [`${db}-wal`]: 0o644 } });
    const r = await check('IC-014').run(rebornCtx([onboard()], fs));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence).toHaveLength(2);
  });

  it('0.x: checks ~/.ironclaw/ironclaw.db', async () => {
    const fs = makeFs({ dirs: { [LEGACY]: 0o755 }, files: { [`${LEGACY}/ironclaw.db`]: 0o600 } });
    expect((await check('IC-014').run(legacyCtx([], fs))).passed).toBe(true);
  });
});
