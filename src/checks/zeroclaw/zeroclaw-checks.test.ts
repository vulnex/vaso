import { describe, it, expect, vi } from 'vitest';
import { parse as parseTOML } from 'smol-toml';
import type { FSProvider } from '../../core/fs-provider.js';
import type { AgentInstallation, ParsedConfig, ScanContext } from '../../core/types.js';
import { zeroclawChecks } from './index.js';
import { effectiveProfiles, gatewayPosture } from './zc-config.js';
import { findPlaintextSecrets } from './zc-secrets.js';
import { applyEnvOverrides } from '../../adapters/env-overrides.js';
import { zeroclawEnvSpecs } from '../../adapters/zeroclaw.js';

vi.mock('../../remediation/config-writer.js', async (orig) => ({
  ...(await orig<typeof import('../../remediation/config-writer.js')>()),
  updateConfigValue: vi.fn(async () => {}),
  chmodFile: vi.fn(async () => {}),
}));
import { updateConfigValue } from '../../remediation/config-writer.js';

/** A written key path as dotted text (profile fixes pass segments). */
const pathText = (p: unknown): unknown => (Array.isArray(p) ? p.join('.') : p);

const DIR = '/home/test/.zeroclaw';
const CONFIG = `${DIR}/config.toml`;

/** What `zeroclaw config set` expands for a fresh 0.8.5 install: one agent on a
 *  supervised, workspace-only risk profile with upstream default lists. */
const DEFAULT_V3 = `schema_version = 3

[providers]

[agents.assistant]
acp_enable_mcp = false
delegate_same_risk_profile = true
enabled = true
model_provider = "ollama.local"
risk_profile = "balanced"

[risk_profiles.balanced]
allowed_commands = ["git", "npm", "cargo", "ls", "cat", "grep"]
auto_approve = ["file_read", "memory_recall", "web_search_tool", "web_fetch", "calculator", "glob_search", "content_search", "image_info", "weather", "tool_search", "browser", "browser_open"]
block_high_risk_commands = true
forbidden_paths = ["/etc", "/root", "/home", "~/.ssh"]
level = "supervised"
require_approval_for_medium_risk = true
workspace_only = true

[agents.assistant.a2a]
published = false

[providers.models]

[agents.assistant.memory]
backend = "sqlite"

[providers.models.ollama.local]
model = "llama3.2"

[agents.assistant.workspace]
unrestricted_filesystem = false

[risk_profiles]
`;

function toml(raw: string, filePath = CONFIG): ParsedConfig {
  return { raw, format: 'toml', filePath, data: parseTOML(raw) as Record<string, unknown> };
}

function json(data: Record<string, unknown>, filePath = `${DIR}/auth-profiles.json`): ParsedConfig {
  return { raw: JSON.stringify(data, null, 2), format: 'json', filePath, data };
}

interface FakeFs {
  modes?: Record<string, number>;
  files?: Record<string, string>;
}

function makeFs(o: FakeFs = {}): FSProvider {
  const modes: Record<string, number> = { '/home': 0o755, '/home/test': 0o755, [DIR]: 0o755, ...o.modes };
  const files = o.files ?? {};
  return {
    homedir: () => '/home/test',
    platform: 'linux',
    access: vi.fn(async (p: string) => p in files || p in modes),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw new Error(`ENOENT ${p}`);
    }),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw new Error(`ENOENT ${p}`);
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    }),
    getEnv: () => undefined,
  } as unknown as FSProvider;
}

function ctx(configs: ParsedConfig[], opts: { fs?: FSProvider; version?: string } = {}): ScanContext {
  const installation: AgentInstallation = {
    agent: 'zeroclaw',
    installDir: DIR,
    configFiles: configs,
    version: opts.version ?? '0.8.5',
  };
  return { installation, configs, platform: 'linux', fs: opts.fs ?? makeFs() };
}

const check = (id: string) => zeroclawChecks.find(c => c.id === id)!;

async function run(id: string, raw: string, opts: { fs?: FSProvider; version?: string; extra?: ParsedConfig[] } = {}) {
  return check(id).run(ctx([toml(raw), ...(opts.extra ?? [])], opts));
}

describe('ZeroClaw checks registry', () => {
  it('exports 16 checks ZC-001..ZC-016', () => {
    expect(zeroclawChecks.map(c => c.id)).toEqual(
      Array.from({ length: 16 }, (_, i) => `ZC-${String(i + 1).padStart(3, '0')}`),
    );
    for (const c of zeroclawChecks) {
      expect(c.category).toBe('zeroclaw');
      expect(c.supportedAgents).toContain('zeroclaw');
    }
  });

  it('never throws on real-world shapes (empty, default, scalars among alias maps, nulls)', async () => {
    const shapes = [
      '',
      DEFAULT_V3,
      'schema_version = 3\n[channels]\ncli = true\nmessage_timeout_secs = 300\n[channels.telegram]\n',
      'schema_version = 3\n[peer_groups.g]\nchannel = "discord"\n[risk_profiles.x]\nlevel = 5\nauto_approve = "shell"\n',
      'schema_version = 3\nagents = "oops"\nrisk_profiles = []\nbrowser = 1\ngateway = "x"\n',
    ];
    for (const raw of shapes) {
      for (const c of zeroclawChecks) {
        await expect(c.run(ctx([toml(raw)]))).resolves.toBeDefined();
      }
    }
    for (const c of zeroclawChecks) {
      await expect(c.run(ctx([]))).resolves.toMatchObject({ passed: true });
    }
  });

  it('a fresh 0.8.5 default install only trips ZC-011 (browser auto-approved by default)', async () => {
    const failed: string[] = [];
    for (const c of zeroclawChecks) {
      const r = await c.run(ctx([toml(DEFAULT_V3)]));
      if (!r.passed) failed.push(r.id);
    }
    expect(failed).toEqual(['ZC-011']);
  });
});

describe('shared readers', () => {
  it('binds risk profiles to enabled agents only', () => {
    const data = parseTOML(`
[agents.a]
risk_profile = "yolo"
[agents.b]
enabled = false
risk_profile = "unused"
[risk_profiles.yolo]
level = "full"
[risk_profiles.unused]
level = "full"
`) as Record<string, unknown>;
    expect(effectiveProfiles(data).map(p => [p.name, p.agents])).toEqual([['yolo', ['a']]]);
  });

  it('evaluates every profile when no agents are declared, and V2 [autonomy] as legacy', () => {
    expect(effectiveProfiles({ risk_profiles: { a: {}, b: {} } }).map(p => p.name)).toEqual(['a', 'b']);
    expect(effectiveProfiles({ autonomy: { level: 'full' } })).toMatchObject([{ path: ['autonomy'], legacy: true }]);
  });

  it('applies gateway defaults', () => {
    expect(gatewayPosture({})).toMatchObject({
      host: '127.0.0.1', hostExposed: false, requirePairing: true, tunnelActive: false, tlsEnabled: false,
    });
    expect(gatewayPosture({ gateway: { host: '192.168.0.10' } }).hostExposed).toBe(true);
    expect(gatewayPosture({ gateway: { host: '::1' } }).hostExposed).toBe(false);
  });

  it('finds plaintext secrets but not enc2:/enc:/op:// values or ${VAR} references', () => {
    const found = findPlaintextSecrets({
      providers: { models: { openai: { main: { api_key: 'sk-plain', model: 'gpt-4o' } } } },
      reliability: { api_keys: ['sk-a', 'enc2:ab'] },
      channels: { telegram: { main: { bot_token: 'op://vault/item/field' } } },
      http_request: { secrets: { github: 'ghp_plain' } },
      composio: { api_key: 'enc:00ff' },
      gateway: { webhook_secret: '${ZC_WEBHOOK_SECRET}' },
      secrets: { encrypt: false },
      profiles: { 'openai:default': { accessToken: 'plain-token' } },
    }).map(s => s.path);
    expect(found).toEqual([
      'providers.models.openai.main.api_key',
      'reliability.api_keys[0]',
      'http_request.secrets.github',
      'profiles.openai:default.accessToken',
    ]);
  });
});

describe('ZC-001: Plaintext Secrets in Config', () => {
  const insecure = `schema_version = 3
[secrets]
encrypt = false
[providers.models.openai.main]
model = "gpt-4o"
api_key = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"
[reliability]
api_keys = ["sk-ant-fallback-0000000000000000"]
`;

  it('flags plaintext provider keys and reliability.api_keys (warning, fixable)', async () => {
    const r = await run('ZC-001', insecure, { fs: makeFs({ modes: { [CONFIG]: 0o600 } }) });
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.fixable).toBe(true);
    expect(r.evidence![0].detail).toContain('reliability.api_keys[0]');
  });

  it('escalates to critical when the file is readable by other users', async () => {
    const r = await run('ZC-001', insecure, { fs: makeFs({ modes: { [CONFIG]: 0o644 } }) });
    expect(r.severity).toBe('critical');
  });

  it('scans auth-profiles.json and the migration backup', async () => {
    const fs = makeFs({ files: { [`${DIR}/config.toml.backup`]: 'api_key = "sk-legacy-plaintext-v1"\n' } });
    const auth = json({ profiles: { 'openai:default': { access_token: 'plain-oauth-token' } } });
    const r = await run('ZC-001', DEFAULT_V3, { fs, extra: [auth] });
    expect(r.passed).toBe(false);
    expect(r.evidence!.map(e => e.file).sort()).toEqual([`${DIR}/auth-profiles.json`, `${DIR}/config.toml.backup`]);
    expect(r.fixable).toBe(false); // encrypt is on (default) — nothing to toggle
  });

  it('passes on a documentation placeholder key', async () => {
    const r = await run('ZC-001', '[providers.models.anthropic.cloud]\napi_key = "sk-ant-..."\n');
    expect(r.passed).toBe(true);
  });

  it('passes with encrypted secrets', async () => {
    const r = await run('ZC-001', '[providers.models.openai.main]\napi_key = "enc2:00ab"\n');
    expect(r.passed).toBe(true);
  });

  it('fix sets secrets.encrypt=true on config.toml only', async () => {
    vi.mocked(updateConfigValue).mockClear();
    const res = await check('ZC-001').fix!(ctx([json({}), toml(insecure)]));
    expect(res.applied).toBe(true);
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [c[0].filePath, pathText(c[1]), c[2]])).toEqual([
      [CONFIG, 'secrets.encrypt', true],
    ]);
  });
});

describe('ZC-002: Legacy XOR-Encrypted Secrets', () => {
  it('flags enc: values', async () => {
    const r = await run('ZC-002', '[composio]\napi_key = "enc:0a1b2c3d"\n');
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    expect(r.evidence![0].line).toBe(2);
  });

  it('does not flag enc2: values or comments', async () => {
    const r = await run('ZC-002', '# was "enc:00"\n[composio]\napi_key = "enc2:0a1b2c3d"\n');
    expect(r.passed).toBe(true);
  });
});

describe('ZC-003 / ZC-004: gateway exposure and pairing', () => {
  it('passes on the default loopback gateway', async () => {
    expect((await run('ZC-003', DEFAULT_V3)).passed).toBe(true);
    expect((await run('ZC-004', DEFAULT_V3)).passed).toBe(true);
  });

  it('ZC-003 warns on a LAN bind without TLS/tunnel; critical when pairing is off', async () => {
    const lan = await run('ZC-003', '[gateway]\nhost = "10.20.30.40"\n');
    expect(lan).toMatchObject({ passed: false, severity: 'warning' });
    const open = await run('ZC-003', '[gateway]\nhost = "0.0.0.0"\nrequire_pairing = false\n');
    expect(open.severity).toBe('critical');
  });

  it('ZC-003 flags allow_public_bind but accepts a tunnel or TLS', async () => {
    expect((await run('ZC-003', '[gateway]\nallow_public_bind = true\n')).passed).toBe(false);
    expect((await run('ZC-003', '[gateway]\nhost = "0.0.0.0"\n[tunnel]\ntunnel_provider = "cloudflare"\n')).passed).toBe(true);
    expect((await run('ZC-003', '[gateway]\nhost = "0.0.0.0"\n[gateway.tls]\nenabled = true\n')).passed).toBe(true);
  });

  it('ZC-004 is a warning on loopback and critical when tunnelled', async () => {
    expect(await run('ZC-004', '[gateway]\nrequire_pairing = false\n')).toMatchObject({ passed: false, severity: 'warning' });
    const tunnelled = await run('ZC-004', '[gateway]\nrequire_pairing = false\n[tunnel]\ntunnel_provider = "ngrok"\n');
    expect(tunnelled.severity).toBe('critical');
  });

  it('fixes write real [gateway] keys', async () => {
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-003').fix!(ctx([toml('[gateway]\nhost = "0.0.0.0"\n')]));
    await check('ZC-004').fix!(ctx([toml('[gateway]\nrequire_pairing = false\n')]));
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [pathText(c[1]), c[2]])).toEqual([
      ['gateway.host', '127.0.0.1'],
      ['gateway.allow_public_bind', false],
      ['gateway.require_pairing', true],
    ]);
  });
});

const YOLO = `[agents.bot]
risk_profile = "yolo"
[risk_profiles.yolo]
level = "full"
workspace_only = false
allowed_commands = ["*"]
block_high_risk_commands = false
auto_approve = ["*"]
sandbox_enabled = false
`;

describe('risk-profile checks (ZC-005/006/014/015)', () => {
  it('ZC-005 flags the yolo preset and fixes the level', async () => {
    const r = await run('ZC-005', YOLO);
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
    expect(r.evidence![0].detail).toContain('agent: bot');
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-005').fix!(ctx([toml(YOLO)]));
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [pathText(c[1]), c[2]])).toEqual([['risk_profiles.yolo.level', 'supervised']]);
  });

  it('ZC-005 fixes a profile whose name contains a dot as one quoted key', async () => {
    const raw = '[agents.main]\nrisk_profile = "prod.v2"\n[risk_profiles."prod.v2"]\nlevel = "full"\n';
    const r = await run('ZC-005', raw);
    expect(r.passed).toBe(false);
    expect(r.evidence![0].detail).toContain('risk_profiles."prod.v2"');
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-005').fix!(ctx([toml(raw)]));
    // segments, not 'risk_profiles.prod.v2.level' — that splits into a new [risk_profiles.prod.v2] table
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [c[1], c[2]])).toEqual([[['risk_profiles', 'prod.v2', 'level'], 'supervised']]);
  });

  it('ZC-005 ignores profiles no enabled agent uses', async () => {
    const r = await run('ZC-005', '[agents.bot]\nrisk_profile = "balanced"\n[risk_profiles.balanced]\n[risk_profiles.yolo]\nlevel = "full"\n');
    expect(r.passed).toBe(true);
  });

  it('ZC-005 honours the legacy V2 [autonomy] table', async () => {
    expect((await run('ZC-005', '[autonomy]\nlevel = "full"\n')).passed).toBe(false);
  });

  it('ZC-006 flags workspace_only=false, broad allowed_roots and unrestricted_filesystem', async () => {
    const r = await run('ZC-006', `${YOLO}allowed_roots = ["~"]\n[agents.bot.workspace]\nunrestricted_filesystem = true\n`);
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(3);
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-006').fix!(ctx([toml(`${YOLO}[agents.bot.workspace]\nunrestricted_filesystem = true\n`)]));
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [pathText(c[1]), c[2]])).toEqual([
      ['risk_profiles.yolo.workspace_only', true],
      ['agents.bot.workspace.unrestricted_filesystem', false],
    ]);
  });

  it('ZC-006 flags allowed_roots that contain $HOME (/home, /Users)', async () => {
    const r = await run('ZC-006', '[risk_profiles.p]\nallowed_roots = ["/home", "/opt/projects"]\n');
    expect(r.passed).toBe(false);
    expect(r.evidence).toHaveLength(1);
    expect(r.evidence![0].detail).toContain('contains the home directory');
  });

  it('reads the flat ZEROCLAW_GATEWAY_* names only for releases before 0.8.0', () => {
    const flat = (v?: string) => zeroclawEnvSpecs({}, v).map(sp => sp.env).filter(e => /^ZEROCLAW_(GATEWAY_|ALLOW_)/.test(e));
    // 0.8.0 made ZEROCLAW_<path> the only override form; 0.8.5 ignores the flat names
    expect(flat('0.8.5')).toEqual([]);
    expect(flat(undefined)).toEqual([]);
    expect(flat('0.7.2')).toEqual(['ZEROCLAW_GATEWAY_HOST', 'ZEROCLAW_GATEWAY_PORT', 'ZEROCLAW_ALLOW_PUBLIC_BIND']);
    // The path form is always read
    expect(zeroclawEnvSpecs({}, '0.8.5').map(sp => sp.env)).toContain('ZEROCLAW_gateway__host');
  });

  it('notes an env override in evidence and in the fix message', async () => {
    const data = applyEnvOverrides({ risk_profiles: { p: { level: 'supervised' } } },
      zeroclawEnvSpecs({ risk_profiles: { p: {} } }),
      { getEnv: (k: string) => (k === 'ZEROCLAW_risk_profiles__p__level' ? 'full' : undefined) } as unknown as FSProvider);
    const config: ParsedConfig = { raw: '[risk_profiles.p]\nlevel = "supervised"\n', format: 'toml', filePath: `${DIR}/config.toml`, data };
    const r = await check('ZC-005').run(ctx([config]));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].detail).toContain('$ZEROCLAW_risk_profiles__p__level');
    const fix = await check('ZC-005').fix!(ctx([config]));
    expect(fix.message).toContain('still overrides');
  });

  it('ZC-014 flags sandbox_enabled=false / backend none on the native runtime only', async () => {
    expect((await run('ZC-014', YOLO)).passed).toBe(false);
    expect((await run('ZC-014', `${YOLO}[runtime]\nkind = "docker"\n`)).passed).toBe(true);
    expect((await run('ZC-014', '[risk_profiles.p]\nsandbox_backend = "none"\n')).passed).toBe(false);
    expect((await run('ZC-014', DEFAULT_V3)).passed).toBe(true);
  });

  it('ZC-015 is critical for yolo (any command, no approval)', async () => {
    const r = await run('ZC-015', YOLO);
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
  });

  it('ZC-015 warns on auto-approved shell under supervision, not on the balanced preset', async () => {
    const r = await run('ZC-015', '[risk_profiles.p]\nauto_approve = ["shell", "file_read"]\n');
    expect(r).toMatchObject({ passed: false, severity: 'warning' });
    const balanced = '[risk_profiles.balanced]\nallowed_commands = ["*"]\nblock_high_risk_commands = true\n';
    expect((await run('ZC-015', balanced)).passed).toBe(true);
    expect((await run('ZC-015', '[risk_profiles.p]\nauto_approve = ["shell"]\nalways_ask = ["shell"]\n')).passed).toBe(true);
  });
});

describe('ZC-007: Open-to-Anyone Channel Access', () => {
  it('flags wildcard external_peers on an enabled channel (critical)', async () => {
    const r = await run('ZC-007', `[channels.telegram.main]
enabled = true
bot_token = "enc2:00"
[peer_groups.everyone]
channel = "telegram.main"
agents = ["assistant"]
external_peers = ["*"]
`);
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
  });

  it('reports a wildcard on a disabled channel at info', async () => {
    const r = await run('ZC-007', '[channels.telegram.main]\nbot_token = "x"\n[peer_groups.g]\nchannel = "telegram"\nexternal_peers = ["*"]\n');
    expect(r).toMatchObject({ passed: false, severity: 'info' });
  });

  it('flags a channel-instance allowlist wildcard and ignores ignore=["*"]', async () => {
    expect((await run('ZC-007', '[channels.wecom_ws.main]\nenabled = true\nallowed_users = ["*"]\n')).passed).toBe(false);
    expect((await run('ZC-007', '[peer_groups.g]\nchannel = "discord"\nexternal_peers = ["*"]\nignore = ["*"]\n')).passed).toBe(true);
  });
});

describe('ZC-008: Unvetted Skill Sources', () => {
  it('flags open skills, scripts and http registries; fixes the booleans', async () => {
    const raw = `[skills]
open_skills_enabled = true
allow_scripts = true
registry_url = "http://skills.example.com/repo.git"
[[skills.extra_registries]]
name = "team"
url = "git://example.com/skills.git"
`;
    const r = await run('ZC-008', raw);
    expect(r.evidence).toHaveLength(4);
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-008').fix!(ctx([toml(raw)]));
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [pathText(c[1]), c[2]])).toEqual([
      ['skills.open_skills_enabled', false],
      ['skills.allow_scripts', false],
    ]);
  });

  it('passes for https registries', async () => {
    expect((await run('ZC-008', '[skills]\nregistry_url = "https://github.com/zeroclaw-labs/zeroclaw-skills"\n')).passed).toBe(true);
  });
});

describe('ZC-009: WhatsApp Web Session Store Exposed', () => {
  const raw = '[channels.whatsapp.web]\nenabled = true\nsession_path = "~/.zeroclaw/data/wa-session.db"\n';
  const session = `${DIR}/data/wa-session.db`;

  it('flags a session store readable by others', async () => {
    const fs = makeFs({ modes: { [`${DIR}/data`]: 0o755, [session]: 0o644 } });
    expect(await run('ZC-009', raw, { fs })).toMatchObject({ passed: false, severity: 'critical' });
  });

  it('says a remote scan could not see a session store outside the probe manifest', async () => {
    const fs = { ...makeFs(), kind: 'snapshot' } as FSProvider;
    const r = await run('ZC-009', raw, { fs });
    expect(r.passed).toBe(true);
    expect(r.message).toContain('not collected by the remote probe');
  });

  it('passes for 600 sessions, missing sessions, and Cloud API mode', async () => {
    expect((await run('ZC-009', raw, { fs: makeFs({ modes: { [session]: 0o600 } }) })).passed).toBe(true);
    expect((await run('ZC-009', raw)).passed).toBe(true);
    expect((await run('ZC-009', '[channels.whatsapp.biz]\nenabled = true\naccess_token = "enc2:00"\n')).passed).toBe(true);
  });
});

describe('ZC-010: Composio', () => {
  it('reports composio.enabled at info', async () => {
    expect(await run('ZC-010', '[composio]\nenabled = true\n')).toMatchObject({ passed: false, severity: 'info' });
    expect((await run('ZC-010', DEFAULT_V3)).passed).toBe(true);
  });
});

describe('ZC-011: Browser Automation Without Approval', () => {
  it('0.8.5: default auto_approve lets browser automation run unprompted; fix drops "browser"', async () => {
    const r = await run('ZC-011', DEFAULT_V3);
    expect(r).toMatchObject({ passed: false, severity: 'warning', fixable: true });
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-011').fix!(ctx([toml(DEFAULT_V3)], { version: '0.8.5' }));
    const [[, path, value]] = vi.mocked(updateConfigValue).mock.calls;
    expect(path).toEqual(['risk_profiles', 'balanced', 'auto_approve']);
    expect(value).toContain('browser_open');
    expect(value).not.toContain('browser');
  });

  it('0.8.5: an omitted auto_approve inherits the default list (includes browser)', async () => {
    expect((await run('ZC-011', '[agents.a]\nrisk_profile = "p"\n[risk_profiles.p]\nlevel = "supervised"\n')).passed).toBe(false);
  });

  it('passes when the browser is disabled or on newer builds without automation_enabled', async () => {
    expect((await run('ZC-011', `${DEFAULT_V3}\n[browser]\nenabled = false\n`)).passed).toBe(true);
    expect((await run('ZC-011', DEFAULT_V3, { version: '0.9.0' })).passed).toBe(true);
    expect((await run('ZC-011', `${DEFAULT_V3}\n[browser]\nautomation_enabled = false\n`)).passed).toBe(true);
  });

  it('flags allowed_private_hosts = ["*"]', async () => {
    const r = await run('ZC-011', '[browser]\nallowed_private_hosts = ["*"]\n', { version: '0.9.0' });
    expect(r.passed).toBe(false);
  });
});

describe('ZC-012: Outbound Tools Reach Private Network', () => {
  it('flags http_request private access and wildcard private hosts', async () => {
    const r = await run('ZC-012', '[http_request]\nallow_private_hosts = true\n[web_fetch]\nallowed_private_hosts = ["*"]\n');
    expect(r.evidence).toHaveLength(2);
    expect(r.fixable).toBe(true);
  });

  it('passes on defaults (public-only, wildcard domains)', async () => {
    expect((await run('ZC-012', '[http_request]\nenabled = true\nallowed_domains = ["*"]\n')).passed).toBe(true);
  });
});

describe('ZC-013: .secret_key Permissions', () => {
  const key = `${DIR}/.secret_key`;
  it('flags a group/world-readable key', async () => {
    const r = await check('ZC-013').run(ctx([], { fs: makeFs({ modes: { [key]: 0o644 } }) }));
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
  });

  it('accepts 600 and 400, and a missing key', async () => {
    expect((await check('ZC-013').run(ctx([], { fs: makeFs({ modes: { [key]: 0o600 } }) }))).passed).toBe(true);
    expect((await check('ZC-013').run(ctx([], { fs: makeFs({ modes: { [key]: 0o400 } }) }))).passed).toBe(true);
    expect((await check('ZC-013').run(ctx([]))).passed).toBe(true);
  });

  it('downgrades to info when the config dir is private', async () => {
    const r = await check('ZC-013').run(ctx([], { fs: makeFs({ modes: { [DIR]: 0o700, [key]: 0o644 } }) }));
    expect(r).toMatchObject({ passed: false, severity: 'info' });
  });
});

describe('ZC-016: Gateway Hardening Relaxed', () => {
  it('flags relaxed safeguards and restores defaults', async () => {
    const raw = `[gateway]
allow_self_upgrade = true
trust_forwarded_headers = true
allow_remote_admin = true
pair_rate_limit_per_minute = 0
webhook_rate_limit_per_minute = 0
`;
    const r = await run('ZC-016', raw);
    expect(r.evidence).toHaveLength(5);
    vi.mocked(updateConfigValue).mockClear();
    await check('ZC-016').fix!(ctx([toml(raw)]));
    expect(vi.mocked(updateConfigValue).mock.calls.map(c => [pathText(c[1]), c[2]])).toEqual([
      ['gateway.allow_self_upgrade', false],
      ['gateway.trust_forwarded_headers', false],
      ['gateway.allow_remote_admin', false],
      ['gateway.pair_rate_limit_per_minute', 10],
      ['gateway.webhook_rate_limit_per_minute', 60],
    ]);
  });

  it('passes on defaults', async () => {
    expect((await run('ZC-016', DEFAULT_V3)).passed).toBe(true);
  });
});
