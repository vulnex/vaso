import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { ironclawAdapter } from './ironclaw.js';
import { ironclawChecks } from '../checks/ironclaw/index.js';

const HOME = '/home/test';
const REBORN = `${HOME}/.ironclaw/reborn`;
const LEGACY = `${HOME}/.ironclaw`;

/** `ironclaw onboard` config.toml (1.4.0), comments trimmed. */
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

const PROVIDERS_JSON = JSON.stringify([
  {
    id: 'example-openrouter', aliases: [], protocol: 'open_ai_completions',
    api_key_env: 'ACME_OPENROUTER_KEY', api_key_required: true,
    default_base_url: 'https://openrouter.ai/api/v1', default_model: 'anthropic/claude-3.5-sonnet',
    model_env: 'ACME_OPENROUTER_MODEL', description: 'example',
  },
]);

interface FakeFs {
  files?: Record<string, string>;
  dirs?: string[];
  env?: Record<string, string>;
  which?: string;
  version?: string;
}

function makeFs(o: FakeFs = {}): FSProvider {
  const files = o.files ?? {};
  const dirs = new Set(o.dirs ?? []);
  const children = (p: string) => {
    const prefix = `${p}/`;
    const names = new Map<string, boolean>();
    for (const d of dirs) if (d.startsWith(prefix)) names.set(d.slice(prefix.length).split('/')[0], true);
    for (const f of Object.keys(files)) {
      if (!f.startsWith(prefix)) continue;
      const rest = f.slice(prefix.length).split('/');
      if (!names.has(rest[0])) names.set(rest[0], rest.length > 1);
    }
    return [...names].map(([name, isDirectory]) => ({ name, isDirectory, isFile: !isDirectory }));
  };
  return {
    homedir: () => HOME,
    platform: 'linux',
    access: vi.fn(async (p: string) => p in files || dirs.has(p)),
    readFile: vi.fn(async (p: string) => {
      if (p in files) return files[p];
      throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
    }),
    stat: vi.fn(async (p: string) => ({ mode: 0o100600, isFile: () => p in files, isDirectory: () => dirs.has(p) })),
    readdir: vi.fn(async (p: string) => children(p).map(c => c.name)),
    readdirEntries: vi.fn(async (p: string) => children(p)),
    realpath: vi.fn(async (p: string) => p),
    execSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === 'which' && args[0] === 'ironclaw' && o.which) return o.which;
      if (args[0] === '--version' && o.version) return o.version;
      throw new Error('not found');
    }),
    getEnv: vi.fn((k: string) => o.env?.[k]),
  } as unknown as FSProvider;
}

/** The live 1.4.0 layout after `ironclaw onboard --no-service` + `ironclaw serve`. */
function rebornLayout(extra: FakeFs = {}): FakeFs {
  return {
    dirs: [
      LEGACY, REBORN, `${REBORN}/local-dev`, `${REBORN}/local-dev/system`,
      `${REBORN}/local-dev/system/skills`, `${REBORN}/local-dev/system/skills/coding`,
      `${REBORN}/local-dev/tenants`, `${REBORN}/local-dev/tenants/reborn-cli`,
      `${REBORN}/local-dev/tenants/reborn-cli/users`, `${REBORN}/local-dev/tenants/reborn-cli/users/owner`,
      `${REBORN}/local-dev/tenants/reborn-cli/users/owner/skills`,
      `${LEGACY}/trace_contributions`,
      ...(extra.dirs ?? []),
    ],
    files: {
      [`${REBORN}/config.toml`]: ONBOARD_CONFIG,
      [`${REBORN}/providers.json`]: PROVIDERS_JSON,
      [`${REBORN}/.onboard-completed.json`]: '{}',
      [`${REBORN}/webui-token`]: 'x'.repeat(64),
      [`${REBORN}/local-dev/.reborn-local-dev-secrets-master-key`]: 'k',
      [`${REBORN}/local-dev/reborn-local-dev.db`]: '',
      [`${REBORN}/local-dev/system/skills/coding/SKILL.md`]: '# coding',
      [`${HOME}/.cargo/bin/ironclaw`]: '',
      ...(extra.files ?? {}),
    },
    env: extra.env,
    version: extra.version ?? 'ironclaw 1.4.0',
    which: extra.which,
  };
}

describe('IronClaw adapter — 1.x Reborn', () => {
  it('returns nothing when neither layout nor binary exists', async () => {
    expect(await ironclawAdapter.detect({ fs: makeFs() })).toEqual([]);
  });

  it('detects ~/.ironclaw/reborn with config.toml + providers.json, version, models, gateway and skill roots', async () => {
    const [inst, ...rest] = await ironclawAdapter.detect({ fs: makeFs(rebornLayout()) });
    expect(rest).toHaveLength(0); // trace_contributions alone is not a 0.x install
    expect(inst.agent).toBe('ironclaw');
    expect(inst.installDir).toBe(REBORN);
    expect(inst.profile).toBeUndefined();
    expect(inst.version).toBe('1.4.0');
    expect(inst.cliBinary).toBe(`${HOME}/.cargo/bin/ironclaw`);
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${REBORN}/config.toml`, `${REBORN}/providers.json`]);
    expect(inst.models).toEqual([{ id: 'llama3.2', provider: 'ollama' }]);
    // stock loopback listener: not reported as a gateway (generic TLS/exposure checks would misread it)
    expect(inst.gateway).toBeUndefined();
    expect(inst.skillsDirs).toEqual([
      `${REBORN}/local-dev/system/skills`,
      `${REBORN}/local-dev/tenants/reborn-cli/users/owner/skills`,
    ]);
  });

  it('honours IRONCLAW_REBORN_HOME from the scanned host', async () => {
    const fs = makeFs({
      dirs: ['/srv/ic'],
      files: { '/srv/ic/config.toml': `${ONBOARD_CONFIG}\n[webui]\nlisten_host = "0.0.0.0"\nlisten_port = 8080\n` },
      env: { IRONCLAW_REBORN_HOME: '/srv/ic' },
    });
    const [inst] = await ironclawAdapter.detect({ fs });
    expect(inst.installDir).toBe('/srv/ic');
    expect(inst.gateway).toMatchObject({ host: '0.0.0.0', port: 8080 });
  });

  it('a 1.x binary with no state yet is a Reborn install', async () => {
    const [inst] = await ironclawAdapter.detect({ fs: makeFs({ files: { [`${HOME}/.cargo/bin/ironclaw`]: '' }, version: 'ironclaw 1.4.0' }) });
    expect(inst.installDir).toBe(REBORN);
    expect(inst.version).toBe('1.4.0');
    expect(inst.configFiles).toEqual([]);
  });

  it('getModels: slot without model falls back to the providers.json default_model; named slots carry `via`', () => {
    const configs = [
      { raw: '', format: 'toml' as const, filePath: `${REBORN}/config.toml`, data: {
        api_version: 'ironclaw.runtime/v1',
        llm: { mission: { provider_id: 'anthropic', model: 'claude-x' }, default: { provider_id: 'example-openrouter' } },
      } },
      { raw: PROVIDERS_JSON, format: 'json' as const, filePath: `${REBORN}/providers.json`, data: JSON.parse(PROVIDERS_JSON) },
    ];
    expect(ironclawAdapter.getModels!(configs)).toEqual([
      { id: 'anthropic/claude-3.5-sonnet', provider: 'example-openrouter' },
      { id: 'claude-x', provider: 'anthropic', via: 'mission' },
    ]);
  });

  it('getModels: no [llm.default] slot falls back to LLM env vars', () => {
    const fs = { getEnv: (k: string) => ({ LLM_BACKEND: 'anthropic', ANTHROPIC_MODEL: 'claude-haiku-4-5' } as Record<string, string>)[k] } as unknown as FSProvider;
    const configs = [{ raw: '', format: 'toml' as const, filePath: `${REBORN}/config.toml`, data: { api_version: 'ironclaw.runtime/v1', llm: {} } }];
    expect(ironclawAdapter.getModels!(configs, fs)).toEqual([{ id: 'claude-haiku-4-5', provider: 'anthropic' }]);
  });
});

describe('IronClaw adapter — 0.x legacy', () => {
  it('detects ~/.ironclaw/.env + ironclaw.db as a legacy install when the binary is 0.x', async () => {
    const fs = makeFs({
      dirs: [LEGACY, `${LEGACY}/skills`],
      files: {
        [`${LEGACY}/.env`]: 'DATABASE_BACKEND=libsql\nLLM_BACKEND=nearai\nNEARAI_MODEL=deepseek-ai/DeepSeek-V3\nGATEWAY_PORT=3000\n',
        [`${LEGACY}/ironclaw.db`]: '',
        [`${HOME}/.cargo/bin/ironclaw`]: '',
      },
      version: 'ironclaw 0.29.1',
    });
    const [inst, ...rest] = await ironclawAdapter.detect({ fs });
    expect(rest).toHaveLength(0);
    expect(inst.installDir).toBe(LEGACY);
    expect(inst.profile).toBe('legacy');
    expect(inst.version).toBe('0.29.1');
    expect(inst.models).toEqual([{ id: 'deepseek-ai/DeepSeek-V3', provider: 'nearai' }]);
    expect(inst.gateway).toEqual({ host: undefined, port: 3000 });
    expect(inst.skillsDirs).toEqual([`${LEGACY}/skills`]);
  });

  it('reports leftover 0.x state next to a 1.x install as legacy-unused, without the 1.x version', async () => {
    const layout = rebornLayout({ files: { [`${LEGACY}/.env`]: 'SECRETS_MASTER_KEY=00112233445566778899aabbccddeeff\nHTTP_HOST=0.0.0.0\n' } });
    const insts = await ironclawAdapter.detect({ fs: makeFs(layout) });
    expect(insts.map(i => [i.installDir, i.profile, i.version])).toEqual([
      [REBORN, undefined, '1.4.0'],
      [LEGACY, 'legacy-unused', undefined],
    ]);
    // The 1.x binary never reads that .env: its HTTP_HOST binds nothing (NET-001/CFG-004)
    expect(insts[1].gateway).toBeUndefined();
  });

  it('honours IRONCLAW_BASE_DIR', async () => {
    const fs = makeFs({ dirs: ['/opt/ic'], files: { '/opt/ic/.env': 'HTTP_HOST=0.0.0.0\n' }, env: { IRONCLAW_BASE_DIR: '/opt/ic' } });
    const [inst] = await ironclawAdapter.detect({ fs });
    expect(inst.installDir).toBe('/opt/ic');
    expect(inst.profile).toBe('legacy');
  });
});

describe('IronClaw adapter — static surface', () => {
  it('declares the bearer token, master-key dotfiles and legacy .env as credentials', () => {
    const paths = ironclawAdapter.getCredentialPaths!(REBORN);
    expect(paths).toContain(`${REBORN}/webui-token`);
    expect(paths).toContain(`${REBORN}/local-dev/.reborn-local-dev-secrets-master-key`);
    expect(paths).toContain(`${REBORN}/.env`);
    // config.toml / providers.json never hold secrets (rejected at parse)
    expect(paths.some(p => p.endsWith('config.toml') || p.endsWith('providers.json'))).toBe(false);
  });

  it('keeps the token, master key and databases metadata-only in the probe manifest', () => {
    const m = ironclawAdapter.getProbeManifest!();
    const content = [...m.filePaths, ...m.globPatterns];
    for (const p of ['~/.ironclaw/reborn/webui-token', '~/.ironclaw/reborn/local-dev/.reborn-local-dev-secrets-master-key',
      '~/.ironclaw/reborn/local-dev/reborn-local-dev.db*', '~/.ironclaw/ironclaw.db*']) {
      expect(m.metadataGlobPatterns).toContain(p);
      expect(content).not.toContain(p);
    }
    // no broad glob over the Reborn home that would sweep secrets in
    expect(content.some(g => /reborn\/\*\*$|reborn\/\*$|\.ironclaw\/\*\*$/.test(g))).toBe(false);
    expect(m.filePaths).toContain('~/.ironclaw/reborn/config.toml');
    expect(m.filePaths).toContain('~/.ironclaw/.env');
    // only selector env vars — never IRONCLAW_REBORN_WEBUI_TOKEN & co.
    for (const p of m.envPrefixes) expect(['IRONCLAW_REBORN_HOME', 'IRONCLAW_REBORN_PROFILE', 'IRONCLAW_BASE_DIR', 'LLM_BACKEND']).toContain(p);
  });

  it('zone graph references only registered IC checks and covers every one', () => {
    const graph = ironclawAdapter.getZoneGraph!();
    const ids = new Set(ironclawChecks.map(c => c.id));
    const referenced = new Set<string>();
    for (const c of graph.components) for (const id of c.guardCheckIds ?? []) referenced.add(id);
    for (const e of graph.edges) for (const id of e.triggerCheckIds ?? []) referenced.add(id);
    for (const id of referenced) expect(ids.has(id), id).toBe(true);
    for (const id of ids) expect(referenced.has(id), id).toBe(true);
  });

  it('returns CLI command and skills dirs per layout', () => {
    expect(ironclawAdapter.getCLICommand!()).toBe('ironclaw');
    expect(ironclawAdapter.getSkillsDir(LEGACY)).toBe(`${LEGACY}/skills`);
    expect(ironclawAdapter.getSkillsDir(REBORN)).toBe(`${REBORN}/local-dev/skills`);
  });
});
