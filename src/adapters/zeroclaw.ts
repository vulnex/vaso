import { basename, dirname, isAbsolute, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, UnscannedSkillsDir } from '../core/types.js';
import { skillRootGap, unscannedDir } from '../core/skill-root-scope.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';
import { applyEnvOverrides, type EnvOverrideSpec, type EnvValueType } from './env-overrides.js';
import { envPath } from './env-path.js';
import { compareVersions } from '../core/semver.js';
import { dirExistsOrUncollected } from '../core/probe-coverage.js';

/**
 * ZeroClaw (zeroclaw-labs/zeroclaw, Rust) — V3 config schema (zeroclaw ≥ 0.8).
 *
 * Layout under the config dir (`~/.zeroclaw` by default):
 *   config.toml           V3 config (`schema_version = 3`); V1/V2 files are
 *                         migrated on load, leaving `config.toml.backup`
 *   .secret_key           ChaCha20-Poly1305 master key for `enc2:` secrets
 *   auth-profiles.json    provider OAuth / subscription tokens
 *   agents/<alias>/workspace/   per-agent MEMORY.md, IDENTITY.md, SOUL.md, skills/
 *   shared/skills/<bundle>/     skill bundles
 *   data/                 SQLite memory, sessions, cost, cron, tls, daemon.sock, traces
 */

/** Files loaded as configs (secret stores included, so CFG-002/003 see them). */
const CONFIG_FILENAMES = ['config.toml', 'auth-profiles.json'];

/** `install.sh` / `cargo install` drop the binary in `$CARGO_HOME/bin`. */
const USER_CLI_RELATIVE_PATHS = ['.cargo/bin/zeroclaw'];
const SYSTEM_CLI_PATHS = ['/usr/local/bin/zeroclaw', '/opt/homebrew/bin/zeroclaw', '/usr/bin/zeroclaw'];

/** Homebrew installs keep config under `<prefix>/var/zeroclaw`. */
const HOMEBREW_CONFIG_DIRS = ['/opt/homebrew/var/zeroclaw', '/usr/local/var/zeroclaw'];

/** config.toml locations for configRoots (relocated twins come from the manifest builder). */
const ZEROCLAW_CONFIGS = ['~/.zeroclaw/config.toml', ...HOMEBREW_CONFIG_DIRS.map(d => `${d}/config.toml`)];

function expandTilde(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return join(home, p.slice(2));
  return p;
}

/**
 * Upstream `resolve_runtime_config_dirs`: ZEROCLAW_CONFIG_DIR >
 * ZEROCLAW_DATA_DIR > ZEROCLAW_WORKSPACE (deprecated) > ~/.zeroclaw (>
 * Homebrew var dir on macOS). Env vars come from the scanned host (`fs.getEnv`).
 */
export async function zeroclawDirs(home: string, fs: FSProvider): Promise<{ configDir: string; dataDir: string }> {
  // Env vars and the Homebrew var dir describe the scanning user's install;
  // other users (--all-users) only have their own ~/.zeroclaw.
  const ownHome = home === fs.homedir();
  const env = (name: string) => (ownHome ? fs.getEnv(name)?.trim() : undefined);
  const configEnv = env('ZEROCLAW_CONFIG_DIR');
  if (configEnv) {
    // absolute, so scan and fix agree on the file (`ZEROCLAW_CONFIG_DIR=.zeroclaw`)
    const configDir = envPath(configEnv, home) ?? configEnv;
    return { configDir, dataDir: join(configDir, 'data') };
  }
  const dataEnv = env('ZEROCLAW_DATA_DIR') || env('ZEROCLAW_WORKSPACE');
  if (dataEnv) {
    // resolve_config_dir_for_data
    const data = envPath(dataEnv, home) ?? dataEnv; // `ZEROCLAW_DATA_DIR=0` too
    if (await fs.access(join(data, 'config.toml'))) return { configDir: data, dataDir: join(data, 'data') };
    const legacy = join(dirname(data), '.zeroclaw');
    if (await fs.access(join(legacy, 'config.toml'))) return { configDir: legacy, dataDir: data };
    if (['data', 'workspace'].includes(basename(data))) return { configDir: legacy, dataDir: data };
    return { configDir: data, dataDir: join(data, 'data') };
  }
  const defaultDir = join(home, '.zeroclaw');
  if (ownHome && fs.platform === 'darwin' && !(await fs.access(join(defaultDir, 'config.toml')))) {
    for (const brew of HOMEBREW_CONFIG_DIRS) {
      if (await fs.access(join(brew, 'config.toml'))) return { configDir: brew, dataDir: join(brew, 'workspace') };
    }
  }
  return { configDir: defaultDir, dataDir: join(defaultDir, 'data') };
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

const ENV_SCALARS: Array<[path: string, type: EnvValueType]> = [
  ['gateway.host', 'string'],
  ['gateway.port', 'int'],
  ['gateway.require_pairing', 'bool'],
  ['gateway.allow_public_bind', 'bool'],
  ['gateway.webhook_secret', 'string'],
  ['gateway.tls.enabled', 'bool'],
  ['tunnel.tunnel_provider', 'string'],
  ['secrets.encrypt', 'bool'],
  ['skills.open_skills_enabled', 'bool'],
  ['skills.allow_scripts', 'bool'],
  ['skills.registry_url', 'string'],
  ['browser.enabled', 'bool'],
  ['composio.enabled', 'bool'],
  ['http_request.allow_private_hosts', 'bool'],
];
const ENV_PROFILE_FIELDS: Array<[field: string, type: EnvValueType]> = [
  ['level', 'string'],
  ['workspace_only', 'bool'],
  ['sandbox_enabled', 'bool'],
  ['sandbox_backend', 'string'],
  ['block_high_risk_commands', 'bool'],
];
const ENV_AGENT_FIELDS: Array<[field: string, type: EnvValueType]> = [
  ['enabled', 'bool'],
  ['risk_profile', 'string'],
  ['workspace.unrestricted_filesystem', 'bool'],
];

/** The release that made `ZEROCLAW_<path>` the only env override form. */
const ZEROCLAW_PATH_ENV_ONLY = '0.8.0';

/**
 * Upstream env_overrides: `ZEROCLAW_<path>` overrides config.toml, with `__`
 * separating path segments (`ZEROCLAW_gateway__require_pairing=false`,
 * `ZEROCLAW_risk_profiles__default__level=full`). Variables can't be
 * enumerated through FSProvider, so the security-relevant scalar paths the
 * ZC checks read are probed by name — for every profile and agent alias the
 * file declares (plus `default`). The older flat gateway variables
 * (`ZEROCLAW_GATEWAY_HOST`, …) are read only for releases before 0.8.0,
 * which made the path form the single override surface (0.8.5 ignores the
 * flat names); they come first so the path form wins.
 */
export function zeroclawEnvSpecs(data: Record<string, unknown>, version?: string): EnvOverrideSpec[] {
  const spec = (path: string, type: EnvValueType): EnvOverrideSpec => {
    const segments = path.split('.');
    return { env: `ZEROCLAW_${segments.join('__')}`, path: segments, type };
  };
  const legacy = !!version && /^\d+\.\d+\.\d+/.test(version) && compareVersions(version, ZEROCLAW_PATH_ENV_ONLY) < 0;
  const out: EnvOverrideSpec[] = [
    ...(legacy ? [
      { env: 'ZEROCLAW_GATEWAY_HOST', path: ['gateway', 'host'], type: 'string' as const },
      { env: 'ZEROCLAW_GATEWAY_PORT', path: ['gateway', 'port'], type: 'int' as const },
      { env: 'ZEROCLAW_ALLOW_PUBLIC_BIND', path: ['gateway', 'allow_public_bind'], type: 'bool' as const },
    ] : []),
    ...ENV_SCALARS.map(([p, t]) => spec(p, t)),
  ];
  const profiles = new Set(['default', ...Object.keys(asRecord(data.risk_profiles) ?? {})]);
  for (const name of profiles) {
    for (const [f, t] of ENV_PROFILE_FIELDS) out.push(spec(`risk_profiles.${name}.${f}`, t));
  }
  for (const alias of Object.keys(asRecord(data.agents) ?? {})) {
    for (const [f, t] of ENV_AGENT_FIELDS) out.push(spec(`agents.${alias}.${f}`, t));
  }
  return out;
}

async function listDirs(dir: string, fs: FSProvider): Promise<string[]> {
  try {
    const entries = await fs.readdirEntries(dir);
    return entries.filter(e => e.isDirectory).map(e => e.name);
  } catch {
    return [];
  }
}

/**
 * Skill roots: each agent's `<workspace>/skills` (agents from config.toml and
 * the `agents/` dir; `[agents.<a>.workspace] path` overrides the location),
 * `shared/skills` (bundles, or `[skill_bundles.<b>] directory`), and the
 * open-skills checkout when `[skills] open_skills_enabled`.
 */
async function skillRoots(configDir: string, data: Record<string, unknown>, home: string, fs: FSProvider): Promise<{ roots: string[]; unscanned: UnscannedSkillsDir[] }> {
  const candidates: string[] = [];
  // Roots config.toml sets itself: walked where a skills tree may be (skill-root-scope)
  const configSet = new Set<string>();
  const agents = asRecord(data.agents) ?? {};
  const aliases = new Set([...Object.keys(agents), ...(await listDirs(join(configDir, 'agents'), fs))]);
  for (const alias of aliases) {
    const ws = asRecord(asRecord(agents[alias])?.workspace);
    const custom = typeof ws?.path === 'string' && ws.path.trim() ? expandTilde(ws.path.trim(), home) : undefined;
    candidates.push(join(custom ?? join(configDir, 'agents', alias, 'workspace'), 'skills'));
    if (custom) configSet.add(candidates[candidates.length - 1]);
  }
  candidates.push(join(configDir, 'shared', 'skills'));
  for (const raw of Object.values(asRecord(data.skill_bundles) ?? {})) {
    const dir = asRecord(raw)?.directory;
    if (typeof dir === 'string' && dir.trim()) {
      const d = expandTilde(dir.trim(), home);
      candidates.push(isAbsolute(d) ? d : join(configDir, d));
      configSet.add(candidates[candidates.length - 1]);
    }
  }
  const skills = asRecord(data.skills);
  if (skills?.open_skills_enabled === true) {
    const dir = typeof skills.open_skills_dir === 'string' && skills.open_skills_dir.trim()
      ? expandTilde(skills.open_skills_dir.trim(), home)
      : join(home, 'open-skills');
    candidates.push(dir);
    configSet.add(dir);
  }
  const out: string[] = [];
  const unscanned: UnscannedSkillsDir[] = [];
  for (const c of candidates) {
    if (out.includes(c) || unscanned.some(u => u.path === c)) continue;
    if (configSet.has(c)) {
      const reason = await skillRootGap(fs, c, home);
      if (reason) {
        unscanned.push(await unscannedDir(fs, c, reason, home));
        continue;
      }
    }
    // A snapshot lacks a workspace the config moved outside the probe's trees: kept, reported unverified
    if (await dirExistsOrUncollected(fs, c)) out.push(c);
  }
  return { roots: out, unscanned };
}

export const zeroclawAdapter: AgentAdapter = {
  agent: 'zeroclaw',
  displayName: 'ZeroClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    const seen = new Set<string>();
    for (const { home, user } of userDirs) {
      const { configDir } = await zeroclawDirs(home, fs);
      if (seen.has(configDir)) continue;
      seen.add(configDir);
      const configFiles: ParsedConfig[] = [];
      for (const name of CONFIG_FILENAMES) {
        const filePath = join(configDir, name);
        try {
          { const loaded = await loadConfigIfPresent(filePath, fs); if (loaded) configFiles.push(loaded); }
        } catch {}
      }

      const installs = await discoverCliInstalls(home, fs, {
        names: ['zeroclaw'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        // `zeroclaw --version` → "zeroclaw 0.8.5" (optionally followed by a build id).
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined),
      });
      const cliBinary = installs.primary?.path;
      if (configFiles.length === 0 && !cliBinary) continue;

      const main = configFiles.find(c => c.filePath.endsWith('config.toml'));
      // The env describes the scanning user's daemon only (see zeroclawDirs).
      if (main && home === fs.homedir()) main.data = applyEnvOverrides(main.data, zeroclawEnvSpecs(main.data, installs.primary?.version), fs);
      const data = main?.data ?? {};
      const { roots: skillsDirs, unscanned } = await skillRoots(configDir, data, home, fs);

      installations.push({
        agent: 'zeroclaw',
        installDir: configDir,
        configFiles,
        skillsDir: skillsDirs[0] ?? this.getSkillsDir(configDir),
        skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
        ...(unscanned.length > 0 ? { unscannedSkillsDirs: unscanned } : {}),
        gateway: main ? this.getGatewayInfo(data) : undefined,
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
        version: installs.primary?.version,
      });
    }
    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return CONFIG_FILENAMES.map(f => join(home, '.zeroclaw', f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'shared', 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // The daemon always serves the gateway; [gateway] only overrides defaults
    // (host 127.0.0.1, port 42617, pairing required, no TLS).
    const gw = asRecord(config.gateway) ?? {};
    const host = typeof gw.host === 'string' && gw.host.trim() ? gw.host.trim() : '127.0.0.1';
    const port = typeof gw.port === 'number' ? gw.port : 42617;
    return {
      host,
      port,
      authMode: gw.require_pairing === false ? 'none' : 'pairing',
      tls: asRecord(gw.tls)?.enabled === true,
    };
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (rawId: unknown, provider?: string, via?: string): void => {
      if (typeof rawId !== 'string' || !rawId.trim()) return;
      const id = rawId.trim();
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    const data = configs.find(c => c.filePath.endsWith('config.toml'))?.data;
    if (!data) return out;

    // [providers.models.<type>.<alias>] model / fallback_models / fallback refs.
    const models = asRecord(asRecord(data.providers)?.models) ?? {};
    const resolve = (ref: unknown): { type: string; entry: Record<string, unknown> } | undefined => {
      if (typeof ref !== 'string' || !ref.includes('.')) return undefined;
      const [type, alias] = ref.trim().split('.', 2);
      const entry = asRecord(asRecord(models[type])?.[alias]);
      return entry ? { type, entry } : undefined;
    };
    const pushProvider = (ref: string, via?: string): void => {
      const r = resolve(ref);
      if (!r) return;
      push(r.entry.model, r.type, via);
      if (Array.isArray(r.entry.fallback_models)) {
        for (const m of r.entry.fallback_models) push(m, r.type, `fallback:${ref}`);
      }
      if (Array.isArray(r.entry.fallback)) {
        for (const f of r.entry.fallback) {
          const fr = resolve(f);
          if (fr) push(fr.entry.model, fr.type, `fallback:${ref}`);
        }
      }
    };

    // Each enabled agent's model_provider; with several agents, tag by alias.
    const agents = Object.entries(asRecord(data.agents) ?? {})
      .map(([alias, a]) => [alias, asRecord(a)] as const)
      .filter(([, a]) => a && a.enabled !== false);
    for (const [alias, a] of agents) {
      if (typeof a!.model_provider === 'string') {
        pushProvider(a!.model_provider, agents.length > 1 ? `agent:${alias}` : undefined);
      }
    }
    if (agents.length === 0) {
      for (const [type, aliases] of Object.entries(models)) {
        for (const alias of Object.keys(asRecord(aliases) ?? {})) pushProvider(`${type}.${alias}`);
      }
    }

    // model_routes = [{ hint, model_provider, model }]
    if (Array.isArray(data.model_routes)) {
      for (const r of data.model_routes) {
        const route = asRecord(r);
        if (!route) continue;
        const type = typeof route.model_provider === 'string' ? route.model_provider.split('.')[0] : undefined;
        push(route.model, type, typeof route.hint === 'string' ? route.hint : undefined);
      }
    }

    // Pre-V3 (never-migrated) configs: top-level default_provider/default_model.
    if (out.length === 0 && typeof data.default_model === 'string') {
      const p = typeof data.default_provider === 'string' ? data.default_provider.split(':')[0] : undefined;
      push(data.default_model, p);
    }
    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'data', 'memory', 'brain.db'),
      join(installDir, 'data', 'sessions', 'sessions.db'),
      join(installDir, 'data', 'sessions', 'acp-sessions.db'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, 'config.toml'),
      join(installDir, 'auth-profiles.json'),
      join(installDir, '.secret_key'),
      join(installDir, 'config.toml.backup'),
    ];
  },

  getCLICommand(): string {
    return 'zeroclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.zeroclaw/config.toml',
        '~/.zeroclaw/auth-profiles.json',
        // Pre-migration V1/V2 config: may still hold plaintext/legacy secrets (ZC-001/002).
        '~/.zeroclaw/config.toml.backup',
      ],
      globPatterns: [
        '~/.zeroclaw/agents/*/workspace/skills/**',
        '~/.zeroclaw/shared/skills/**',
        // open-skills checkout at its default location (`[skills] open_skills_enabled`)
        '~/open-skills/**',
        // Homebrew service installs keep agents and bundles under var/
        ...HOMEBREW_CONFIG_DIRS.flatMap(d => [`${d}/agents/*/workspace/skills/**`, `${d}/shared/skills/**`]),
      ],
      // Key material, memory, sessions, traces and per-agent memory/identity
      // markdown — permissions only, content never shipped.
      metadataGlobPatterns: [
        '~/.zeroclaw/.secret_key',
        '~/.zeroclaw/data/*',
        '~/.zeroclaw/data/*/*',
        '~/.zeroclaw/state/*',
        // Nested state stores (e.g. a WhatsApp Web session dir, ZC-009)
        '~/.zeroclaw/state/*/*',
        '~/.zeroclaw/agents/*/workspace/*.md',
        // Homebrew service installs (macOS) keep the config under var/
        ...HOMEBREW_CONFIG_DIRS.map(d => `${d}/.secret_key`),
      ],
      commands: [
        { id: 'zeroclaw-which', cmd: 'which', args: ['zeroclaw'], timeout: 3000 },
        { id: 'zeroclaw-version', cmd: 'zeroclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.zeroclaw',
        '~/.zeroclaw/agents',
        '~/.zeroclaw/shared',
        '~/.zeroclaw/shared/skills',
        '~/.zeroclaw/data',
        '~/.cargo/bin',
      ],
      envPrefixes: ['ZEROCLAW_'],
      systemPaths: [
        ...SYSTEM_CLI_PATHS,
        ...HOMEBREW_CONFIG_DIRS.flatMap(d => CONFIG_FILENAMES.map(f => `${d}/${f}`)),
      ],
      systemDirListings: [...HOMEBREW_CONFIG_DIRS],
      // Skill roots config.toml sets (skillRoots): per-agent workspaces,
      // skill bundles, the open-skills checkout
      configRoots: [
        {
          configs: ZEROCLAW_CONFIGS,
          format: 'toml',
          kind: 'tree',
          keys: [['agents', '*', 'workspace', 'path']],
          globs: ['skills/**'],
        },
        {
          configs: ZEROCLAW_CONFIGS,
          format: 'toml',
          kind: 'tree',
          keys: [['skill_bundles', '*', 'directory']],
          globs: ['**'],
          relative: 'config',
        },
        {
          configs: ZEROCLAW_CONFIGS,
          format: 'toml',
          kind: 'tree',
          keys: [['skills', 'open_skills_dir']],
          when: ['skills', 'open_skills_enabled'],
          globs: ['**'],
        },
      ],
    };
  },
};
