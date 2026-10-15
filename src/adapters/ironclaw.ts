import { basename, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent, pathPresent } from './load-if-present.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';
import { envPath, xdgPath } from './env-path.js';

/*
 * IronClaw ships two incompatible generations:
 *
 * - 1.x "Reborn" (1.0.0, 2026-07-27 onward — the current line). State root is
 *   `$IRONCLAW_REBORN_HOME`, default `~/.ironclaw/reborn`
 *   (crates/app/ironclaw_config/src/home.rs). It holds `config.toml`
 *   (`deny_unknown_fields` — secrets are env-only and rejected at parse),
 *   `providers.json` (LLM provider catalog overlay, no secret fields),
 *   `webui-token` (WebChat v2 bearer token, also the session-signing HMAC key)
 *   and one storage subdir per boot profile (`local-dev`, `hosted-single-tenant`,
 *   …) with the libSQL database, the fallback secrets master-key dotfile and
 *   the skill roots.
 * - 0.x legacy (last: 0.29.1). State root `$IRONCLAW_BASE_DIR`, default
 *   `~/.ironclaw`: `.env` (bootstrap env), optional `config.toml` settings
 *   overlay, `ironclaw.db`, `skills/`, `installed_skills/`, `channels/`.
 *   `settings.json` / `mcp-servers.json` are pre-DB leftovers (migrated into
 *   the database on first run). 1.x never reads any of it.
 */

export const IRONCLAW_REBORN_HOME_ENV = 'IRONCLAW_REBORN_HOME';
export const IRONCLAW_REBORN_PROFILE_ENV = 'IRONCLAW_REBORN_PROFILE';
export const IRONCLAW_LEGACY_BASE_ENV = 'IRONCLAW_BASE_DIR';

/** `installation.profile` of a 0.x install whose binary is still 0.x (or unknown). */
export const IRONCLAW_LEGACY_PROFILE = 'legacy';
/** `installation.profile` of 0.x state left behind after upgrading to 1.x —
 *  the binary no longer reads it; only secrets at rest still matter. */
export const IRONCLAW_LEGACY_UNUSED_PROFILE = 'legacy-unused';

/** Per-profile storage subdirs (`RebornProfile::local_runtime_storage_subdir`). */
export const REBORN_STORAGE_SUBDIRS = [
  'local-dev',
  'hosted-single-tenant',
  'hosted-single-tenant-volume',
  'hosted-single-tenant-volume-sandboxed',
] as const;

/** Written only when no OS keychain and no SECRETS_MASTER_KEY are available. */
export const REBORN_MASTER_KEY_FILE = '.reborn-local-dev-secrets-master-key';
export const REBORN_DB_FILE = 'reborn-local-dev.db';
export const REBORN_WEBUI_TOKEN_FILE = 'webui-token';

const REBORN_CONFIG_FILES = ['config.toml', 'providers.json'];
const LEGACY_CONFIG_FILES = ['.env', 'config.toml', 'settings.json', 'mcp-servers.json'];

/** `ironclaw service install` unit locations (crates/app/ironclaw_cli/src/commands/service). */
export const REBORN_SYSTEMD_UNIT = 'ironclaw-reborn.service';
export const REBORN_LAUNCHD_PLIST = 'com.ironclaw.reborn.plist';

export function isIronclawLegacy(inst: Pick<AgentInstallation, 'profile'>): boolean {
  return inst.profile === IRONCLAW_LEGACY_PROFILE || inst.profile === IRONCLAW_LEGACY_UNUSED_PROFILE;
}

function envOverride(fs: FSProvider, home: string, key: string): string | undefined {
  // Relocation env vars describe the scanning user's session only.
  if (home !== fs.homedir()) return undefined;
  return envPath(fs.getEnv(key), home);
}

/** 1.x state root: `$IRONCLAW_REBORN_HOME`, else `<home>/.ironclaw/reborn`. */
export function ironclawRebornHome(home: string, fs: FSProvider): string {
  return envOverride(fs, home, IRONCLAW_REBORN_HOME_ENV) ?? join(home, '.ironclaw', 'reborn');
}

/** 0.x state root: `$IRONCLAW_BASE_DIR`, else `<home>/.ironclaw`. */
export function ironclawLegacyDir(home: string, fs: FSProvider): string {
  return envOverride(fs, home, IRONCLAW_LEGACY_BASE_ENV) ?? join(home, '.ironclaw');
}

/** Service unit files that may carry `IRONCLAW_REBORN_PROFILE` / `serve` flags. */
export function ironclawServiceUnitPaths(home: string, fs: FSProvider): string[] {
  const xdg = home === fs.homedir() ? xdgPath(fs.getEnv('XDG_CONFIG_HOME')) : undefined;
  const paths = [join(xdg || join(home, '.config'), 'systemd', 'user', REBORN_SYSTEMD_UNIT)];
  if (xdg) paths.push(join(home, '.config', 'systemd', 'user', REBORN_SYSTEMD_UNIT));
  paths.push(join(home, 'Library', 'LaunchAgents', REBORN_LAUNCHD_PLIST));
  return paths;
}

function table(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** True for a parsed 1.x `config.toml` (top-level sections the 0.x settings
 *  overlay never has). */
export function isRebornConfigData(data: unknown): boolean {
  const t = table(data);
  if (!t) return false;
  if (typeof t.api_version === 'string') return true;
  return ['boot', 'webui', 'identity', 'runner', 'policy', 'storage'].some(k => table(t[k]) !== undefined)
    || table(t.llm) !== undefined;
}

async function loadExisting(dir: string, names: string[], fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const filePath = join(dir, name);
    try {
      { const loaded = await loadConfigIfPresent(filePath, fs); if (loaded) out.push(loaded); }
    } catch {
      // Unreadable/unparseable files surface as CONFIG-LOAD via captureConfigLoadErrors.
    }
  }
  return out;
}

async function listDirs(fs: FSProvider, dir: string): Promise<string[]> {
  try {
    const entries = await fs.readdirEntries(dir);
    return entries.filter(e => e.isDirectory).map(e => e.name);
  } catch {
    return [];
  }
}

/** Every skill root the Reborn runtime mounts, per storage subdir
 *  (host_access_assembly.rs / runtime_mounts.rs / standalone_bootstrap_assembly.rs). */
async function rebornSkillDirs(rebornHome: string, fs: FSProvider): Promise<string[]> {
  const dirs: string[] = [];
  for (const sub of REBORN_STORAGE_SUBDIRS) {
    const storage = join(rebornHome, sub);
    if (!(await fs.access(storage))) continue;
    const candidates = [
      join(storage, 'skills'),
      join(storage, 'tenant-shared', 'skills'),
      join(storage, 'system', 'skills'),
    ];
    for (const tenant of await listDirs(fs, join(storage, 'tenants'))) {
      const tenantDir = join(storage, 'tenants', tenant);
      candidates.push(join(tenantDir, 'shared', 'skills'));
      for (const user of await listDirs(fs, join(tenantDir, 'users'))) {
        candidates.push(join(tenantDir, 'users', user, 'skills'));
      }
    }
    for (const c of candidates) {
      if (await fs.access(c)) dirs.push(c);
    }
  }
  return dirs;
}

function rebornGatewayInfo(configData: Record<string, unknown> | undefined): GatewayInfo | undefined {
  const webui = table(configData?.webui);
  // Only report a gateway the operator configured: the stock listener is
  // loopback-only and generic TLS/exposure checks would misread the default.
  if (webui?.listen_host === undefined && webui?.listen_port === undefined) return undefined;
  const host = typeof webui?.listen_host === 'string' ? webui.listen_host : '127.0.0.1';
  const port = typeof webui?.listen_port === 'number' ? webui.listen_port : 3000;
  // WebChat v2 always requires the env-bearer token (>=32 bytes); it serves
  // plain HTTP — TLS is left to a reverse proxy.
  return { host, port, authMode: 'bearer', tls: false };
}

function legacyGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
  const envHost = typeof config.GATEWAY_HOST === 'string' ? config.GATEWAY_HOST : undefined;
  const envPort = config.GATEWAY_PORT;
  if (envHost || envPort !== undefined) {
    const port = typeof envPort === 'number' ? envPort : parseInt(String(envPort ?? ''), 10);
    return { host: envHost, port: Number.isFinite(port) ? port : undefined };
  }
  const channels = table(config.channels);
  if (channels && (channels.gateway_host !== undefined || channels.gateway_port !== undefined)) {
    return {
      host: typeof channels.gateway_host === 'string' ? channels.gateway_host : undefined,
      port: typeof channels.gateway_port === 'number' ? channels.gateway_port : undefined,
    };
  }
  return undefined;
}

// 0.x: `LLM_BACKEND` selects a backend and that backend reads its own
// `<NAME>_MODEL` env var. 1.x falls back to the same env vars when no
// `[llm.default]` slot is configured.
const BACKEND_ENV: Record<string, { model: string }> = {
  nearai: { model: 'NEARAI_MODEL' },
  ollama: { model: 'OLLAMA_MODEL' },
  openai_compatible: { model: 'LLM_MODEL' },
  openai: { model: 'OPENAI_MODEL' },
  anthropic: { model: 'ANTHROPIC_MODEL' },
  github_copilot: { model: 'GITHUB_COPILOT_MODEL' },
  tinfoil: { model: 'TINFOIL_MODEL' },
  openai_codex: { model: 'OPENAI_CODEX_MODEL' },
  gemini_oauth: { model: 'GEMINI_MODEL' },
  minimax: { model: 'MINIMAX_MODEL' },
};

function envModels(configs: ParsedConfig[], fs: FSProvider | undefined, push: (id: string | undefined, provider: string, via?: string) => void): void {
  const lookup = (key: string): string | undefined => {
    // Prefer the .env file over process env so a local override wins.
    const env = configs.find(c => c.filePath.endsWith('.env'));
    const fromFile = env?.data?.[key];
    if (typeof fromFile === 'string' && fromFile.trim()) return fromFile.trim();
    const fromProc = fs?.getEnv?.(key);
    if (typeof fromProc === 'string' && fromProc.trim()) return fromProc.trim();
    return undefined;
  };

  const selected = lookup('LLM_BACKEND');
  if (selected && BACKEND_ENV[selected]) {
    push(lookup(BACKEND_ENV[selected].model), selected);
  } else {
    for (const [backend, keys] of Object.entries(BACKEND_ENV)) {
      push(lookup(keys.model), backend, selected ? undefined : 'env-detected');
    }
  }
}

export const ironclawAdapter: AgentAdapter = {
  agent: 'ironclaw',
  displayName: 'IronClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const rebornHome = ironclawRebornHome(home, fs);
      const legacyDir = ironclawLegacyDir(home, fs);

      const installs = await discoverCliInstalls(home, fs, {
        names: ['ironclaw'],
        // cargo-dist installer (`ironclaw-installer.sh`) and `cargo install`
        userRelPaths: ['.cargo/bin/ironclaw', '.local/bin/ironclaw'],
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined),
      });
      const cliBinary = installs.primary?.path;
      const binVersion = installs.primary?.version;
      const binMajor = binVersion ? parseInt(binVersion.split('.')[0], 10) : undefined;
      const binIsLegacy = binMajor !== undefined && binMajor < 1;
      const binIsReborn = binMajor !== undefined && binMajor >= 1;
      const others = installs.others.length > 0 ? installs.others : undefined;

      // ── 1.x Reborn ─────────────────────────────────────────────────────
      const rebornConfigs = await loadExisting(rebornHome, REBORN_CONFIG_FILES, fs);
      let rebornPresent = rebornConfigs.length > 0
        || await pathPresent(join(rebornHome, REBORN_WEBUI_TOKEN_FILE), fs)
        || await pathPresent(join(rebornHome, '.onboard-completed.json'), fs);
      if (!rebornPresent) {
        for (const sub of REBORN_STORAGE_SUBDIRS) {
          if (await pathPresent(join(rebornHome, sub), fs)) { rebornPresent = true; break; }
        }
      }

      // ── 0.x legacy ─────────────────────────────────────────────────────
      const legacyConfigs = await loadExisting(legacyDir, LEGACY_CONFIG_FILES, fs);
      const legacyPresent = legacyConfigs.length > 0 || await fs.access(join(legacyDir, 'ironclaw.db'));

      // A binary with no state yet: attribute it to the generation it belongs to.
      if (!rebornPresent && !legacyPresent) {
        if (!cliBinary) continue;
        if (binIsLegacy) {
          installations.push(await legacyInstallation(legacyDir, [], fs, {
            user: options?.allUsers ? user : undefined, cliBinary, version: binVersion, others, unused: false,
          }));
        } else {
          installations.push(await rebornInstallation(rebornHome, [], fs, {
            user: options?.allUsers ? user : undefined, cliBinary, version: binVersion, others,
          }));
        }
        continue;
      }

      if (rebornPresent) {
        installations.push(await rebornInstallation(rebornHome, rebornConfigs, fs, {
          user: options?.allUsers ? user : undefined,
          cliBinary,
          version: binIsLegacy ? undefined : binVersion,
          others: binIsLegacy ? undefined : others,
        }));
      }
      if (legacyPresent) {
        installations.push(await legacyInstallation(legacyDir, legacyConfigs, fs, {
          user: options?.allUsers ? user : undefined,
          cliBinary,
          version: binIsLegacy ? binVersion : undefined,
          others: binIsLegacy || !rebornPresent ? others : undefined,
          // A 1.x binary never reads the 0.x root (config path reports v1_state).
          unused: binIsReborn,
        }));
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    const reborn = ironclawRebornHome(home, fs);
    const legacy = ironclawLegacyDir(home, fs);
    return [
      ...REBORN_CONFIG_FILES.map(f => join(reborn, f)),
      ...LEGACY_CONFIG_FILES.map(f => join(legacy, f)),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    // 0.x keeps skills directly under the base dir; 1.x under the storage subdir.
    return basename(installDir) === '.ironclaw'
      ? join(installDir, 'skills')
      : join(installDir, 'local-dev', 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    if (isRebornConfigData(config)) return rebornGatewayInfo(config);
    return legacyGatewayInfo(config);
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (id: string | undefined, provider: string, via?: string): void => {
      if (!id) return;
      const key = `${provider}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, provider, ...(via ? { via } : {}) });
    };

    // 1.x: `[llm.<slot>]` selects provider_id + model; a slot without a
    // model uses the provider's catalog `default_model` (providers.json).
    const reborn = configs.find(c => basename(c.filePath) === 'config.toml' && isRebornConfigData(c.data));
    if (reborn) {
      const catalog = configs.find(c => basename(c.filePath) === 'providers.json')?.data as unknown;
      const providers = Array.isArray(catalog)
        ? catalog.filter((p): p is Record<string, unknown> => !!table(p))
        : [];
      const defaultModelFor = (providerId: string): string | undefined => {
        const p = providers.find(e => e.id === providerId
          || (Array.isArray(e.aliases) && e.aliases.includes(providerId)));
        return typeof p?.default_model === 'string' ? p.default_model : undefined;
      };
      const llm = table(reborn.data.llm) ?? {};
      const slots = Object.entries(llm).filter(([, v]) => table(v) !== undefined);
      // default slot first
      slots.sort(([a], [b]) => (a === 'default' ? -1 : b === 'default' ? 1 : 0));
      let anyProvider = false;
      for (const [slot, raw] of slots) {
        const sel = table(raw)!;
        const provider = typeof sel.provider_id === 'string' ? sel.provider_id.trim() : '';
        if (!provider) continue;
        anyProvider = true;
        const model = typeof sel.model === 'string' && sel.model.trim() ? sel.model.trim() : defaultModelFor(provider);
        push(model, provider, slot === 'default' ? undefined : slot);
      }
      // No slot seeded → the runtime falls back to LLM env vars.
      if (!anyProvider) envModels([], fs, push);
      return out;
    }

    envModels(configs, fs, push);
    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      ...REBORN_STORAGE_SUBDIRS.map(sub => join(installDir, sub, REBORN_DB_FILE)),
      join(installDir, 'ironclaw.db'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    // Union of both layouts — permission checks skip paths that don't exist.
    return [
      join(installDir, REBORN_WEBUI_TOKEN_FILE),
      ...REBORN_STORAGE_SUBDIRS.map(sub => join(installDir, sub, REBORN_MASTER_KEY_FILE)),
      join(installDir, '.env'),
    ];
  },

  getCLICommand(): string {
    return 'ironclaw';
  },

  getProbeManifest(): ProbeManifest {
    const storageGlobs = (suffix: string) => REBORN_STORAGE_SUBDIRS.map(sub => `~/.ironclaw/reborn/${sub}/${suffix}`);
    return {
      filePaths: [
        // 1.x
        '~/.ironclaw/reborn/config.toml',
        '~/.ironclaw/reborn/providers.json',
        `~/.config/systemd/user/${REBORN_SYSTEMD_UNIT}`,
        `~/Library/LaunchAgents/${REBORN_LAUNCHD_PLIST}`,
        // 0.x
        '~/.ironclaw/.env',
        '~/.ironclaw/config.toml',
        '~/.ironclaw/settings.json',
        '~/.ironclaw/mcp-servers.json',
      ],
      globPatterns: [
        ...storageGlobs('skills/**'),
        ...storageGlobs('tenant-shared/skills/**'),
        ...storageGlobs('system/skills/**'),
        ...storageGlobs('tenants/*/shared/skills/**'),
        ...storageGlobs('tenants/*/users/*/skills/**'),
        '~/.ironclaw/skills/**',
        '~/.ironclaw/installed_skills/**',
      ],
      // Bearer token, secrets master key and the conversation/memory
      // databases: permissions only, content never shipped.
      metadataGlobPatterns: [
        `~/.ironclaw/reborn/${REBORN_WEBUI_TOKEN_FILE}`,
        '~/.ironclaw/reborn/.onboard-completed.json',
        ...storageGlobs(REBORN_MASTER_KEY_FILE),
        ...storageGlobs(`${REBORN_DB_FILE}*`),
        '~/.ironclaw/ironclaw.db*',
        // By name too: a glob can't list a dir its owner can traverse but not read
        ...['', '-wal', '-shm'].flatMap(s => [...storageGlobs(`${REBORN_DB_FILE}${s}`), `~/.ironclaw/ironclaw.db${s}`]),
        '~/.ironclaw/channels/*',
      ],
      commands: [
        { id: 'ironclaw-which', cmd: 'which', args: ['ironclaw'], timeout: 3000 },
        { id: 'ironclaw-version', cmd: 'ironclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.ironclaw',
        '~/.ironclaw/reborn',
        ...REBORN_STORAGE_SUBDIRS.map(sub => `~/.ironclaw/reborn/${sub}`),
        '~/.ironclaw/reborn/local-dev/tenants',
        '~/.ironclaw/channels',
        '~/.ironclaw/skills',
        '~/.cargo/bin',
      ],
      // Only the relocation/profile selectors — never the IRONCLAW_REBORN_*
      // token / master-key / database-URL variables.
      envPrefixes: [
        IRONCLAW_REBORN_HOME_ENV,
        IRONCLAW_REBORN_PROFILE_ENV,
        IRONCLAW_LEGACY_BASE_ENV,
        'LLM_BACKEND',
      ],
      systemPaths: [],
      systemDirListings: [],
    };
  },

  // 1.x privilege gradient: browser / network → WebChat v2 listener (bearer
  // token, CORS allow-list) → agent runtime (boot profile, approval policy)
  // → host filesystem, secrets store and LLM egress. Legacy 0.x checks guard
  // the same runtime zone (sandbox, auto-approve, local tools).
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Browser / Network / Channels', trustLevel: 0 },
        { id: 'webui', label: 'WebChat v2 Listener', trustLevel: 1 },
        { id: 'runtime', label: 'Agent Runtime + Approvals', trustLevel: 2 },
        { id: 'host', label: 'Host FS + Secrets + LLM Egress', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Channel Ingress', zone: 'net', guardCheckIds: ['IC-010'] },
        {
          id: 'webchat',
          label: 'IronClaw WebChat v2 (HTTP/SSE/WebSocket)',
          zone: 'webui',
          guardCheckIds: ['IC-001', 'IC-004', 'IC-013'],
        },
        {
          id: 'runtime',
          label: 'Boot Profile + Approval Policy + Sandbox',
          zone: 'runtime',
          guardCheckIds: ['IC-003', 'IC-005', 'IC-006', 'IC-007', 'IC-008', 'IC-011', 'IC-012'],
        },
        {
          id: 'host',
          label: 'Host Filesystem, Secrets Store, State DB, LLM Endpoints',
          zone: 'host',
          guardCheckIds: ['IC-002', 'IC-009', 'IC-014'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'webchat', kind: 'data' },
        { from: 'webchat', to: 'runtime', kind: 'control' },
        { from: 'runtime', to: 'host', kind: 'data' },
        {
          from: 'inbound',
          to: 'host',
          label: 'unrestricted host access',
          triggerCheckIds: ['IC-006', 'IC-007'],
        },
      ],
    };
  },
};

interface InstallOpts {
  user?: string;
  cliBinary?: string;
  version?: string;
  others?: AgentInstallation['otherInstalls'];
}

async function rebornInstallation(
  home: string,
  configs: ParsedConfig[],
  fs: FSProvider,
  o: InstallOpts,
): Promise<AgentInstallation> {
  const configToml = configs.find(c => basename(c.filePath) === 'config.toml');
  const skillsDirs = await rebornSkillDirs(home, fs);
  return {
    agent: 'ironclaw',
    version: o.version,
    installDir: home,
    configFiles: configs,
    skillsDir: skillsDirs[0] ?? join(home, 'local-dev', 'skills'),
    skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
    gateway: rebornGatewayInfo(configToml?.data),
    models: await ironclawAdapter.getModels!(configs, fs),
    user: o.user,
    cliBinary: o.cliBinary,
    otherInstalls: o.others,
  };
}

async function legacyInstallation(
  dir: string,
  configs: ParsedConfig[],
  fs: FSProvider,
  o: InstallOpts & { unused: boolean },
): Promise<AgentInstallation> {
  const merged: Record<string, unknown> = {};
  for (const c of configs) {
    if (table(c.data)) Object.assign(merged, c.data);
  }
  const skillsDirs: string[] = [];
  for (const d of [join(dir, 'skills'), join(dir, 'installed_skills')]) {
    if (await fs.access(d)) skillsDirs.push(d);
  }
  return {
    agent: 'ironclaw',
    version: o.version,
    installDir: dir,
    configFiles: configs,
    profile: o.unused ? IRONCLAW_LEGACY_UNUSED_PROFILE : IRONCLAW_LEGACY_PROFILE,
    skillsDir: join(dir, 'skills'),
    skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
    // A 1.x binary never reads the 0.x .env: its HTTP_HOST binds nothing
    gateway: o.unused ? undefined : legacyGatewayInfo(merged),
    models: await ironclawAdapter.getModels!(configs, fs),
    user: o.user,
    cliBinary: o.cliBinary,
    otherInstalls: o.others,
  };
}
