import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig } from '../core/types.js';
import type { CommandForEach, ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { pathPresent } from './load-if-present.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';

/**
 * NVIDIA OpenShell — the sandbox runtime NemoClaw runs on, also used on its
 * own to sandbox coding agents. One installation per user covers the
 * `openshell` CLI and the local gateway it manages. Layout verified live
 * against 0.1.2 (Homebrew on macOS, gateway container on Linux) and 0.0.116
 * (Debian package set up by NemoClaw):
 *
 *   $XDG_CONFIG_HOME/openshell/        CLI: active_gateway, gateways/<name>/{metadata.json, mtls/, oidc_token.json}
 *                                      gateway: gateway.toml, gateway.env (systemd EnvironmentFile / Homebrew wrapper)
 *   $XDG_STATE_HOME/openshell/         gateway/openshell.db (+ -wal/-shm), gateway/credentials/key-encryption-key.bin,
 *                                      tls/ (deb), homebrew/tls/ (Homebrew mirror), docker-sandbox-tokens/
 *   <brew prefix>/var/openshell/       Homebrew gateway.toml + tls/ (incl. the CA private key)
 *   ~/snap/openshell/common/           snap (per user, installation docs): .config/openshell/gateway.toml,
 *                                      .local/state/openshell/{gateway/openshell.db, tls/}
 *   /var/snap/openshell/common/        snap $SNAP_COMMON: optional gateway.toml + tls/
 *
 * gateway.env overrides the TOML (flag > env > TOML > default) and can move
 * the TOML, database and TLS directory elsewhere — NemoClaw points them at
 * ~/.local/state/nemoclaw/openshell-docker-gateway/.
 */

const CLI_SYSTEM_PATHS = ['/usr/bin/openshell', '/usr/local/bin/openshell', '/opt/homebrew/bin/openshell', '/snap/bin/openshell'];
const CLI_USER_PATHS = [join('.local', 'bin', 'openshell'), join('.cargo', 'bin', 'openshell')];
export const BREW_VAR_DIRS = ['/opt/homebrew/var/openshell', '/usr/local/var/openshell'];
export const SNAP_COMMON_DIR = '/var/snap/openshell/common';
/** The snap's per-user data dir ($SNAP_USER_COMMON) — its gateway runs with HOME there. */
export const SNAP_USER_REL = join('snap', 'openshell', 'common');

export function snapUserDir(home: string): string {
  return join(home, SNAP_USER_REL);
}
export const DEFAULT_GATEWAY_PORT = 17670;

export interface OpenShellPaths {
  home: string;
  /** CLI + per-user gateway config ($XDG_CONFIG_HOME/openshell). */
  configDir: string;
  /** Gateway state ($XDG_STATE_HOME/openshell). */
  stateDir: string;
}

/** $XDG_* dirs apply only to the scanning user's own home. */
export function openShellPaths(home: string, fs: FSProvider): OpenShellPaths {
  const own = home === fs.homedir();
  const xdgConfig = own ? fs.getEnv('XDG_CONFIG_HOME')?.trim() : undefined;
  const xdgState = own ? fs.getEnv('XDG_STATE_HOME')?.trim() : undefined;
  return {
    home,
    configDir: join(xdgConfig || join(home, '.config'), 'openshell'),
    stateDir: join(xdgState || join(home, '.local', 'state'), 'openshell'),
  };
}

/** `~/…` in env-file values → the user's home. */
export function expandHome(value: string, home: string): string {
  return value === '~' ? home : value.startsWith('~/') ? join(home, value.slice(2)) : value;
}

async function firstExisting(paths: string[], fs: FSProvider): Promise<string | undefined> {
  // An unreadable file counts: loading it then reports CONFIG-LOAD
  for (const p of paths) {
    if (await pathPresent(p, fs)) return p;
  }
  return undefined;
}

async function tryLoad(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  try {
    return await loadConfig(filePath, fs);
  } catch {
    return undefined;
  }
}

/** The gateway env file and TOML the user's gateway service would load. */
async function gatewayConfigs(paths: OpenShellPaths, fs: FSProvider): Promise<ParsedConfig[]> {
  const brewVar = fs.platform === 'darwin' ? BREW_VAR_DIRS : [];
  const configs: ParsedConfig[] = [];

  // systemd: EnvironmentFile=-%E/openshell/gateway.env; Homebrew wrapper: XDG, else the prefix copy
  const envFile = await firstExisting([join(paths.configDir, 'gateway.env'), ...brewVar.map(d => join(d, 'gateway.env'))], fs);
  const env = envFile ? await tryLoad(envFile, fs) : undefined;
  if (env) configs.push(env);

  const redirected = typeof env?.data.OPENSHELL_GATEWAY_CONFIG === 'string' && env.data.OPENSHELL_GATEWAY_CONFIG.trim()
    ? expandHome(env.data.OPENSHELL_GATEWAY_CONFIG.trim(), paths.home)
    : undefined;
  const toml = redirected && (await fs.access(redirected))
    ? redirected
    : await firstExisting([
      join(paths.configDir, 'gateway.toml'),
      ...brewVar.map(d => join(d, 'gateway.toml')),
      // Installation docs: the snap gateway reads ~/snap/openshell/common/.config/openshell/gateway.toml
      // when it exists, else the optional $SNAP_COMMON/gateway.toml
      join(snapUserDir(paths.home), '.config', 'openshell', 'gateway.toml'),
      ...(paths.home === fs.homedir() ? [join(SNAP_COMMON_DIR, 'gateway.toml')] : []),
    ], fs);
  const parsed = toml ? await tryLoad(toml, fs) : undefined;
  if (parsed) configs.push(parsed);
  return configs;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

/** `[openshell.gateway]` of a gateway TOML (schema v1 and v2 share it). */
export function gatewayTable(config: ParsedConfig): Record<string, unknown> | undefined {
  return asRecord(asRecord(asRecord(config.data)?.openshell)?.gateway);
}

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

function envValue(configs: ParsedConfig[], key: string): string | undefined {
  for (const c of configs) {
    if (c.format !== 'env') continue;
    const v = c.data[key];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return undefined;
}

export function envTruthy(configs: ParsedConfig[], key: string): boolean | undefined {
  const v = envValue(configs, key);
  return v === undefined ? undefined : TRUTHY.has(v.toLowerCase());
}

/** Effective listener + TLS of the gateway: env file over TOML over the built-in 127.0.0.1:17670. */
export function resolveGateway(configs: ParsedConfig[]): GatewayInfo {
  const toml = configs.find(c => c.format === 'toml');
  const gw = toml ? gatewayTable(toml) : undefined;

  let host = '127.0.0.1';
  let port = DEFAULT_GATEWAY_PORT;
  const bind = gw?.bind_address;
  if (typeof bind === 'string' && bind.trim()) {
    const m = /^\[?([^\]]*?)\]?(?::(\d+))?$/.exec(bind.trim());
    if (m) {
      host = m[1] || host;
      if (m[2]) port = Number(m[2]);
    }
  }
  const envHost = envValue(configs, 'OPENSHELL_BIND_ADDRESS');
  const envPort = Number(envValue(configs, 'OPENSHELL_SERVER_PORT'));
  if (envHost) host = envHost;
  if (Number.isInteger(envPort) && envPort > 0) port = envPort;

  const disableTls = envTruthy(configs, 'OPENSHELL_DISABLE_TLS') ?? gw?.disable_tls === true;
  const oidc = asRecord(gw?.oidc);
  const oidcIssuer = envValue(configs, 'OPENSHELL_OIDC_ISSUER') ?? (typeof oidc?.issuer === 'string' ? oidc.issuer : undefined);
  const unauth = asRecord(gw?.auth)?.allow_unauthenticated_users === true;
  return {
    host,
    port,
    tls: !disableTls,
    authMode: unauth ? 'none' : oidcIssuer ? 'oidc' : 'mtls',
  };
}

export const openshellAdapter: AgentAdapter = {
  agent: 'openshell',
  displayName: 'NVIDIA OpenShell',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const paths = openShellPaths(home, fs);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['openshell'],
        systemPaths: CLI_SYSTEM_PATHS,
        userRelPaths: CLI_USER_PATHS,
        nvm: false,
        version: (bin, canExec) => (canExec ? queryCliVersion(bin, fs, { timeoutMs: 5000 }) : undefined),
      });
      const cliBinary = installs.primary?.path;
      const hasConfig = await fs.access(paths.configDir);
      const hasState = await fs.access(paths.stateDir);
      const own = home === fs.homedir();
      const packageGateway = (own
        ? await firstExisting([...(fs.platform === 'darwin' ? BREW_VAR_DIRS : []), SNAP_COMMON_DIR], fs)
        : undefined) ?? await firstExisting([snapUserDir(home)], fs);

      // Positive signal required: CLI/gateway state, a package-managed gateway, or the CLI itself.
      if (!hasConfig && !hasState && !packageGateway && !cliBinary) continue;

      const configFiles = await gatewayConfigs(paths, fs);
      installations.push({
        agent: 'openshell',
        version: installs.primary?.version,
        installDir: hasConfig ? paths.configDir : hasState ? paths.stateDir : (packageGateway ?? paths.configDir),
        configFiles,
        gateway: resolveGateway(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }
    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const paths = openShellPaths(fs.homedir(), fs);
    return [join(paths.configDir, 'gateway.toml'), join(paths.configDir, 'gateway.env')];
  },

  getSkillsDir(): string | undefined {
    // Agents run inside sandboxes; OpenShell itself loads no skills.
    return undefined;
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    return resolveGateway([{ raw: '', format: 'toml', filePath: '', data: config }]);
  },

  getCLICommand(): string {
    return 'openshell';
  },

  getProbeManifest(): ProbeManifest {
    const tlsKeys = (dir: string) => [`${dir}/ca.key`, `${dir}/server/tls.key`, `${dir}/client/tls.key`, `${dir}/jwt/signing.pem`];
    return {
      filePaths: [
        // The default sandbox policy file (OSH-011–014; expanded by the probe)
        '${OPENSHELL_SANDBOX_POLICY}',
        '~/.config/openshell/gateway.toml',
        '~/.config/openshell/gateway.env',
        '~/.config/openshell/active_gateway',
        ...BREW_VAR_DIRS.flatMap(d => [`${d}/gateway.toml`, `${d}/gateway.env`]),
        `${SNAP_COMMON_DIR}/gateway.toml`,
        `~/${SNAP_USER_REL}/.config/openshell/gateway.toml`,
        ...CLI_USER_PATHS.map(p => `~/${p}`),
      ],
      globPatterns: [
        '~/.config/openshell/gateways/*/metadata.json',
        // NemoClaw's gateway: gateway.env points OPENSHELL_GATEWAY_CONFIG here
        '~/.local/state/nemoclaw/openshell-docker-gateway/*.toml',
      ],
      // Keys, the credential database and its key, sandbox tokens: modes only, never content
      metadataGlobPatterns: [
        '~/.config/openshell/gateways/*/mtls/*',
        '~/.config/openshell/gateways/*/oidc_token.json',
        '~/.local/state/openshell/gateway/openshell.db*',
        '~/.local/state/openshell/gateway/credentials/*',
        '~/.local/state/openshell/docker-sandbox-tokens/**',
        ...tlsKeys('~/.local/state/openshell/tls'),
        ...tlsKeys('~/.local/state/openshell/homebrew/tls'),
        ...BREW_VAR_DIRS.flatMap(d => tlsKeys(`${d}/tls`)),
        ...tlsKeys(`${SNAP_COMMON_DIR}/tls`),
        `~/${SNAP_USER_REL}/.local/state/openshell/gateway/openshell.db*`,
        ...tlsKeys(`~/${SNAP_USER_REL}/.local/state/openshell/tls`),
        '~/.local/state/nemoclaw/openshell-docker-gateway/openshell.db*',
        ...tlsKeys('~/.local/state/nemoclaw/openshell-docker-gateway/tls'),
        '~/.local/state/nemoclaw/openshell-docker-gateway/jwt/signing.pem',
      ],
      commands: [
        { id: 'openshell-which', cmd: 'which', args: ['openshell'], timeout: 3000 },
        { id: 'openshell-version', cmd: 'openshell', args: ['--version'], timeout: 5000, isolateHome: true },
        // Read-only gateway queries (verified side-effect free): the sandboxes,
        // each sandbox's effective policy, and the global policy. Policies carry
        // no credential values.
        // They need the user's real HOME (registered gateway + mTLS bundle).
        { id: 'openshell-sandbox-list', cmd: 'openshell', args: [...SANDBOX_LIST_ARGS], timeout: 15000, isolateHome: false },
        {
          id: 'openshell-sandbox-policy',
          cmd: 'openshell',
          args: sandboxPolicyArgs('{name}', '{workspace}'),
          timeout: 15000,
          isolateHome: false,
          forEach: SANDBOX_POLICY_FOR_EACH,
        },
        { id: 'openshell-global-policy', cmd: 'openshell', args: [...GLOBAL_POLICY_ARGS], timeout: 15000, isolateHome: false },
      ],
      directoryListings: [
        '~/.config/openshell',
        '~/.config/openshell/gateways',
        '~/.local/state/openshell',
        '~/.local/state/openshell/gateway',
        '~/.local/state/openshell/docker-sandbox-tokens',
        `~/${SNAP_USER_REL}`,
      ],
      envPrefixes: ['OPENSHELL_', 'XDG_'],
      systemPaths: [...CLI_SYSTEM_PATHS, ...BREW_VAR_DIRS, SNAP_COMMON_DIR],
      systemDirListings: [...BREW_VAR_DIRS.map(d => `${d}/tls`), `${SNAP_COMMON_DIR}/tls`],
    };
  },
};

/** Workspace of a sandbox `sandbox list` reports without one. */
export const DEFAULT_WORKSPACE = 'default';

// `defaults` (probes newer than 1.2.1) fills a field an item omits, matching the local
// scan; older probes ignore it and skip such items.
const SANDBOX_POLICY_FOR_EACH: CommandForEach = {
  from: 'openshell-sandbox-list',
  array: 'sandboxes',
  fields: ['name', 'workspace'],
  defaults: { workspace: DEFAULT_WORKSPACE },
};

/** Gateway queries shared by the checks (local exec) and the probe manifest (remote). */
export const SANDBOX_LIST_ARGS = ['sandbox', 'list', '--all-workspaces', '-o', 'json'] as const;
export const GLOBAL_POLICY_ARGS = ['policy', 'get', '--global', '--full', '-o', 'json'] as const;
export function sandboxPolicyArgs(name: string, workspace: string): string[] {
  return ['policy', 'get', name, '--workspace', workspace, '--full', '-o', 'json'];
}
