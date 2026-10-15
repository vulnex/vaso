import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { hermesApiServer, isTruthy, HERMES_API_DEFAULT_HOST, HERMES_API_DEFAULT_PORT } from './hermes-api-server.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';

const CONFIG_FILENAMES = ['cli-config.yaml', 'config.yaml', '.env'];

const SEMVER = /^\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/;

/**
 * The installer's record of the checkout version
 * (`$HERMES_HOME/hermes-agent/install-stamp.json`, `baseVersion`). Read from
 * a file, so it works on snapshots and needs no exec — `hermes --version`
 * from a fresh data root installs Python deps, and a source checkout can
 * report the placeholder 0.0.0.
 */
async function installStampVersion(hermesHome: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const stamp = JSON.parse(await fs.readFile(join(hermesHome, 'hermes-agent', 'install-stamp.json'))) as Record<string, unknown>;
    const v = typeof stamp.baseVersion === 'string' ? stamp.baseVersion.trim().replace(/^v/, '') : '';
    return SEMVER.test(v) && v !== '0.0.0' ? v : undefined;
  } catch {
    return undefined;
  }
}

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/hermes',
  '/opt/homebrew/bin/hermes',
  '/usr/bin/hermes',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/hermes',
  '.local/pipx/venvs/hermes-agent/bin/hermes',
];

export const hermesAdapter: AgentAdapter = {
  agent: 'hermes',
  displayName: 'Hermes',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    // The scanned host's environment (a snapshot's on remote scans)
    const hermesHome = fs.getEnv('HERMES_HOME') || join(home, '.hermes');

    if (!(await fs.access(hermesHome))) return [];

    const configFiles = [];

    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(hermesHome, filename);
      try {
        if (await fs.access(filePath)) {
          configFiles.push(await loadConfig(filePath, fs));
        }
      } catch {}
    }

    if (configFiles.length === 0) return [];

    const stampVersion = await installStampVersion(hermesHome, fs);

    const installs = await discoverCliInstalls(home, fs, {
      names: ['hermes'],
      systemPaths: SYSTEM_CLI_PATHS,
      userRelPaths: USER_CLI_RELATIVE_PATHS,
      // `--version` only. Hermes has no `version` subcommand, and in a fresh
      // data root (the throwaway HOME version queries run under) it installs
      // its Python dependencies before parsing arguments — hundreds of MB per
      // scan. `--version` exits without writing; a git checkout then reports
      // no version (its version comes from `git describe`).
      // The install stamp wins when present (no exec at all); 0.0.0 is a
      // placeholder, never a real release.
      version: async (bin, canExec) => {
        if (stampVersion || !canExec) return undefined;
        const v = await queryCliVersion(bin, fs);
        return v === '0.0.0' ? undefined : v;
      },
    });
    const cliBinary = installs.primary?.path;
    const version = stampVersion ?? installs.primary?.version;

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    return [{
      agent: 'hermes',
      installDir: hermesHome,
      configFiles,
      skillsDir: this.getSkillsDir(hermesHome),
      version,
      gateway: this.getGatewayInfo(merged),
      models: await this.getModels?.(configFiles, fs),
      cliBinary,
      otherInstalls: installs.others.length > 0 ? installs.others : undefined,
    }];
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const hermesHome = fs.getEnv('HERMES_HOME') || join(fs.homedir(), '.hermes');
    return CONFIG_FILENAMES.map(f => join(hermesHome, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // `config` is config.yaml merged with .env (env keys at the top level)
    const api = hermesApiServer([
      { format: 'env', data: config },
      { format: 'yaml', data: config },
    ]);
    // Only a listening API server is a gateway: enabled, or bound somewhere explicitly
    if (!isTruthy(api.enabled?.value) && !api.host) return undefined;
    const port = Number(api.port?.value);
    return {
      host: api.host?.value ?? HERMES_API_DEFAULT_HOST,
      port: Number.isInteger(port) && port > 0 ? port : HERMES_API_DEFAULT_PORT,
    };
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (rawId: unknown, rawProvider?: unknown, via?: string): void => {
      if (typeof rawId !== 'string' || !rawId.trim()) return;
      const trimmed = rawId.trim();
      let provider =
        typeof rawProvider === 'string' && rawProvider.trim() ? rawProvider.trim() : undefined;
      let id = trimmed;
      // If no explicit provider was given but the id is "<provider>/<id>",
      // split it. With a sibling provider field (Hermes' actual shape), keep
      // the id intact even if it contains slashes (e.g. nvidia/nemotron-...).
      if (!provider && trimmed.includes('/')) {
        const slash = trimmed.indexOf('/');
        provider = trimmed.slice(0, slash);
        id = trimmed.slice(slash + 1);
      }
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    // cli-config.yaml (or legacy config.yaml): `model.default` (or `model.model`
    // — upstream accepts both) is the active model; `model.provider` and
    // `model.base_url` are sibling metadata for that model, not separate slots.
    const yaml = configs.find(
      c => c.filePath.endsWith('cli-config.yaml') || c.filePath.endsWith('config.yaml'),
    );
    const block = yaml?.data?.model;
    if (typeof block === 'string') {
      push(block);
    } else if (block && typeof block === 'object') {
      const m = block as Record<string, unknown>;
      push(m.default ?? m.model, m.provider);
      push(m.fallback, m.fallback_provider ?? m.provider, 'fallback');
    }

    // .env overrides (no slot expansion — env keys are flat by nature)
    const env = configs.find(c => c.filePath.endsWith('.env'));
    if (env) {
      const envProvider = env.data.HERMES_PROVIDER;
      push(env.data.HERMES_MODEL, envProvider, out.length ? 'HERMES_MODEL' : undefined);
      push(env.data.HERMES_DEFAULT_MODEL, envProvider);
      push(env.data.OPENROUTER_MODEL, 'openrouter', 'OPENROUTER_MODEL');
    }

    // Process env fallback (only when nothing was found in files)
    if (out.length === 0 && fs?.getEnv) {
      push(fs.getEnv('HERMES_MODEL'), fs.getEnv('HERMES_PROVIDER'), 'HERMES_MODEL');
    }

    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory'),
      join(installDir, 'conversations.db'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.env'),
      join(installDir, 'credentials.json'),
    ];
  },

  getCLICommand(): string {
    return 'hermes';
  },

  // Hermes' privilege gradient: untrusted network → API-server gateway →
  // approvals/Tirith layer → terminal/MCP/inference fan-out → host filesystem
  // and remote inference endpoints. Inversion edges fire when the API server
  // is reachable without auth (HM-004) or approvals are off (HM-008), when
  // a custom inference endpoint is plaintext (HM-006) or untrusted (HM-007),
  // or when MCP stdio is shell-c'd / world-writable (HM-010).
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Browser Tabs', trustLevel: 0 },
        { id: 'api', label: 'API Server Gateway', trustLevel: 1 },
        { id: 'approval', label: 'Approvals + Tirith', trustLevel: 2 },
        { id: 'tools', label: 'Terminal + MCP + Inference', trustLevel: 3 },
        { id: 'host', label: 'Host FS + Remote Endpoints', trustLevel: 4 },
      ],
      components: [
        { id: 'inbound', label: 'Network Ingress', zone: 'net' },
        {
          id: 'api-server',
          label: 'Hermes API Server (8642)',
          zone: 'api',
          guardCheckIds: ['HM-004', 'HM-005'],
        },
        {
          id: 'approval-layer',
          label: 'Approvals + Tirith Scanner',
          zone: 'approval',
          guardCheckIds: ['HM-008', 'HM-009'],
        },
        {
          id: 'tool-fanout',
          label: 'Terminal + MCP + Inference',
          zone: 'tools',
          guardCheckIds: ['HM-001', 'HM-002', 'HM-003', 'HM-010'],
        },
        {
          id: 'remote',
          label: 'Inference Endpoints + Host FS',
          zone: 'host',
          guardCheckIds: ['HM-006', 'HM-007'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'api-server', kind: 'data' },
        { from: 'api-server', to: 'approval-layer', kind: 'control' },
        { from: 'approval-layer', to: 'tool-fanout', kind: 'data' },
        { from: 'tool-fanout', to: 'remote', kind: 'data' },
        {
          from: 'inbound',
          to: 'tool-fanout',
          label: 'unauth API bypass',
          triggerCheckIds: ['HM-004'],
        },
        {
          from: 'api-server',
          to: 'tool-fanout',
          label: 'approval bypass',
          triggerCheckIds: ['HM-008'],
        },
        {
          from: 'tool-fanout',
          to: 'remote',
          label: 'plaintext / exfil endpoint',
          triggerCheckIds: ['HM-006', 'HM-007'],
        },
      ],
    };
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.hermes/cli-config.yaml',
        '~/.hermes/config.yaml',
        '~/.hermes/.env',
        // Installer version record ({"baseVersion": …})
        '~/.hermes/hermes-agent/install-stamp.json',
      ],
      // Credential stores — permissions only (HM-003), never content
      metadataGlobPatterns: [
        // Auto-installed tirith binary (HM-009) — presence only
        '~/.hermes/bin/tirith',
        '~/.hermes/credentials.json',
        '~/.hermes/auth.json',
        '~/.hermes/mcp-tokens/*.json',
      ],
      globPatterns: [
        '~/.hermes/skills/**',
        '~/.hermes/optional-skills/**',
      ],
      commands: [
        { id: 'hermes-which', cmd: 'which', args: ['hermes'], timeout: 3000 },
        { id: 'hermes-version-flag', cmd: 'hermes', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.hermes',
        '~/.hermes/skills',
        '~/.hermes/optional-skills',
      ],
      // TIRITH_ENABLED / TIRITH_FAIL_OPEN override security.tirith_* (HM-009)
      envPrefixes: ['HERMES_', 'TIRITH_ENABLED', 'TIRITH_FAIL_OPEN'],
      systemPaths: [
        '/usr/local/bin/hermes',
        '/opt/homebrew/bin/hermes',
        '/usr/bin/hermes',
      ],
      systemDirListings: [],
    };
  },
};

