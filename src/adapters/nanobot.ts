import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/nanobot',
  '/opt/homebrew/bin/nanobot',
  '/usr/bin/nanobot',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/nanobot',
  '.npm-global/bin/nanobot',
  '.volta/bin/nanobot',
  '.bun/bin/nanobot',
];

function nodeModulesPackageJsonCandidates(home: string): string[] {
  return [
    '/usr/lib/node_modules/nanobot/package.json',
    '/usr/local/lib/node_modules/nanobot/package.json',
    '/opt/homebrew/lib/node_modules/nanobot/package.json',
    `${home}/.npm-global/lib/node_modules/nanobot/package.json`,
    `${home}/.bun/install/global/node_modules/nanobot/package.json`,
    `${home}/.volta/tools/image/packages/nanobot/package.json`,
  ];
}

async function readNodePackageVersion(fs: FSProvider): Promise<string | undefined> {
  const home = fs.homedir();
  for (const p of nodeModulesPackageJsonCandidates(home)) {
    try {
      const raw = await fs.readFile(p);
      const pkg = JSON.parse(raw);
      if (pkg.version && /^\d+\.\d+\.\d+/.test(pkg.version)) return pkg.version;
    } catch {}
  }
  return undefined;
}

export const nanobotAdapter: AgentAdapter = {
  agent: 'nanobot',
  displayName: 'Nanobot',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const nanobotDir = join(home, '.nanobot');
    const configFiles = [];

    const configPath = join(nanobotDir, 'config.json');
    if (await fs.access(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath, fs));
      } catch {}
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary(home, fs);

    if (configFiles.length === 0 && !cliBinary) return [];

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version: config field > CLI exec > package.json next to binary
    // > known npm-global package.json roots.
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string)
      ?? queryCliVersion(cliBinary, fs)
      ?? (await readPackageVersion(cliBinary, fs))
      ?? (await readNodePackageVersion(fs));

    return [{
      agent: 'nanobot',
      installDir: nanobotDir,
      configFiles,
      skillsDir: this.getSkillsDir(nanobotDir),
      gateway: this.getGatewayInfo(merged),
      models: this.getModels?.(configFiles),
      cliBinary,
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return [
      join(home, '.nanobot', 'config.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'workspace', 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const host = config.host as string | undefined;
    const port = config.port as number | undefined;
    if (host || port) {
      return {
        host: host ?? '0.0.0.0',
        port: port ?? 18790,
      };
    }
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const main = configs.find(c => c.filePath.endsWith('config.json'));
    const agents = main?.data?.agents as Record<string, unknown> | undefined;
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const push = (raw: string, via?: string) => {
      // Nanobot stores models as "<provider>/<id>" (e.g. "anthropic/claude-opus-4-5").
      const slash = raw.indexOf('/');
      const provider = slash !== -1 ? raw.slice(0, slash) : undefined;
      const id = slash !== -1 ? raw.slice(slash + 1) : raw;
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, provider, via });
    };
    const defaults = agents?.defaults as Record<string, unknown> | undefined;
    const defaultModel = defaults?.model as string | undefined;
    if (defaultModel) push(defaultModel);
    for (const [name, cfg] of Object.entries(agents ?? {})) {
      if (name === 'defaults') continue;
      const m = (cfg as Record<string, unknown> | undefined)?.model as string | undefined;
      if (m) push(m, name);
    }
    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'workspace', 'memory', 'MEMORY.md'),
      join(installDir, 'workspace', 'HEARTBEAT.md'),
      join(installDir, 'workspace', 'SOUL.md'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, 'config.json'),
    ];
  },

  getCLICommand(): string {
    return 'nanobot';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.nanobot/config.json',
        '~/.nanobot/workspace/memory/MEMORY.md',
        '~/.nanobot/workspace/HEARTBEAT.md',
        '~/.nanobot/workspace/SOUL.md',
        // User-relative CLI install locations.
        '~/.local/bin/nanobot',
        '~/.npm-global/bin/nanobot',
        '~/.volta/bin/nanobot',
        '~/.bun/bin/nanobot',
        // npm-global package.json (canonical version source for Node CLIs).
        '/usr/lib/node_modules/nanobot/package.json',
        '/usr/local/lib/node_modules/nanobot/package.json',
        '/opt/homebrew/lib/node_modules/nanobot/package.json',
        '~/.npm-global/lib/node_modules/nanobot/package.json',
        '~/.bun/install/global/node_modules/nanobot/package.json',
        '~/.volta/tools/image/packages/nanobot/package.json',
      ],
      globPatterns: [
        '~/.nanobot/workspace/skills/**',
        '~/.nvm/versions/node/*/lib/node_modules/nanobot/package.json',
      ],
      commands: [
        { id: 'nanobot-which', cmd: 'which', args: ['nanobot'], timeout: 3000 },
        { id: 'nanobot-version', cmd: 'nanobot', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.nanobot',
        '~/.nanobot/workspace',
        '~/.nanobot/workspace/skills',
      ],
      envPrefixes: ['NANOBOT_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },

  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'chat', label: 'Chat Platforms', trustLevel: 0 },
        { id: 'core', label: 'Bot Core', trustLevel: 1 },
        { id: 'exec', label: 'Shell Exec', trustLevel: 2 },
        { id: 'host', label: 'Host FS', trustLevel: 3 },
      ],
      components: [
        { id: 'edge', label: 'Discord/Slack Edge', zone: 'chat' },
        {
          id: 'bot',
          label: 'Nanobot Core',
          zone: 'core',
          guardCheckIds: ['NB-001', 'NB-008', 'NB-010', 'NB-011', 'NB-012'],
        },
        {
          id: 'shell',
          label: 'Tool/Shell Execution',
          zone: 'exec',
          guardCheckIds: ['NB-004', 'NB-005', 'NB-006', 'NB-007', 'NB-009'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['NB-002', 'NB-003'],
        },
      ],
      edges: [
        { from: 'edge', to: 'bot', kind: 'data', label: 'message' },
        { from: 'bot', to: 'shell', kind: 'control' },
        { from: 'shell', to: 'fs', kind: 'data' },
        {
          from: 'edge',
          to: 'fs',
          label: 'channel-driven exec',
          triggerCheckIds: ['NB-001', 'NB-004'],
        },
      ],
    };
  },
};

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync('which', ['nanobot'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}
