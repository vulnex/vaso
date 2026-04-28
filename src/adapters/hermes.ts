import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion } from './version-query.js';

const CONFIG_FILENAMES = ['config.yaml', '.env'];

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
    const hermesHome = process.env.HERMES_HOME ?? join(home, '.hermes');

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

    const version = queryCliVersion(await findCLIBinary(home, fs), fs, { argSets: [['version'], ['--version']] });

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    const cliBinary = await findCLIBinary(home, fs);

    return [{
      agent: 'hermes',
      installDir: hermesHome,
      configFiles,
      skillsDir: this.getSkillsDir(hermesHome),
      version,
      gateway: this.getGatewayInfo(merged),
      cliBinary,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const hermesHome = process.env.HERMES_HOME ?? join(home, '.hermes');
    return CONFIG_FILENAMES.map(f => join(hermesHome, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const platforms = config.platforms as Record<string, unknown> | undefined;
    const apiServer = platforms?.api_server as Record<string, unknown> | undefined;

    // Hermes gateway defaults: 127.0.0.1:8642
    if (!apiServer && !platforms) return undefined;

    return {
      host: (apiServer?.host as string) ?? '127.0.0.1',
      port: (apiServer?.port as number) ?? 8642,
    };
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

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.hermes/config.yaml',
        '~/.hermes/.env',
        '~/.hermes/credentials.json',
      ],
      globPatterns: [
        '~/.hermes/skills/**',
        '~/.hermes/optional-skills/**',
      ],
      commands: [
        { id: 'hermes-which', cmd: 'which', args: ['hermes'], timeout: 3000 },
        { id: 'hermes-version', cmd: 'hermes', args: ['version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.hermes',
        '~/.hermes/skills',
        '~/.hermes/optional-skills',
      ],
      envPrefixes: ['HERMES_'],
      systemPaths: [
        '/usr/local/bin/hermes',
        '/opt/homebrew/bin/hermes',
        '/usr/bin/hermes',
      ],
      systemDirListings: [],
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
    const result = fs.execSync('which', ['hermes'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

