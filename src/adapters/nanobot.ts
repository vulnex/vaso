import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { queryCliVersion } from './version-query.js';

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
    const cliBinary = await findCLIBinary(fs);

    if (configFiles.length === 0 && !cliBinary) return [];

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from config, fallback to CLI
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string) ?? queryCliVersion(cliBinary ?? 'nanobot', fs);

    return [{
      agent: 'nanobot',
      installDir: nanobotDir,
      configFiles,
      skillsDir: this.getSkillsDir(nanobotDir),
      gateway: this.getGatewayInfo(merged),
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
      ],
      globPatterns: [
        '~/.nanobot/workspace/skills/**',
      ],
      commands: [
        { id: 'nanobot-which', cmd: 'which', args: ['nanobot'], timeout: 3000 },
        { id: 'nanobot-version', cmd: 'nanobot', args: ['--version'], timeout: 3000 },
      ],
      directoryListings: [
        '~/.nanobot',
        '~/.nanobot/workspace',
        '~/.nanobot/workspace/skills',
      ],
      envPrefixes: ['NANOBOT_'],
      systemPaths: [],
      systemDirListings: [],
    };
  },
};

async function findCLIBinary(fs: FSProvider): Promise<string | undefined> {
  try {
    const result = fs.execSync('which', ['nanobot'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
