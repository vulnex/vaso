import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';

const CONFIG_FILENAMES = [
  '.env',
  'config.toml',
  'settings.json',
  'mcp-servers.json',
];

export const ironclawAdapter: AgentAdapter = {
  agent: 'ironclaw',
  displayName: 'IronClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = _options?.fs ?? new LocalFSProvider();
    const home = fs.homedir();
    const ironDir = join(home, '.ironclaw');
    const configFiles = [];

    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(ironDir, filename);
      if (await fs.access(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath, fs));
        } catch {}
      }
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary(home, fs);

    if (configFiles.length === 0 && !cliBinary) return [];

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from TOML config, fallback to CLI
    const tomlConfig = configFiles.find(c => c.filePath.endsWith('.toml'));
    const version =
      (tomlConfig?.data?.version as string) ??
      ((tomlConfig?.data?.package as Record<string, unknown>)?.version as string) ??
      queryCliVersion(cliBinary ?? 'ironclaw', fs);

    return [{
      agent: 'ironclaw',
      installDir: ironDir,
      configFiles,
      skillsDir: this.getSkillsDir(ironDir),
      gateway: this.getGatewayInfo(merged),
      cliBinary,
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const ironDir = join(home, '.ironclaw');
    return CONFIG_FILENAMES.map(f => join(ironDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // Check .env-style keys first
    const envHost = config.GATEWAY_HOST as string | undefined;
    const envPort = config.GATEWAY_PORT as string | undefined;
    if (envHost || envPort) {
      return {
        host: envHost,
        port: envPort ? parseInt(envPort, 10) : undefined,
      };
    }

    // Check TOML [gateway] section
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (gw) {
      return {
        host: gw.host as string | undefined,
        port: gw.port as number | undefined,
        tls: gw.tls as boolean | undefined,
      };
    }

    return undefined;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory.json'),
      join(installDir, 'conversations.db'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.env'),
      join(installDir, 'config.toml'),
      join(installDir, 'settings.json'),
    ];
  },

  getCLICommand(): string {
    return 'ironclaw';
  },
};

function queryCliVersion(binary: string, fs: FSProvider): string | undefined {
  try {
    const output = fs.execSync(binary, ['--version'], { timeout: 3000 }).trim();
    const m = /(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/.exec(output);
    return m?.[1];
  } catch {
    return undefined;
  }
}

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  const cargoPath = join(home, '.cargo', 'bin', 'ironclaw');
  if (await fs.access(cargoPath)) return cargoPath;

  try {
    const result = fs.execSync('which', ['ironclaw'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
