import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';
import { pathExists } from '../core/utils.js';

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
    const home = homedir();
    const ironDir = join(home, '.ironclaw');
    const configFiles = [];

    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(ironDir, filename);
      if (await pathExists(filePath)) {
        try {
          configFiles.push(await loadConfig(filePath));
        } catch {}
      }
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary(home);

    if (configFiles.length === 0 && !cliBinary) return [];

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    return [{
      agent: 'ironclaw',
      installDir: ironDir,
      configFiles,
      skillsDir: this.getSkillsDir(ironDir),
      gateway: this.getGatewayInfo(merged),
      cliBinary,
    }];
  },

  getConfigPaths(): string[] {
    const home = homedir();
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

async function findCLIBinary(home: string): Promise<string | undefined> {
  const cargoPath = join(home, '.cargo', 'bin', 'ironclaw');
  if (await pathExists(cargoPath)) return cargoPath;

  try {
    const result = execFileSync('which', ['ironclaw'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
