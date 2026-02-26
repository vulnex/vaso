import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';
import { pathExists } from '../core/utils.js';

export const nanobotAdapter: AgentAdapter = {
  agent: 'nanobot',
  displayName: 'Nanobot',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const home = homedir();
    const nanobotDir = join(home, '.nanobot');
    const configFiles = [];

    const configPath = join(nanobotDir, 'config.json');
    if (await pathExists(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath));
      } catch {}
    }

    // Also check for CLI binary
    const cliBinary = await findCLIBinary();

    if (configFiles.length === 0 && !cliBinary) return [];

    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from config, fallback to CLI
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string) ?? queryCliVersion(cliBinary ?? 'nanobot');

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
    const home = homedir();
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
};

function queryCliVersion(binary: string): string | undefined {
  try {
    const output = execFileSync(binary, ['--version'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    const m = /(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/.exec(output);
    return m?.[1];
  } catch {
    return undefined;
  }
}

async function findCLIBinary(): Promise<string | undefined> {
  try {
    const result = execFileSync('which', ['nanobot'], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    if (result) return result;
  } catch {}

  return undefined;
}
