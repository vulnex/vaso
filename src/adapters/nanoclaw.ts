import { access } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';

async function fileExists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export const nanoclawAdapter: AgentAdapter = {
  agent: 'nanoclaw',
  displayName: 'NanoClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
    const home = homedir();
    const configDir = join(home, '.config', 'nanoclaw');
    const envPath = join(home, '.nanoclaw.env');
    const configFiles = [];

    // Check .env file with NanoClaw vars
    if (await fileExists(envPath)) {
      try {
        const config = await loadConfig(envPath);
        if (config.data.NANOCLAW_HOME || config.data.NANOCLAW_PORT) {
          configFiles.push(config);
        }
      } catch {}
    }

    // Check config dir
    const mountAllowlistPath = join(configDir, 'mount-allowlist.json');
    if (await fileExists(mountAllowlistPath)) {
      try {
        configFiles.push(await loadConfig(mountAllowlistPath));
      } catch {}
    }

    const configPath = join(configDir, 'config.json');
    if (await fileExists(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath));
      } catch {}
    }

    if (configFiles.length === 0) return [];

    // Extract version from config, fallback to CLI
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string) ?? queryCliVersion('nanoclaw');

    return [{
      agent: 'nanoclaw',
      installDir: configDir,
      configFiles,
      skillsDir: this.getSkillsDir(configDir),
      version,
    }];
  },

  getConfigPaths(): string[] {
    const home = homedir();
    return [
      join(home, '.nanoclaw.env'),
      join(home, '.config', 'nanoclaw', 'config.json'),
      join(home, '.config', 'nanoclaw', 'mount-allowlist.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getCLICommand(): string {
    return 'nanoclaw';
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
