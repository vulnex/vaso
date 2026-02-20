import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AgentAdapter } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';

async function fileExists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export const nanoclawAdapter: AgentAdapter = {
  agent: 'nanoclaw',
  displayName: 'NanoClaw',

  async detect(): Promise<AgentInstallation | null> {
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

    if (configFiles.length === 0) return null;

    return {
      agent: 'nanoclaw',
      installDir: configDir,
      configFiles,
      skillsDir: this.getSkillsDir(configDir),
    };
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
