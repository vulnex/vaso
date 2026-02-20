import { access } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AgentAdapter } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import { loadConfig } from '../core/config-loader.js';

async function fileExists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export const picoclawAdapter: AgentAdapter = {
  agent: 'picoclaw',
  displayName: 'PicoClaw',

  async detect(): Promise<AgentInstallation | null> {
    const home = homedir();
    const picoDir = join(home, '.picoclaw');
    const configFiles = [];

    const configPath = join(picoDir, 'config.json');
    if (await fileExists(configPath)) {
      try {
        configFiles.push(await loadConfig(configPath));
      } catch {}
    }

    const authPath = join(picoDir, 'auth.json');
    if (await fileExists(authPath)) {
      try {
        configFiles.push(await loadConfig(authPath));
      } catch {}
    }

    if (configFiles.length === 0) return null;

    return {
      agent: 'picoclaw',
      installDir: picoDir,
      configFiles,
      skillsDir: this.getSkillsDir(picoDir),
    };
  },

  getConfigPaths(): string[] {
    const home = homedir();
    return [
      join(home, '.picoclaw', 'config.json'),
      join(home, '.picoclaw', 'auth.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getCLICommand(): string {
    return 'picoclaw';
  },
};
