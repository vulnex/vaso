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

export const picoclawAdapter: AgentAdapter = {
  agent: 'picoclaw',
  displayName: 'PicoClaw',

  async detect(_options?: DetectOptions): Promise<AgentInstallation[]> {
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

    if (configFiles.length === 0) return [];

    // Merge all config data to extract gateway info
    const merged: Record<string, unknown> = {};
    for (const c of configFiles) {
      Object.assign(merged, c.data);
    }

    // Extract version from config, fallback to CLI
    const mainConfig = configFiles.find(c => c.filePath.endsWith('config.json'));
    const version = (mainConfig?.data?.version as string) ?? queryCliVersion('picoclaw');

    return [{
      agent: 'picoclaw',
      installDir: picoDir,
      configFiles,
      skillsDir: this.getSkillsDir(picoDir),
      gateway: this.getGatewayInfo(merged),
      version,
    }];
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
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (!gw) return undefined;

    return {
      host: gw.host as string | undefined,
      port: gw.port as number | undefined,
      authMode: (config.auth as Record<string, unknown>)?.mode as string | undefined,
      tls: gw.tls as boolean | undefined,
    };
  },

  getCLICommand(): string {
    return 'picoclaw';
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
